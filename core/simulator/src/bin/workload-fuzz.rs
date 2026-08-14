// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! Deterministic workload fuzzer for the Iggy simulator.
//!
//! Drives [`simulator::workload::run`] (per-tick invariants + optional crash
//! injection) for a number of ticks, then optionally quiesces and asserts the
//! Phase C consensus checks. Everything is a function of `--seed`, logged at
//! start and on panic so any failure replays with `--seed <value>`.
//!
//! ```text
//! workload-fuzz [--seed N] [--ticks N] [--clients N] [--replicas N]
//!               [--plane partition|metadata|mixed|uniform]
//!               [--faults none|light|heavy] [--crash-prob F] [--no-quiesce]
//!               [network overrides: --packet-loss, --replay, --partition-mode,
//!                --partition-prob, --unpartition-prob, --clog-prob, ...]
//! ```
//!
//! `--plane` selects the op mix (see [`ActionWeights`]). Partition-plane runs
//! drain and converge most readily; `uniform` is the widest per-tick op
//! coverage.
//!
//! `--faults` picks a whole network fault profile; the individual network flags
//! override single fields of the chosen profile, so exploring one axis does not
//! mean spelling out the other ten. The default profile is `none`, a perfect
//! network, so a run says what it injects rather than inheriting it.

use clap::{Parser, ValueEnum};
use iggy_common::IggyByteSize;
use server_common::sharding::IggyNamespace;
use server_common::{MemoryPool, MemoryPoolConfigOther};
use simulator::Simulator;
use simulator::client::SimClient;
use simulator::packet::{PacketSimulatorOptions, PartitionMode, PartitionSymmetry};
use simulator::workload::actions::Action;
use simulator::workload::options::{ActionWeights, WorkloadOptions};
use simulator::workload::{Workload, oracle, run};
use strum::IntoEnumIterator;

#[derive(Parser)]
#[command(about = "Deterministic workload fuzzer for the Iggy simulator")]
struct Args {
    /// Omitted draws a random seed (logged for replay).
    #[arg(long)]
    seed: Option<u64>,
    #[arg(long, default_value_t = 10_000)]
    ticks: u64,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..))]
    clients: u8,
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..))]
    replicas: u8,
    /// Op mix to draw from.
    #[arg(long, value_enum, default_value_t = Plane::Partition)]
    plane: Plane,
    /// Probability a consumer-offset store asks for `Quorum` rather than
    /// `NoAck`. `1.0` keeps every offset op on the replicated path.
    #[arg(long, default_value_t = 0.5, value_parser = parse_unit_interval)]
    ack_quorum_ratio: f32,
    #[arg(long, default_value_t = 0.0, value_parser = parse_unit_interval)]
    crash_prob: f32,
    #[arg(long)]
    no_quiesce: bool,

    /// Network fault profile. Individual network flags below override single
    /// fields of the profile.
    #[arg(long, value_enum, default_value_t = Faults::None)]
    faults: Faults,
    /// Chance a packet is dropped at delivery time.
    #[arg(long, value_parser = parse_unit_interval_f64)]
    packet_loss: Option<f64>,
    /// Chance a packet is duplicated at delivery time.
    #[arg(long, value_parser = parse_unit_interval_f64)]
    replay: Option<f64>,
    /// Minimum one-way delay, in ticks.
    #[arg(long)]
    one_way_delay_min: Option<u64>,
    /// Mean one-way delay, in ticks (exponentially distributed).
    #[arg(long)]
    one_way_delay_mean: Option<u64>,
    /// Maximum packets queued on a single link; beyond it the link drops.
    #[arg(long)]
    link_capacity: Option<u8>,
    /// How an automatic partition picks its sides.
    #[arg(long, value_enum)]
    partition_mode: Option<PartitionModeArg>,
    /// Whether a partition blocks both directions or just one.
    #[arg(long, value_enum)]
    partition_symmetry: Option<PartitionSymmetryArg>,
    /// Per-tick chance a partition forms while connectivity is whole.
    #[arg(long, value_parser = parse_unit_interval_f64)]
    partition_prob: Option<f64>,
    /// Per-tick chance a standing partition heals.
    #[arg(long, value_parser = parse_unit_interval_f64)]
    unpartition_prob: Option<f64>,
    /// Minimum ticks a partition lasts once formed.
    #[arg(long)]
    partition_stability: Option<u32>,
    /// Minimum ticks of whole connectivity before another partition may form.
    #[arg(long)]
    unpartition_stability: Option<u32>,
    /// Per-tick chance any one path clogs (stops delivering, keeps queueing).
    #[arg(long, value_parser = parse_unit_interval_f64)]
    clog_prob: Option<f64>,
    /// Mean clog duration, in ticks (exponentially distributed).
    #[arg(long)]
    clog_duration_mean: Option<u64>,
}

/// Named network fault profile, in the spirit of TigerBeetle's VOPR modes: one
/// flag for "how hostile is the network", rather than eleven.
///
/// Anything but [`Faults::None`] currently stalls the run, and not because the
/// cluster fails to make progress: `SimClient` has no request timeout, so a
/// client holds its single in-flight slot forever once the request or its reply
/// is dropped. Every profile below is therefore write-once-read-later until the
/// client grows a resend path; they are wired now so the fault space is
/// described in one place rather than rediscovered later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Faults {
    /// Perfect network. Delays only, no loss and no partitions.
    None,
    /// Occasional loss, duplication and short one-sided partitions. Meant to
    /// stay inside the range where a healthy cluster still drains.
    Light,
    /// Frequent loss, long partitions and clogged paths. Expected to stall
    /// progress for stretches; use with a generous tick budget.
    Heavy,
}

/// Clap mirror of [`PartitionMode`], so the library type stays free of a clap
/// derive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum PartitionModeArg {
    None,
    UniformSize,
    UniformPartition,
    IsolateSingle,
}

impl From<PartitionModeArg> for PartitionMode {
    fn from(value: PartitionModeArg) -> Self {
        match value {
            PartitionModeArg::None => Self::None,
            PartitionModeArg::UniformSize => Self::UniformSize,
            PartitionModeArg::UniformPartition => Self::UniformPartition,
            PartitionModeArg::IsolateSingle => Self::IsolateSingle,
        }
    }
}

/// Clap mirror of [`PartitionSymmetry`]; see [`PartitionModeArg`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum PartitionSymmetryArg {
    Symmetric,
    Asymmetric,
}

impl From<PartitionSymmetryArg> for PartitionSymmetry {
    fn from(value: PartitionSymmetryArg) -> Self {
        match value {
            PartitionSymmetryArg::Symmetric => Self::Symmetric,
            PartitionSymmetryArg::Asymmetric => Self::Asymmetric,
        }
    }
}

impl Faults {
    /// Base network options for this profile. `node_count`, `client_count` and
    /// `seed` are filled by the caller.
    fn options(self) -> PacketSimulatorOptions {
        match self {
            // `PacketSimulatorOptions::default` is already a perfect network:
            // delay only, every probability zero.
            Self::None => PacketSimulatorOptions::default(),
            Self::Light => PacketSimulatorOptions {
                packet_loss_probability: 0.02,
                replay_probability: 0.01,
                partition_probability: 0.005,
                unpartition_probability: 0.05,
                partition_stability: 20,
                unpartition_stability: 40,
                partition_mode: PartitionMode::IsolateSingle,
                partition_symmetry: PartitionSymmetry::Asymmetric,
                path_clog_probability: 0.002,
                path_clog_duration_mean: 10,
                ..PacketSimulatorOptions::default()
            },
            Self::Heavy => PacketSimulatorOptions {
                packet_loss_probability: 0.10,
                replay_probability: 0.03,
                one_way_delay_mean: 8,
                partition_probability: 0.02,
                unpartition_probability: 0.02,
                partition_stability: 50,
                unpartition_stability: 50,
                partition_mode: PartitionMode::UniformSize,
                partition_symmetry: PartitionSymmetry::Asymmetric,
                path_clog_probability: 0.01,
                path_clog_duration_mean: 25,
                ..PacketSimulatorOptions::default()
            },
        }
    }
}

/// Which plane the sampled ops target. Maps onto an [`ActionWeights`] preset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Plane {
    /// Writes and consumer offsets only.
    Partition,
    /// Replicated metadata mutations only.
    Metadata,
    /// Stream creates over a write-heavy base.
    Mixed,
    /// Every action equally likely.
    Uniform,
}

impl Plane {
    fn weights(self) -> ActionWeights {
        match self {
            Self::Partition => ActionWeights::partition_only(),
            Self::Metadata => ActionWeights::metadata_only(),
            Self::Mixed => ActionWeights::default(),
            Self::Uniform => ActionWeights::uniform(),
        }
    }
}

/// Clap value parser: accept a probability in `[0.0, 1.0]`.
fn parse_unit_interval(raw: &str) -> Result<f32, String> {
    let value: f32 = raw
        .parse()
        .map_err(|_| format!("`{raw}` is not a number"))?;
    if (0.0..=1.0).contains(&value) {
        Ok(value)
    } else {
        Err(format!("must be within [0.0, 1.0], got {value}"))
    }
}

/// [`parse_unit_interval`] for the network knobs, which are `f64`.
fn parse_unit_interval_f64(raw: &str) -> Result<f64, String> {
    let value: f64 = raw
        .parse()
        .map_err(|_| format!("`{raw}` is not a number"))?;
    if (0.0..=1.0).contains(&value) {
        Ok(value)
    } else {
        Err(format!("must be within [0.0, 1.0], got {value}"))
    }
}

/// The chosen fault profile with any individually-set network flag applied over
/// it, plus the cluster shape and seed.
fn network_options(args: &Args, replicas: u8, clients: u8, seed: u64) -> PacketSimulatorOptions {
    let mut options = args.faults.options();
    options.node_count = replicas;
    options.client_count = clients;
    options.seed = seed;

    if let Some(value) = args.packet_loss {
        options.packet_loss_probability = value;
    }
    if let Some(value) = args.replay {
        options.replay_probability = value;
    }
    if let Some(value) = args.one_way_delay_min {
        options.one_way_delay_min = value;
    }
    if let Some(value) = args.one_way_delay_mean {
        options.one_way_delay_mean = value;
    }
    if let Some(value) = args.link_capacity {
        options.link_capacity = value;
    }
    if let Some(value) = args.partition_mode {
        options.partition_mode = value.into();
    }
    if let Some(value) = args.partition_symmetry {
        options.partition_symmetry = value.into();
    }
    if let Some(value) = args.partition_prob {
        options.partition_probability = value;
    }
    if let Some(value) = args.unpartition_prob {
        options.unpartition_probability = value;
    }
    if let Some(value) = args.partition_stability {
        options.partition_stability = value;
    }
    if let Some(value) = args.unpartition_stability {
        options.unpartition_stability = value;
    }
    if let Some(value) = args.clog_prob {
        options.path_clog_probability = value;
    }
    if let Some(value) = args.clog_duration_mean {
        options.path_clog_duration_mean = value;
    }
    options
}

fn main() {
    let args = Args::parse();

    // Server-side diagnostics (`emit_partition_diag` and friends) are the only
    // record of a request the server dropped after logging, which is exactly the
    // shape that wedges a client's in-flight slot. Without a subscriber they go
    // nowhere and the run looks like an unexplained stall, so install one and let
    // `RUST_LOG` select. Off by default: a WARN per dropped frame drowns the run.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    // A provided seed reproduces a prior run exactly; otherwise draw one and
    // log it. Both the network and workload PRNGs derive from it.
    let seed = args.seed.unwrap_or_else(rand::random);
    let ticks = args.ticks;
    let clients = args.clients;
    let replicas = args.replicas;
    let plane = args.plane;
    let crash_prob = args.crash_prob;
    let quiesce = !args.no_quiesce;

    // Surface the seed on any panic (invariant or oracle violation) so the run
    // is replayable. The process still exits non-zero via the default hook.
    std::panic::set_hook(Box::new(move |info| {
        eprintln!("workload-fuzz FAILED — reproduce with --seed {seed}\n{info}");
    }));

    let network_opts = network_options(&args, replicas, clients, seed);
    println!(
        "workload-fuzz: seed={seed} ticks={ticks} clients={clients} replicas={replicas} \
         plane={plane:?} faults={:?} crash_prob={crash_prob} quiesce={quiesce}",
        args.faults,
    );
    println!(
        "network: loss={} replay={} delay={}..{} partition={:?}/{:?} \
         p_partition={} p_unpartition={} clog={} link_capacity={}",
        network_opts.packet_loss_probability,
        network_opts.replay_probability,
        network_opts.one_way_delay_min,
        network_opts.one_way_delay_mean,
        network_opts.partition_mode,
        network_opts.partition_symmetry,
        network_opts.partition_probability,
        network_opts.unpartition_probability,
        network_opts.path_clog_probability,
        network_opts.link_capacity,
    );

    // poll_messages / reply paths panic without an initialized pool; disabled
    // pooling falls through to the system allocator.
    MemoryPool::init_pool(&MemoryPoolConfigOther {
        enabled: false,
        size: IggyByteSize::from(0u64),
        bucket_capacity: 1,
    });

    let client_ids: Vec<u128> = (1..=u128::from(clients)).collect();
    let mut sim = Simulator::new(
        usize::from(replicas),
        client_ids.iter().copied(),
        network_opts,
    );
    let sim_clients: Vec<SimClient> = client_ids.iter().map(|&id| SimClient::new(id)).collect();

    let ns = IggyNamespace::new(1, 1, 0);
    sim.init_partition(ns);
    for client in &sim_clients {
        sim.register_client_with_primary(client);
    }

    let mut options = WorkloadOptions::new(seed, replicas, vec![ns]);
    options.client_count = clients;
    options.crash_per_tick_ratio = crash_prob;
    options.ack_quorum_ratio = args.ack_quorum_ratio;
    options.weights = plane.weights();
    let mut workload = Workload::new(options);

    let replies = run(&mut sim, &mut workload, &sim_clients, ticks, u64::MAX);
    println!(
        "ran {ticks} ticks; {replies} replies; crashed replicas: {}",
        sim.crashed.len()
    );

    if quiesce {
        if oracle::drive_to_quiesce(&mut sim, &mut workload, 50_000) {
            oracle::assert_converged(&sim, &workload);
            println!("quiesced and converged (leader-relative + entity oracle)");
        } else {
            println!(
                "WARN: did not quiesce within budget — expected when crashing to bare quorum; \
                 per-tick invariants still held"
            );
        }
    }

    let stats = workload.auditor.stats();
    println!(
        "coverage: replies_seen={} replies_unknown={} committed_rejections={} samples_none={}",
        stats.replies_seen,
        stats.replies_unknown,
        stats.committed_rejections,
        workload.samples_none(),
    );
    for action in Action::iter() {
        let commits = stats.commits(action);
        if commits > 0 {
            println!("  {action:?}: {commits} commits");
        }
    }

    println!("workload-fuzz: OK (seed={seed})");
}
