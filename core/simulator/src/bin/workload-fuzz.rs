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
//!               [--crash-prob F] [--no-quiesce]
//! ```
//!
//! `--plane` selects the op mix (see [`ActionWeights`]). Partition-plane runs
//! drain and converge most readily; `uniform` is the widest per-tick op
//! coverage.

use clap::{Parser, ValueEnum};
use iggy_common::IggyByteSize;
use server_common::sharding::IggyNamespace;
use server_common::{MemoryPool, MemoryPoolConfigOther};
use simulator::Simulator;
use simulator::client::SimClient;
use simulator::packet::PacketSimulatorOptions;
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

    println!(
        "workload-fuzz: seed={seed} ticks={ticks} clients={clients} replicas={replicas} \
         plane={plane:?} crash_prob={crash_prob} quiesce={quiesce}"
    );

    // poll_messages / reply paths panic without an initialized pool; disabled
    // pooling falls through to the system allocator.
    MemoryPool::init_pool(&MemoryPoolConfigOther {
        enabled: false,
        size: IggyByteSize::from(0u64),
        bucket_capacity: 1,
    });

    let client_ids: Vec<u128> = (1..=u128::from(clients)).collect();
    let network_opts = PacketSimulatorOptions {
        node_count: replicas,
        client_count: clients,
        seed,
        ..PacketSimulatorOptions::default()
    };
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
