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

//! Deterministic seed-based workload generator.
//!
//! - `actions::Action`: server command variants.
//! - `ops/<name>.rs`: per-op `sample`, `build_message`, `classify_reply`,
//!   `predicted_effect`.
//! - `shadow::Shadow`: predicted server entity state.
//! - `auditor::ServerAuditor`: in-flight expectations and invariants.
//! - `effect::Effect`: predicted shadow mutation per commit.

pub mod actions;
pub mod auditor;
pub mod effect;
pub mod ids;
pub mod invariants;
pub mod ops;
pub mod options;
pub mod oracle;
pub mod shadow;
pub mod state_checker;

use crate::Simulator;
use crate::client::SimClient;
use crate::workload::ops::InFlight;
use actions::Action;
use auditor::{OnReply, ServerAuditor};
use effect::SimCommand;
use iggy_binary_protocol::{ReplyHeader, RoutedRequestHeader, result_code};
use invariants::Invariants;
use metadata::stm::result::result_code_recognized;
use options::WorkloadOptions;
use rand::RngExt;
use rand_xoshiro::Xoshiro256Plus;
use rand_xoshiro::rand_core::SeedableRng;
use server_common::Message;
use shadow::Shadow;
use std::collections::{BTreeMap, HashSet};

/// Max in-flight requests per client. Must stay under the consensus
/// pipeline's queue limits.
pub const CLIENT_REQUEST_QUEUE_MAX: usize = 1;

/// An outstanding request, retained so the client can resend it.
///
/// The encoded message is kept verbatim rather than rebuilt from the sampled
/// `Input`, because rebuilding would draw a fresh request id from the client and
/// a resend must reuse the original: that id is what the metadata plane's client
/// table dedups on, so a renumbered retry commits a second time instead of
/// returning the cached reply.
struct Outstanding {
    message: Message<RoutedRequestHeader>,
    /// Replica the most recent attempt went to. A resend moves to the next one,
    /// so a client whose primary died eventually finds the new one.
    target: u8,
    /// Tick of the most recent attempt, not of the first.
    attempted_tick: u64,
    attempts: u32,
}

pub struct Workload {
    prng: Xoshiro256Plus,
    pub auditor: ServerAuditor,
    pub shadow: Shadow,
    pub options: WorkloadOptions,
    /// Outstanding requests keyed exactly as the auditor keys its expectations,
    /// so the two are removed together.
    ///
    /// A `BTreeMap`, not a `HashMap`: [`Self::due_resends`] walks it and the
    /// resulting submit order is observable, so hash iteration order would make
    /// replay diverge from the seed.
    ///
    /// TODO: reap on client disconnect; bounded today by the fixed
    /// `Simulator::new` set.
    outstanding: BTreeMap<(u128, u64), Outstanding>,
    /// Driver tick, advanced by [`Self::tick`]. A driver that never ticks never
    /// resends, which is what the hand-written scenario tests rely on.
    now: u64,
    /// Total resends issued, for the run summary.
    resends: u64,
    /// Debug counter for `sample()` returning `None` (a targeted outcome whose
    /// shadow precondition is unmet). Flags PRNG-trace drift during development.
    samples_none: u64,
    /// Assert the targeted outcome equals the committed one. Sound only for a
    /// fully serial run (one client, one in-flight slot), where the shadow equals
    /// committed server state at sample time so the target is always realized.
    /// Gated on `client_count == 1 && CLIENT_REQUEST_QUEUE_MAX == 1`.
    strict_outcome_oracle: bool,
}

impl Workload {
    #[must_use]
    pub fn new(options: WorkloadOptions) -> Self {
        let prng = Xoshiro256Plus::seed_from_u64(options.seed);
        let shadow = Shadow::new(options.namespaces.clone(), ids::IdPermutation::Identity);
        // Both halves of the soundness precondition (see the field doc). Coupling
        // to the queue max disarms strict equality if it is raised, rather than
        // letting the assert fire on a legitimately raced outcome (a 2nd in-flight
        // request sampled against the shadow before the 1st commits).
        let strict_outcome_oracle = options.client_count == 1 && CLIENT_REQUEST_QUEUE_MAX == 1;
        Self {
            prng,
            auditor: ServerAuditor::new(),
            shadow,
            options,
            outstanding: BTreeMap::new(),
            now: 0,
            resends: 0,
            samples_none: 0,
            strict_outcome_oracle,
        }
    }

    /// True if the client has a free in-flight slot.
    #[must_use]
    pub fn client_idle(&self, client_id: u128) -> bool {
        self.client_in_flight(client_id) < CLIENT_REQUEST_QUEUE_MAX
    }

    /// Total in-flight requests across all clients. Read by the
    /// [`Invariants`]; draws no PRNG.
    #[must_use]
    pub(crate) fn total_in_flight(&self) -> usize {
        self.outstanding.len()
    }

    /// Advance the resend clock by one tick. Called once per driver iteration;
    /// [`Self::due_resends`] measures against it.
    pub fn tick(&mut self) {
        self.now += 1;
    }

    /// Total resends issued so far.
    #[must_use]
    pub const fn resends(&self) -> u64 {
        self.resends
    }

    /// Requests whose reply has not arrived within
    /// [`WorkloadOptions::request_timeout_ticks`], each paired with the replica
    /// to retry it against. Callers must submit every returned message.
    ///
    /// This is what a real client's read timeout does, and the harness needs it
    /// for two reasons. A dropped request or reply otherwise strands the
    /// client's only in-flight slot for the rest of the run, so any packet loss
    /// wedges the workload. And a request lost to a crashed primary can only be
    /// answered by the next one, which the client reaches by rotating its
    /// target.
    ///
    /// Resending is safe on both planes but not equally cheap: the metadata
    /// plane dedups on the retained request id and replays the cached reply,
    /// while the partition plane is at-least-once and may commit the op twice.
    /// The shadow already models that (`Effect` application is driven by what
    /// committed, not by what was targeted).
    #[must_use = "returned requests must be submitted or the client stays wedged"]
    pub fn due_resends(&mut self) -> Vec<(u8, Message<RoutedRequestHeader>)> {
        let timeout = self.options.request_timeout_ticks;
        if timeout == 0 {
            return Vec::new();
        }
        let replica_count = self.options.replica_count.max(1);
        let now = self.now;
        let mut due = Vec::new();
        for entry in self.outstanding.values_mut() {
            if now.saturating_sub(entry.attempted_tick) < timeout {
                continue;
            }
            entry.target = (entry.target + 1) % replica_count;
            entry.attempted_tick = now;
            entry.attempts += 1;
            due.push((entry.target, entry.message.deep_copy()));
        }
        self.resends += due.len() as u64;
        due
    }

    /// Outstanding requests as `(client, request, action, target, attempts)`, in
    /// key order. Diagnostic only: names what a run was still waiting on when it
    /// failed to drain, including which op, since some ops cannot be answered
    /// twice and a resend of those is a permanent stall rather than a slow one.
    #[must_use]
    pub(crate) fn outstanding_summary(&self) -> Vec<(u128, u64, Option<Action>, u8, u32)> {
        self.outstanding
            .iter()
            .map(|(&key, entry)| {
                (
                    key.0,
                    key.1,
                    self.auditor.in_flight_action(key),
                    entry.target,
                    entry.attempts,
                )
            })
            .collect()
    }

    /// In-flight count for one client. Keys are `(client, request)`, so the
    /// client's entries are one contiguous range.
    fn client_in_flight(&self, client_id: u128) -> usize {
        self.outstanding
            .range((client_id, 0)..=(client_id, u64::MAX))
            .count()
    }

    /// Aggregate in-flight ceiling: one queue's worth per declared client.
    /// Fixtures set `client_count` to the number of driven clients, the same
    /// coupling `strict_outcome_oracle` relies on.
    #[must_use]
    pub(crate) fn in_flight_bound(&self) -> usize {
        usize::from(self.options.client_count) * CLIENT_REQUEST_QUEUE_MAX
    }

    /// True when the run is fully serial (one client, one in-flight slot), the
    /// regime where the shadow equals committed server state. Gates the
    /// quiesce-time entity oracle the same way it gates the per-op equality
    /// oracle.
    #[must_use]
    pub(crate) const fn strict_outcome_oracle(&self) -> bool {
        self.strict_outcome_oracle
    }

    /// Build the next request for `client`. Returns the message and target
    /// replica index, or `None` if the client has no idle slot or
    /// `ops::sample` could not synthesize an input.
    ///
    /// Note: `pick_action`/`pick_target_replica`/`pick_outcome` draw from the
    /// PRNG before `sample` runs, so they advance the trace even when `sample`
    /// returns `None` (a targeted outcome whose precondition is unmet, e.g. a
    /// duplicate-name target with an empty shadow). `samples_none` counts these.
    pub fn build_request(
        &mut self,
        client: &SimClient,
    ) -> Option<(u8, Message<RoutedRequestHeader>)> {
        if !self.client_idle(client.client_id()) {
            return None;
        }

        let action = self.pick_action();
        let target = self.pick_target_replica();
        let outcome_id = self.pick_outcome(action);

        let Some((input, outcome)) = ops::sample(
            action,
            &mut self.shadow,
            &mut self.prng,
            &self.options,
            outcome_id,
        ) else {
            self.samples_none += 1;
            return None;
        };
        let message = ops::build_message(client, &input);

        let header = message.header();
        let key = (client.client_id(), header.request);
        self.auditor.record_in_flight(
            key,
            InFlight {
                action,
                input,
                outcome,
                request_namespace: header.group,
            },
        );
        self.outstanding.insert(
            key,
            Outstanding {
                message: message.deep_copy(),
                target,
                attempted_tick: self.now,
                attempts: 1,
            },
        );

        Some((target, message))
    }

    /// Validate and apply a reply. Returns [`SimCommand`]s the driver
    /// must run against the simulator (e.g. `init_partition`); the
    /// auditor stays transport-agnostic.
    ///
    /// Returns an empty `Vec` for unknown replies (duplicate or stale
    /// at-least-once) and for `OnReply::NsMismatch`. See
    /// [`auditor::ServerAuditor::on_reply`] for the per-variant contract.
    ///
    /// # Panics
    /// If a metadata reply carries a committed result code outside the op's
    /// declared result enum (a server bug).
    #[must_use = "returned SimCommands must be applied; call apply_sim_commands or use Workload::run"]
    pub fn on_reply(&mut self, reply: &Message<ReplyHeader>) -> Vec<SimCommand> {
        let header = reply.header();
        let key = (header.client, header.request);
        let entry = match self.auditor.on_reply(key, header) {
            OnReply::Match(entry) => entry,
            OnReply::NsMismatch => {
                // Entry consumed; release slot, skip effects (misrouted).
                self.release_outstanding(key);
                return Vec::new();
            }
            OnReply::Unknown => return Vec::new(),
        };

        // Decode the committed result code. Metadata replies carry a
        // result section (see `ApplyReply::to_reply_body`); partition-plane
        // replies do not, hence the `is_metadata` gate.
        let committed_code = if header.operation.is_metadata() {
            // `size` spans header + body, but `Message::try_from` never gates
            // `size >= size_of::<ReplyHeader>()`, so a short `size` reaches here.
            // Assert it (loud server-bug diagnostic) before the slice below
            // panics with start > end.
            assert!(
                header.size as usize >= size_of::<ReplyHeader>(),
                "metadata op {:?} reply size {} below header size {} (client={}, request={})",
                entry.action,
                header.size,
                size_of::<ReplyHeader>(),
                header.client,
                header.request,
            );
            let body = &reply.as_slice()[size_of::<ReplyHeader>()..header.size as usize];
            // A metadata reply always carries a well-formed result section, so
            // `None` is a truncated/corrupt one: a server bug, not a silent Ok
            // (the rejection->success flip "classify never guesses" forbids).
            let Some(code) = result_code(body) else {
                panic!(
                    "metadata op {:?} reply has a truncated or corrupt result section \
                     (client={}, request={})",
                    entry.action, header.client, header.request,
                );
            };
            // The state machine only commits codes its own result enum declares,
            // so an unrecognized one is a server bug (a race still yields a
            // declared code). Classify never guesses.
            assert!(
                result_code_recognized(header.operation, code),
                "metadata op {:?} returned unrecognized result code {code} \
                 (client={}, request={})",
                entry.action,
                header.client,
                header.request,
            );
            code
        } else {
            0
        };

        // Classify the *actual* committed outcome from the wire result code.
        let classified = ops::classify_reply(entry.action, committed_code);

        // Equality oracle: the targeted outcome must match what committed. Sound
        // only for a fully serial run (see `strict_outcome_oracle`); with several
        // clients a concurrent commit can flip it (a targeted duplicate races a
        // delete), so there the recognized-code check above is the only oracle.
        if self.strict_outcome_oracle {
            assert_eq!(
                classified, entry.outcome,
                "outcome-first oracle: targeted {:?} but committed {classified:?} \
                 (action={:?}, code={committed_code}, client={}, request={})",
                entry.outcome, entry.action, header.client, header.request,
            );
        }

        // Effect-follows-actual: drive the shadow off the committed outcome, never
        // the targeted one. Success mutates; a nonzero code is a committed no-op
        // whose `predicted_effect` is `Effect::None`. Keeps the shadow correct
        // under at-least-once re-execution and races.
        let effect = ops::predicted_effect(&entry.input, &classified);
        if committed_code != 0 {
            self.auditor.note_committed_rejection();
        }
        let result = self.shadow.apply(effect);

        // Count a commit only on a success that mutated the shadow, so
        // `commits_per_action` tracks net shadow state (rejections and no-op
        // applies, e.g. AddTopic after a concurrent RemoveStream, are excluded).
        if committed_code == 0 && result.applied {
            self.auditor.note_committed(entry.action);
        }

        self.release_outstanding(key);

        result.sim_commands
    }

    /// Drop a request's retry entry, freeing the client's slot. Paired with the
    /// auditor consuming its expectation for the same key, so the two never
    /// disagree about what is outstanding.
    ///
    /// # Panics
    /// Panics if no entry exists for `key`; the auditor only reports a match or
    /// a namespace mismatch for a key it was given, and `build_request` records
    /// both sides together, so a miss here means the two drifted.
    fn release_outstanding(&mut self, key: (u128, u64)) {
        assert!(
            self.outstanding.remove(&key).is_some(),
            "no outstanding entry for (client={}, request={}); the auditor \
             matched a key the retry buffer never recorded",
            key.0,
            key.1,
        );
    }

    /// Debug counter for `sample()` returning `None`. Surfaces sampling
    /// preconditions that aren't met (e.g. shadow has no live stream
    /// when `DeleteStream` is drawn).
    #[must_use]
    pub const fn samples_none(&self) -> u64 {
        self.samples_none
    }

    fn pick_action(&mut self) -> Action {
        use strum::IntoEnumIterator;

        let r: u32 = self.prng.random_range(0..100);
        let weights = &self.options.weights;
        let mut cum: u32 = 0;
        for action in Action::iter() {
            cum += u32::from(weights.weight(action));
            if r < cum {
                return action;
            }
        }
        unreachable!("ActionWeights sum to 100; r < 100 must hit a bucket")
    }

    fn pick_target_replica(&mut self) -> u8 {
        let f: f32 = self.prng.random();
        if f < self.options.target_non_primary_ratio && self.options.replica_count > 1 {
            self.prng.random_range(1..self.options.replica_count)
        } else {
            0
        }
    }

    /// Pick which declared outcome to target for `action`. Single-outcome ops
    /// (the partition/offset plane: `SendMessages`, `StoreConsumerOffset`, ...)
    /// return 0; multi-outcome ops (most metadata ops) draw one, advancing the
    /// PRNG. Adding an outcome to a single-outcome op, or a weight change to which
    /// ops are sampled, shifts the draw order and reply trace - see the locked
    /// baseline in `workload_replay_is_deterministic`.
    fn pick_outcome(&mut self, action: Action) -> usize {
        let count = ops::outcome_count(action);
        if count <= 1 {
            0
        } else {
            self.prng.random_range(0..count)
        }
    }
}

/// Salt mixed into the workload seed for the fault PRNG, so crash scheduling
/// is reproducible from the seed yet independent of the traffic draw order
/// (the determinism baseline stays valid with injection on).
const FAULT_SEED_SALT: u64 = 0x5A1A_F0E5_FACE_0001;

/// Drive the simulator until `tick_budget` elapses or `replies_target`
/// replies are seen. Returns the number of replies seen.
///
/// The invariants are asserted after every tick, so a consensus or
/// workload regression panics at the tick it occurs (the seed in the message
/// replays it). Crash and restart injection runs through [`FaultInjector`],
/// idle unless one of the two probabilities is set.
///
/// Discards the injector; use [`run_with_faults`] to read the crash and restart
/// counts back.
pub fn run(
    sim: &mut Simulator,
    workload: &mut Workload,
    clients: &[SimClient],
    tick_budget: u64,
    replies_target: u64,
) -> u64 {
    let mut injector = FaultInjector::new(workload.options.seed, sim.replica_count);
    run_with_faults(
        sim,
        workload,
        clients,
        tick_budget,
        replies_target,
        &mut injector,
    )
}

/// [`run`] against a caller-owned [`FaultInjector`], so a test can assert what
/// was actually injected instead of trusting the probabilities to have fired.
pub fn run_with_faults(
    sim: &mut Simulator,
    workload: &mut Workload,
    clients: &[SimClient],
    tick_budget: u64,
    replies_target: u64,
    injector: &mut FaultInjector,
) -> u64 {
    let mut invariants = Invariants::new();
    let mut replies_seen = 0u64;
    for _ in 0..tick_budget {
        workload.tick();
        injector.step(sim, workload);
        // Resend before sampling: a timed-out request still holds the client's
        // slot, so `build_request` would decline it anyway.
        resubmit_due(sim, workload);
        for client in clients {
            if let Some((target, msg)) = workload.build_request(client) {
                sim.submit_request(client.client_id(), target, msg.into_generic());
            }
        }
        for reply in sim.step() {
            let cmds = workload.on_reply(&reply);
            apply_sim_commands(sim, &cmds);
            replies_seen += 1;
        }
        invariants.check(sim, workload);
        if replies_seen >= replies_target {
            break;
        }
    }
    replies_seen
}

/// Crash and restart injection with stability windows, in the shape of
/// TigerBeetle's VOPR: a crash must last a while before it may be repaired, and
/// a repaired replica must run a while before it may fail again.
///
/// Owns the fault PRNG so crash scheduling stays reproducible from the seed yet
/// independent of the traffic draw order. Draws nothing while both probabilities
/// are zero, so a fault-free run replays bit-identically.
pub struct FaultInjector {
    prng: Xoshiro256Plus,
    /// Tick of each replica's last crash or restart, indexed by replica id.
    /// Compared against the stability windows to decide eligibility.
    last_transition: Vec<u64>,
    now: u64,
    crashes: u64,
    restarts: u64,
}

impl FaultInjector {
    #[must_use]
    pub fn new(seed: u64, replica_count: u8) -> Self {
        Self {
            prng: Xoshiro256Plus::seed_from_u64(seed ^ FAULT_SEED_SALT),
            last_transition: vec![0; usize::from(replica_count)],
            now: 0,
            crashes: 0,
            restarts: 0,
        }
    }

    #[must_use]
    pub const fn crashes(&self) -> u64 {
        self.crashes
    }

    #[must_use]
    pub const fn restarts(&self) -> u64 {
        self.restarts
    }

    /// Advance one tick and maybe crash or restart one replica.
    ///
    /// Restart is considered before crash so a single tick never both revives
    /// and kills, which would make the stability windows meaningless.
    pub fn step(&mut self, sim: &mut Simulator, workload: &Workload) {
        self.now += 1;
        self.maybe_restart(sim, workload);
        self.maybe_crash(sim, workload);
    }

    /// With probability `restart_per_tick_ratio`, restart one replica that has
    /// been down at least `crash_stability_ticks`.
    ///
    /// This is what exercises rejoin: the replica comes back with its durable
    /// superblock and metadata WAL but no volatile consensus state, asks the
    /// current view's primary for a `StartView`, and repairs the log it missed.
    fn maybe_restart(&mut self, sim: &mut Simulator, workload: &Workload) {
        if workload.options.restart_per_tick_ratio <= 0.0 {
            return;
        }
        let eligible: Vec<u8> = (0..sim.replica_count)
            .filter(|replica_idx| sim.is_crashed(*replica_idx))
            .filter(|replica_idx| {
                self.stable_for(*replica_idx) >= workload.options.crash_stability_ticks
            })
            .collect();
        if eligible.is_empty() {
            return;
        }
        let roll: f32 = self.prng.random();
        if roll >= workload.options.restart_per_tick_ratio {
            return;
        }
        let revived = eligible[self.prng.random_range(0..eligible.len())];
        sim.replica_restart(revived);
        self.last_transition[usize::from(revived)] = self.now;
        self.restarts += 1;
    }

    /// With probability `crash_per_tick_ratio`, crash one live replica that has
    /// been up at least `restart_stability_ticks`, provided doing so leaves at
    /// least `min_survivors` live.
    ///
    /// Primaries are excluded unless `spare_primary` is off. The exclusion set
    /// comes from `Simulator::primary_index`, which reads `partitions()`, so it
    /// names partition-plane primaries; the metadata primary is spared only by
    /// co-location, since every group starts at view 0 with
    /// `primary = view % replica_count`. Once views diverge across planes the
    /// metadata primary can be crashed even with this on.
    fn maybe_crash(&mut self, sim: &mut Simulator, workload: &Workload) {
        if workload.options.crash_per_tick_ratio <= 0.0 {
            return;
        }
        let live: Vec<u8> = (0..sim.replica_count)
            .filter(|replica_idx| !sim.is_crashed(*replica_idx))
            .collect();
        if live.len() <= usize::from(workload.options.min_survivors) {
            return;
        }
        let roll: f32 = self.prng.random();
        if roll >= workload.options.crash_per_tick_ratio {
            return;
        }
        let primaries: HashSet<u8> = if workload.options.spare_primary {
            workload
                .options
                .namespaces
                .iter()
                .filter_map(|ns| sim.primary_index(*ns))
                .collect()
        } else {
            HashSet::new()
        };
        let eligible: Vec<u8> = live
            .into_iter()
            .filter(|replica_idx| !primaries.contains(replica_idx))
            .filter(|replica_idx| {
                self.stable_for(*replica_idx) >= workload.options.restart_stability_ticks
            })
            .collect();
        if eligible.is_empty() {
            return;
        }
        let victim = eligible[self.prng.random_range(0..eligible.len())];
        sim.replica_crash(victim);
        self.last_transition[usize::from(victim)] = self.now;
        self.crashes += 1;
    }

    /// Ticks since this replica last changed state. A replica that never
    /// transitioned counts from tick 0, so the first crash still has to wait out
    /// `restart_stability_ticks`.
    fn stable_for(&self, replica_idx: u8) -> u64 {
        self.now
            .saturating_sub(self.last_transition[usize::from(replica_idx)])
    }
}

/// Submit every request whose reply is overdue (see [`Workload::due_resends`]).
///
/// The client id rides the retained message's header, so a resend re-enters the
/// network exactly as the original did, only aimed at the next replica.
pub fn resubmit_due(sim: &mut Simulator, workload: &mut Workload) {
    for (target, message) in workload.due_resends() {
        let client_id = message.header().client;
        sim.submit_request(client_id, target, message.into_generic());
    }
}

/// Apply `SimCommand`s returned by [`Workload::on_reply`].
///
/// Callers must invoke this (or [`run`]) for every batch of returned
/// commands; the auditor itself stays transport-agnostic so the workload
/// can be reused outside the in-process simulator.
pub fn apply_sim_commands(sim: &mut Simulator, cmds: &[SimCommand]) {
    for cmd in cmds {
        match cmd {
            SimCommand::InitPartition { ns } => sim.init_partition(*ns),
        }
    }
}
