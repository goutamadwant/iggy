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

//! Cross-replica committed-log equality, after TigerBeetle's
//! `testing/cluster/state_checker.zig`.
//!
//! The per-tick checks in [`super::invariants`] catch a single replica
//! contradicting itself, and [`super::oracle`] compares committed metadata
//! against the workload's shadow. Neither compares replicas to EACH OTHER, which
//! is the actual consensus property: two replicas that both committed op N must
//! have committed the same op N.
//!
//! Modelled on TigerBeetle's checker rather than invented: it keeps one canonical
//! commit chain, asserts every replica agrees with it wherever they overlap
//! (`(commit_a == commit_b) == (checksum_a == checksum_b)`), and asserts the chain
//! is hash-linked (`header_b.parent == checksum_a`). Recording which replicas
//! reached each op also makes the check provably non-vacuous, which matters:
//! a chain nothing was ever compared against passes silently.

use crate::Simulator;
use consensus::MetadataHandle;
use iggy_binary_protocol::PrepareHeader;
use journal::Journal;
use std::collections::{BTreeMap, BTreeSet};

/// One op of the canonical committed chain.
#[derive(Debug)]
struct CanonicalCommit {
    /// Identity of the prepare committed at this op. Two replicas disagreeing
    /// here is a divergence: the same log position holds different history.
    ///
    /// The chain's hash link is checked against this rather than against a stored
    /// `parent`: an arriving header's `parent` must equal the canonical previous
    /// op's `checksum`, so keeping each entry's own parent as well would record a
    /// value nothing ever reads.
    checksum: u128,
    /// Replicas observed committing this op, so the check can prove it compared
    /// something rather than passing over an empty chain.
    replicas: BTreeSet<u8>,
}

/// Canonical committed metadata chain, accumulated across ticks.
#[derive(Debug, Default)]
pub struct StateChecker {
    commits: BTreeMap<u64, CanonicalCommit>,
    /// Highest op already verified per replica, so a tick only walks what is
    /// new. A high-water mark, never lowered: a restart recovers its commit
    /// point from a lower bound (`SimJournal::recovery_commit_watermark`) and so
    /// may report a smaller `commit_min` than it did before, and re-verifying
    /// that prefix every tick would make this quadratic for no gain.
    verified_upto: BTreeMap<u8, u64>,
}

impl StateChecker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold every live replica's newly committed metadata ops into the canonical
    /// chain, asserting agreement.
    ///
    /// Reads committed state only (ops at or below `commit_min`), so a prepare
    /// still in flight is never compared: replicas are allowed to disagree about
    /// uncommitted tails, and that is what a view change resolves.
    ///
    /// Crashed replicas are skipped rather than dropped: their high-water mark is
    /// kept, so a restart re-verifies only what it commits anew.
    ///
    /// # Panics
    /// On any disagreement about a committed op, or a broken hash chain. The
    /// message names both replicas and the op, and the seed replays the run.
    pub fn check(&mut self, sim: &Simulator, seed: u64) {
        for replica_idx in 0..sim.replica_count {
            if sim.is_crashed(replica_idx) {
                continue;
            }
            let replica = &sim.replicas[usize::from(replica_idx)];
            let Some(consensus) = replica.shards[0].plane.metadata().consensus.as_ref() else {
                continue;
            };
            let committed = consensus.commit_min();
            let verified = self.verified_upto.get(&replica_idx).copied().unwrap_or(0);
            for op in (verified + 1)..=committed {
                // Absent header at a committed op: the sim never checkpoints, so
                // nothing drains the prefix and this would be a real hole. Left to
                // the journal's own invariants rather than asserted here, since a
                // recovered replica legitimately reports a commit point one above
                // its head (the watermark is a lower bound).
                let Some(header) = journaled_header(replica, op) else {
                    continue;
                };
                self.record(replica_idx, op, &header, seed);
            }
            self.verified_upto
                .insert(replica_idx, verified.max(committed));
        }
    }

    /// Number of ops in the canonical chain. Tests assert this is non-zero, so a
    /// green run cannot mean "never compared anything".
    #[must_use]
    pub fn chain_len(&self) -> usize {
        self.commits.len()
    }

    /// Ops witnessed by more than one replica. The only ops that actually
    /// exercised the equality property: an op only ever seen on one replica was
    /// recorded, never compared.
    #[must_use]
    pub fn ops_compared(&self) -> usize {
        self.commits
            .values()
            .filter(|commit| commit.replicas.len() > 1)
            .count()
    }

    fn record(&mut self, replica_idx: u8, op: u64, header: &PrepareHeader, seed: u64) {
        // Hash-chain link, checked before the identity comparison so a diverged
        // prefix is reported at the op where the chains part rather than at the
        // first op whose contents happen to differ.
        if let Some(previous) = self.commits.get(&(op - 1))
            && header.parent != previous.checksum
        {
            panic!(
                "replica {replica_idx} committed op {op} whose parent {:#x} is not the \
                 canonical op {} checksum {:#x}: its committed history forked below this \
                 op (seed={seed:#x})",
                header.parent,
                op - 1,
                previous.checksum,
            );
        }
        match self.commits.get_mut(&op) {
            Some(canonical) => {
                assert_eq!(
                    canonical.checksum, header.checksum,
                    "replicas disagree on committed op {op}: canonical checksum {:#x} \
                     (committed by {:?}) vs replica {replica_idx}'s {:#x}. Two replicas \
                     committed different history at the same log position (seed={seed:#x})",
                    canonical.checksum, canonical.replicas, header.checksum,
                );
                canonical.replicas.insert(replica_idx);
            }
            None => {
                self.commits.insert(
                    op,
                    CanonicalCommit {
                        checksum: header.checksum,
                        replicas: BTreeSet::from([replica_idx]),
                    },
                );
            }
        }
    }
}

/// Assert every live replica's committed metadata prefix agrees, op for op.
///
/// The quiesce-time counterpart to [`StateChecker::check`]: that one folds ops in
/// as they commit and so compares whatever happened to overlap, while this walks
/// the full committed prefix of every live replica at rest and requires the
/// shorter to be a genuine PREFIX of the longer. A replica may still trail (it
/// may have missed the last commit broadcast), but where it has committed
/// anything it must match.
///
/// # Panics
/// If two live replicas disagree on any committed op.
pub fn assert_committed_prefixes_agree(sim: &Simulator, seed: u64) {
    let mut canonical: BTreeMap<u64, (u128, u8)> = BTreeMap::new();
    for replica_idx in 0..sim.replica_count {
        if sim.is_crashed(replica_idx) {
            continue;
        }
        let replica = &sim.replicas[usize::from(replica_idx)];
        let Some(consensus) = replica.shards[0].plane.metadata().consensus.as_ref() else {
            continue;
        };
        for op in 1..=consensus.commit_min() {
            let Some(header) = journaled_header(replica, op) else {
                continue;
            };
            match canonical.get(&op) {
                Some(&(checksum, owner)) => assert_eq!(
                    checksum, header.checksum,
                    "at quiesce replica {replica_idx} and replica {owner} disagree on \
                     committed metadata op {op}: {:#x} vs {checksum:#x} (seed={seed:#x})",
                    header.checksum,
                ),
                None => {
                    canonical.insert(op, (header.checksum, replica_idx));
                }
            }
        }
    }
}

/// The header a replica has journaled at `op`, if any.
///
/// Reads shard 0's retained metadata WAL, which is where the committed metadata
/// log lives; the journal is harness-owned so this also works across a restart.
fn journaled_header(replica: &crate::SimReplica, op: u64) -> Option<PrepareHeader> {
    let slot = usize::try_from(op).ok()?;
    replica.metadata_journal.header(slot).copied()
}
