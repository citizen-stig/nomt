//! Session latency: workload scenarios with correctness invariants, and slowdown guards.
//!
//! Every workload here keeps a model of the expected state and checks, outside the timed code:
//! reads against the model (including values only in uncommitted overlays), every root against a
//! trie built independently from the model, the chaining of previous roots, witnesses and proofs,
//! rollback, and the state after the final commit and after reopening the database.
//!
//! The guards (`guard_*`) fail when a cost is out of proportion. A test binary has no baseline
//! revision to compare with, so each guard measures two configurations in the same process, in
//! interleaved rounds, and bounds the ratio of their medians. That catches fixed per-session
//! costs, costs that grow with a setting that should not matter, contention between threads or
//! databases, starvation, superlinear scaling and drift, in whatever profile the tests are built
//! with: a cost that is invisible in an optimized build can dominate small sessions in an
//! unoptimized or coverage-instrumented one. It does not catch a uniform slowdown of everything;
//! that needs a baseline (see `benchtop`).
//!
//! A guard fails only if it is over its limit in three independent attempts. All tests of this
//! file run one at a time, and each under a watchdog that turns a hang into a failure.
//!
//! Timings are printed (`LAT` and `GUARD` lines, visible with `--nocapture`). `LAT_SCALE` scales
//! iteration counts and the larger workload sizes, in percent (default 100).

use bitvec::prelude::*;
use nomt::{
    hasher::{Sha2Hasher, ValueHasher},
    proof,
    trie::{KeyPath, LeafData, Node, ValueHash},
    InvalidAncestors, KeyReadWrite, Nomt, Options, Overlay, Session, SessionParams, Witness,
    WitnessMode,
};
use std::{
    collections::{BTreeMap, VecDeque},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Barrier, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

type Db = Nomt<Sha2Hasher>;

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// Tests of one binary run on parallel threads; timings need the machine to themselves.
static SERIAL: Mutex<()> = Mutex::new(());

/// Runs `body` alone and fails, rather than hangs, if it does not return.
fn serial(name: &'static str, body: impl FnOnce() + Send + 'static) {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (done_tx, done_rx) = mpsc::channel();
    let thread = std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            body();
            let _ = done_tx.send(());
        })
        .unwrap();
    let limit = Duration::from_secs(300 * scale().max(100) / 100);
    match done_rx.recv_timeout(limit) {
        Ok(()) => thread.join().unwrap(),
        // The body panicked.
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            std::panic::resume_unwind(thread.join().unwrap_err())
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("{name}: still running after {limit:?}: hang or deadlock")
        }
    }
}

fn scale() -> u64 {
    std::env::var("LAT_SCALE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
}

/// An iteration count at the current scale.
fn scaled(iters: u64) -> u64 {
    (iters * scale() / 100).max(3)
}

/// A workload size that grows with the scale up to `full`.
fn sized(default: u64, full: u64) -> u64 {
    (default * scale() / 100).clamp(1, full)
}

/// The `i`-th key of database `db`: splitmix64, four words.
fn key(db: u64, i: u64) -> KeyPath {
    let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(db << 56);
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        chunk.copy_from_slice(&(z ^ (z >> 31)).to_be_bytes());
    }
    out
}

fn open(path: &Path, rollback: bool, commit_concurrency: Option<usize>, warm_up: bool) -> Db {
    let mut o = Options::new();
    o.path(path);
    o.rollback(rollback);
    o.max_rollback_log_len(1);
    o.prepopulate_page_cache(true);
    o.metrics(true);
    o.warm_up(warm_up);
    if let Some(commit_concurrency) = commit_concurrency {
        o.commit_concurrency(commit_concurrency);
    }
    Db::open(o).unwrap()
}

fn median(samples: &[Duration]) -> Duration {
    quantile(samples, 50)
}

fn quantile(samples: &[Duration], percent: usize) -> Duration {
    let mut sorted = samples.to_vec();
    sorted.sort();
    sorted[(sorted.len() - 1) * percent / 100]
}

/// The expected contents of a database.
#[derive(Default)]
struct Model {
    values: BTreeMap<KeyPath, (Vec<u8>, ValueHash)>,
}

impl Model {
    fn get(&self, key: &KeyPath) -> Option<&Vec<u8>> {
        self.values.get(key).map(|(value, _)| value)
    }

    fn hash(&self, key: &KeyPath) -> Option<ValueHash> {
        self.values.get(key).map(|(_, hash)| *hash)
    }

    fn set(&mut self, key: KeyPath, value: Vec<u8>) {
        let hash = Sha2Hasher::hash_value(&value);
        self.values.insert(key, (value, hash));
    }

    /// The root of a trie built from scratch over the model.
    fn root(&self) -> Node {
        let leaves = self.values.iter().map(|(key, (_, hash))| (*key, *hash));
        nomt_core::update::build_trie::<Sha2Hasher>(0, leaves, |_| {})
    }

    /// The root after overwriting the values of some existing keys.
    fn root_with(&self, writes: &[(KeyPath, KeyReadWrite)]) -> Node {
        let written: BTreeMap<_, _> = writes
            .iter()
            .map(|(key, read_write)| match read_write {
                KeyReadWrite::Write(Some(value)) => (*key, Sha2Hasher::hash_value(value)),
                _ => unreachable!("only overwrites"),
            })
            .collect();
        let leaves = self.values.iter().map(|(key, (_, hash))| {
            assert!(written.len() <= self.values.len());
            (*key, written.get(key).copied().unwrap_or(*hash))
        });
        nomt_core::update::build_trie::<Sha2Hasher>(0, leaves, |_| {})
    }

    /// Checks the committed state of `nomt` against the model.
    fn check_committed(&self, nomt: &Db, absent: &[KeyPath], when: &str) {
        assert_eq!(nomt.root().into_inner(), self.root(), "root {when}");
        let session = nomt.begin_session(SessionParams::default());
        for (key, (value, _)) in &self.values {
            let read = session.read(*key).unwrap();
            assert_eq!(read.as_ref(), Some(value), "value {when}");
        }
        for key in absent {
            assert_eq!(session.read(*key).unwrap(), None, "absent key {when}");
        }
    }
}

/// Checks a witness: its reads against the state before the session, each path proof against
/// `prev_root`, and that applying its writes to the proven paths gives `root`.
fn check_witness(witness: &Witness, before: &Model, prev_root: Node, root: Node) {
    let mut updates = Vec::new();
    for (i, witnessed_path) in witness.path_proofs.iter().enumerate() {
        let verified = witnessed_path
            .inner
            .verify::<Sha2Hasher>(witnessed_path.path.path(), prev_root)
            .expect("witness path proof verifies against the previous root");

        for read in witness
            .operations
            .reads
            .iter()
            .filter(|r| r.path_index == i)
        {
            assert_eq!(read.value, before.hash(&read.key), "witnessed read value");
            match read.value {
                None => assert!(verified.confirm_nonexistence(&read.key).unwrap()),
                Some(value_hash) => {
                    let leaf = LeafData {
                        key_path: read.key,
                        value_hash,
                    };
                    assert!(verified.confirm_value(&leaf).unwrap());
                }
            }
        }

        let ops: Vec<_> = witness
            .operations
            .writes
            .iter()
            .filter(|w| w.path_index == i)
            .map(|w| (w.key, w.value))
            .collect();
        if !ops.is_empty() {
            updates.push(proof::PathUpdate {
                inner: verified,
                ops,
            });
        }
    }
    updates.sort_by(|a, b| a.inner.path().partial_cmp(b.inner.path()).unwrap());
    assert_eq!(
        proof::verify_update::<Sha2Hasher>(prev_root, &updates).unwrap(),
        root,
        "the witnessed update reproduces the new root"
    );
}

/// Collects the samples of a scenario's phases and prints them when dropped.
struct Recorder {
    scenario: &'static str,
    phases: Vec<(&'static str, Vec<Duration>)>,
}

impl Recorder {
    fn new(scenario: &'static str) -> Self {
        Recorder {
            scenario,
            phases: Vec::new(),
        }
    }

    fn record(&mut self, phase: &'static str, sample: Duration) {
        match self.phases.iter_mut().find(|(name, _)| *name == phase) {
            Some((_, samples)) => samples.push(sample),
            None => self.phases.push((phase, vec![sample])),
        }
    }

    fn time<R>(&mut self, phase: &'static str, f: impl FnOnce() -> R) -> R {
        let start = Instant::now();
        let out = f();
        self.record(phase, start.elapsed());
        out
    }

    fn record_block(&mut self, times: &BlockTimes) {
        self.record("begin", times.begin);
        self.record("access", times.access);
        self.record("finish", times.finish);
        if let Some(seal) = times.seal {
            self.record("into_overlay", seal);
        }
        self.record("block", times.total());
        if let Some(commit) = times.commit {
            self.record("commit", commit);
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        for (phase, samples) in &self.phases {
            let mean = samples.iter().sum::<Duration>() / samples.len() as u32;
            println!(
                "LAT {:<28} {phase:<12} n={:<4} mean={mean:<10.1?} p50={:<10.1?} p99={:<10.1?} \
                 max={:.1?}",
                self.scenario,
                samples.len(),
                median(samples),
                quantile(samples, 99),
                quantile(samples, 100),
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The block workload
// ---------------------------------------------------------------------------------------------

/// Where a full chain's oldest overlay is committed.
#[derive(Clone, Copy, PartialEq)]
enum Commit {
    /// On the thread running the blocks, before the next block.
    Inline,
    /// On another thread, while the next block's session opens.
    Thread,
}

/// A stream of blocks: a session per database, reads, `finish`, then either a direct commit or an
/// overlay appended to a chain whose oldest member is committed once the chain is full.
#[derive(Clone, Copy)]
struct Workload {
    /// Independent databases, each getting a session per block.
    dbs: usize,
    /// Keys committed before the first block.
    prefill: u64,
    /// Uncommitted overlays kept per database. 0 commits every finished session directly.
    chain: usize,
    /// Keys written per block and database: half fresh, half rewrites.
    writes: u64,
    /// Keys only read per block and database. They are in the actuals only with a witness.
    reads: u64,
    witness: bool,
    rollback: bool,
    /// Whether `Session::warm_up` does anything: off by default in NOMT.
    warm_up: bool,
    /// `None` keeps the default.
    commit_concurrency: Option<usize>,
    commit: Commit,
    iters: u64,
}

/// A small block on a short overlay chain.
const SMALL: Workload = Workload {
    dbs: 1,
    prefill: 0,
    chain: 4,
    writes: 20,
    reads: 20,
    witness: false,
    rollback: true,
    warm_up: false,
    commit_concurrency: None,
    commit: Commit::Inline,
    iters: 16,
};

/// A chain that never fills, so no commit happens between the measured blocks.
const UNBOUNDED: Workload = Workload {
    chain: usize::MAX,
    ..SMALL
};

/// The timed parts of a block. The invariant checks between them are not timed.
struct BlockTimes {
    begin: Duration,
    access: Duration,
    finish: Duration,
    /// `into_overlay`, unless the session was committed directly.
    seal: Option<Duration>,
    /// The direct commit, if any. Not part of the block total.
    commit: Option<Duration>,
}

impl BlockTimes {
    fn total(&self) -> Duration {
        self.begin + self.access + self.finish + self.seal.unwrap_or_default()
    }
}

/// A database, its chain of uncommitted overlays, and the model of the state at the chain's tip.
struct ChainedDb {
    id: u64,
    dir: tempfile::TempDir,
    rollback: bool,
    commit_concurrency: Option<usize>,
    warm_up: bool,
    nomt: Arc<Db>,
    /// Newest first.
    chain: VecDeque<Overlay>,
    model: Model,
    tip_root: Node,
    next_key: u64,
    blocks_since_root_check: usize,
}

impl ChainedDb {
    fn open(id: u64, w: &Workload) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let nomt = open(
            &dir.path().join("db"),
            w.rollback,
            w.commit_concurrency,
            w.warm_up,
        );

        let mut model = Model::default();
        if w.prefill > 0 {
            let mut actuals = Vec::new();
            for i in 0..w.prefill {
                model.set(key(id, i), vec![1; 64]);
                actuals.push((key(id, i), KeyReadWrite::Write(Some(vec![1; 64]))));
            }
            actuals.sort_by(|a, b| a.0.cmp(&b.0));
            let finished = nomt
                .begin_session(SessionParams::default())
                .finish(actuals)
                .unwrap();
            finished.commit(&nomt).unwrap();
        }
        let tip_root = nomt.root().into_inner();
        assert_eq!(tip_root, model.root(), "root after prefill");

        ChainedDb {
            id,
            dir,
            rollback: w.rollback,
            commit_concurrency: w.commit_concurrency,
            warm_up: w.warm_up,
            nomt: Arc::new(nomt),
            chain: VecDeque::new(),
            model,
            tip_root,
            next_key: w.prefill,
            blocks_since_root_check: 0,
        }
    }

    /// If the chain is full, returns the commit of its oldest overlay, which yields its duration.
    fn full_chain_commit(&mut self, w: &Workload) -> Option<impl FnOnce() -> Duration + Send> {
        if w.chain == 0 || self.chain.len() < w.chain {
            return None;
        }
        let oldest = self.chain.pop_back().unwrap();
        let nomt = self.nomt.clone();
        Some(move || {
            let root = oldest.root();
            let start = Instant::now();
            oldest.commit(&nomt).unwrap();
            let elapsed = start.elapsed();
            assert_eq!(nomt.root(), root, "root after committing an overlay");
            elapsed
        })
    }

    /// One block on top of the chain. `iter` selects the keys and the written value.
    fn block(&mut self, iter: u64, w: &Workload) -> BlockTimes {
        let start = Instant::now();
        // With `Commit::Thread` the chain is incomplete until the commit of the previous oldest
        // overlay has taken the write lock and marked it committed.
        let params = loop {
            match SessionParams::default().overlay(self.chain.iter()) {
                Ok(params) => break params,
                Err(InvalidAncestors::Incomplete) => std::thread::yield_now(),
                Err(e) => panic!("{e:?}"),
            }
        };
        let witness_mode = if w.witness {
            WitnessMode::read_write()
        } else {
            WitnessMode::disabled()
        };
        let session = self.nomt.begin_session(params.witness_mode(witness_mode));
        let begin = start.elapsed();

        assert_eq!(
            session.prev_root().into_inner(),
            self.tip_root,
            "a session starts from the root of the newest overlay"
        );

        let start = Instant::now();
        let mut actuals = Vec::with_capacity((w.writes + w.reads) as usize);
        let mut only_read = Vec::with_capacity(w.reads as usize);
        for i in 0..w.writes {
            let k = if i % 2 == 0 || self.next_key == 0 {
                self.next_key += 1;
                key(self.id, self.next_key - 1)
            } else {
                key(self.id, (iter * 7919 + i * 104_729) % self.next_key)
            };
            session.warm_up(k);
            let prior = session.read(k).unwrap();
            let value = Some(iter.to_le_bytes().repeat(8));
            actuals.push((k, KeyReadWrite::ReadThenWrite(prior, value)));
        }
        for i in 0..w.reads {
            if self.next_key == 0 {
                break;
            }
            let k = key(self.id, (iter * 31 + i * 15_485_863) % self.next_key);
            session.warm_up(k);
            only_read.push((k, session.read(k).unwrap()));
        }
        let access = start.elapsed();

        // Reads see the committed state plus every overlay of the chain, and none of this
        // session's own writes.
        for (k, read_write) in &actuals {
            let KeyReadWrite::ReadThenWrite(prior, _) = read_write else {
                unreachable!()
            };
            assert_eq!(prior.as_ref(), self.model.get(k), "read of a key to write");
        }
        for (k, value) in &only_read {
            assert_eq!(value.as_ref(), self.model.get(k), "read");
        }

        if w.witness {
            actuals.extend(
                only_read
                    .into_iter()
                    .map(|(k, v)| (k, KeyReadWrite::Read(v))),
            );
        }
        // Stable, so a key that occurs twice keeps its first entry, and writes come first.
        actuals.sort_by(|a, b| a.0.cmp(&b.0));
        actuals.dedup_by(|a, b| a.0 == b.0);
        let writes: Vec<_> = actuals
            .iter()
            .filter_map(|(k, read_write)| match read_write {
                KeyReadWrite::ReadThenWrite(_, Some(value)) => Some((*k, value.clone())),
                _ => None,
            })
            .collect();

        let start = Instant::now();
        let mut finished = session.finish(actuals).unwrap();
        let finish = start.elapsed();

        let root = finished.root().into_inner();
        assert_eq!(finished.prev_root().into_inner(), self.tip_root);
        if w.witness {
            let witness = finished.take_witness().expect("witness was requested");
            check_witness(&witness, &self.model, self.tip_root, root);
        }
        for (k, value) in writes {
            self.model.set(k, value);
        }
        // Building the model's trie costs as much as the model is large, so large models are
        // checked less often: about 256 keys' worth of work per block.
        self.blocks_since_root_check += 1;
        if self.blocks_since_root_check * 256 >= self.model.values.len() {
            assert_eq!(root, self.model.root(), "root of a finished session");
            self.blocks_since_root_check = 0;
        }

        let (seal, commit) = if w.chain == 0 {
            let start = Instant::now();
            finished.commit(&self.nomt).unwrap();
            let commit = start.elapsed();
            assert_eq!(self.nomt.root().into_inner(), root, "root after a commit");
            (None, Some(commit))
        } else {
            let start = Instant::now();
            let overlay = finished.into_overlay();
            let seal = start.elapsed();
            assert_eq!(overlay.root().into_inner(), root);
            self.chain.push_front(overlay);
            (Some(seal), None)
        };
        self.tip_root = root;

        BlockTimes {
            begin,
            access,
            finish,
            seal,
            commit,
        }
    }

    /// Commits what is left of the chain and checks the database against the model, before and
    /// after reopening it. Returns the final root.
    fn verify_durable(mut self) -> Node {
        while let Some(oldest) = self.chain.pop_back() {
            let root = oldest.root();
            oldest.commit(&self.nomt).unwrap();
            assert_eq!(self.nomt.root(), root, "root after committing an overlay");
        }
        assert_eq!(self.tip_root, self.model.root(), "root of the last block");

        let absent: Vec<_> = (0..8).map(|i| key(self.id, self.next_key + i)).collect();
        self.model
            .check_committed(&self.nomt, &absent, "after the final commit");

        let Ok(nomt) = Arc::try_unwrap(self.nomt) else {
            panic!("a commit thread still holds the database")
        };
        drop(nomt);
        let nomt = open(
            &self.dir.path().join("db"),
            self.rollback,
            self.commit_concurrency,
            self.warm_up,
        );
        self.model
            .check_committed(&nomt, &absent, "after reopening");
        self.tip_root
    }
}

/// Runs the workload, printing its timings, and returns the final root of each database.
fn run_blocks(scenario: &'static str, w: Workload) -> Vec<Node> {
    let mut rec = Recorder::new(scenario);
    let mut dbs: Vec<_> = (0..w.dbs as u64)
        .map(|id| ChainedDb::open(id, &w))
        .collect();

    for iter in 0..w.iters {
        // Finality: the oldest overlay of each full chain is committed.
        let mut commits = Vec::new();
        for db in &mut dbs {
            if let Some(commit) = db.full_chain_commit(&w) {
                match w.commit {
                    Commit::Inline => rec.record("commit", commit()),
                    Commit::Thread => commits.push(std::thread::spawn(commit)),
                }
            }
        }
        for db in &mut dbs {
            rec.record_block(&db.block(iter, &w));
        }
        for commit in commits {
            rec.record("commit", commit.join().unwrap());
        }
    }

    dbs.into_iter().map(ChainedDb::verify_durable).collect()
}

// ---------------------------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------------------------

/// The same blocks end at the same root however they are chained, committed and parallelized.
#[test]
fn blocks_agree_across_configurations() {
    serial("blocks_agree_across_configurations", || {
        let base = Workload {
            iters: scaled(16),
            ..SMALL
        };
        let variants: [(&'static str, Workload); 10] = [
            ("small", base),
            ("small_direct", Workload { chain: 0, ..base }),
            ("small_chain1", Workload { chain: 1, ..base }),
            ("small_chain50", Workload { chain: 50, ..base }),
            (
                "small_cc8",
                Workload {
                    commit_concurrency: Some(8),
                    ..base
                },
            ),
            (
                "small_cc64",
                Workload {
                    commit_concurrency: Some(64),
                    ..base
                },
            ),
            (
                "small_witness",
                Workload {
                    witness: true,
                    ..base
                },
            ),
            (
                "small_no_rollback",
                Workload {
                    rollback: false,
                    ..base
                },
            ),
            (
                "small_warm_up",
                Workload {
                    warm_up: true,
                    ..base
                },
            ),
            (
                "small_commit_thread",
                Workload {
                    commit: Commit::Thread,
                    ..base
                },
            ),
        ];

        let mut roots = Vec::new();
        for (name, workload) in variants {
            roots.push((name, run_blocks(name, workload)[0]));
        }
        for (name, root) in &roots {
            assert_eq!(*root, roots[0].1, "{name} ends at a different root");
        }
    });
}

/// Sessions that read and write nothing leave the root alone.
#[test]
fn empty_blocks() {
    serial("empty_blocks", || {
        let workload = Workload {
            prefill: 100,
            writes: 0,
            reads: 0,
            iters: scaled(8),
            ..SMALL
        };
        let before = ChainedDb::open(0, &workload).tip_root;
        assert_eq!(run_blocks("empty", workload), [before]);
        let direct = Workload {
            chain: 0,
            ..workload
        };
        assert_eq!(run_blocks("empty_direct", direct), [before]);
    });
}

#[test]
fn medium_blocks_with_witness() {
    serial("medium_blocks_with_witness", || {
        run_blocks(
            "medium_witness_cc8",
            Workload {
                writes: 2_000,
                reads: 2_000,
                chain: 2,
                witness: true,
                commit_concurrency: Some(8),
                iters: scaled(4),
                ..SMALL
            },
        );
    });
}

#[test]
fn large_blocks_committed_directly() {
    serial("large_blocks_committed_directly", || {
        run_blocks(
            "large_direct",
            Workload {
                writes: sized(4_000, 20_000),
                reads: 0,
                chain: 0,
                iters: scaled(3),
                ..SMALL
            },
        );
    });
}

#[test]
fn small_blocks_on_a_populated_database() {
    serial("small_blocks_on_a_populated_database", || {
        run_blocks(
            "small_prefilled",
            Workload {
                prefill: sized(10_000, 100_000),
                iters: scaled(12),
                ..SMALL
            },
        );
    });
}

/// Two databases whose oldest overlays are committed on other threads while the next block's
/// sessions open.
#[test]
fn two_databases_committing_on_other_threads() {
    serial("two_databases_committing_on_other_threads", || {
        run_blocks(
            "two_dbs_commit_thread",
            Workload {
                dbs: 2,
                commit: Commit::Thread,
                iters: scaled(12),
                ..SMALL
            },
        );
    });
}

/// A session that is opened, warmed up and dropped changes nothing.
#[test]
fn dropped_sessions() {
    serial("dropped_sessions", || {
        let mut rec = Recorder::new("session_drop");
        let db = ChainedDb::open(
            0,
            &Workload {
                prefill: 1_000,
                ..SMALL
            },
        );

        for iter in 0..scaled(100) {
            let session = rec.time("begin", || db.nomt.begin_session(SessionParams::default()));
            rec.time("warm_up", || {
                for i in 0..20 {
                    session.warm_up(key(0, (iter * 31 + i) % 1_000));
                    session.preserve_prior_value(key(0, (iter * 17 + i) % 1_000));
                }
            });
            rec.time("drop", || drop(session));
            assert_eq!(db.nomt.root().into_inner(), db.tip_root);
        }
        db.verify_durable();
    });
}

/// Reads and proofs through a session agree with the model.
#[test]
fn session_reads_and_proofs() {
    serial("session_reads_and_proofs", || {
        let mut rec = Recorder::new("session_reads");
        let db = ChainedDb::open(
            0,
            &Workload {
                prefill: 5_000,
                ..SMALL
            },
        );

        for iter in 0..scaled(20) {
            let session = db.nomt.begin_session(SessionParams::default());
            // Half of the keys exist.
            let keys = |n: u64, stride: u64| {
                (0..n).map(move |i| key(0, (iter * 31 + i * stride) % 10_000))
            };

            let values = rec.time("read_x200", || {
                keys(200, 7919)
                    .map(|k| session.read(k).unwrap())
                    .collect::<Vec<_>>()
            });
            for (k, value) in keys(200, 7919).zip(values) {
                assert_eq!(value.as_ref(), db.model.get(&k), "read");
            }

            let proofs = rec.time("prove_x20", || {
                keys(20, 104_729)
                    .map(|k| session.prove(k).unwrap())
                    .collect::<Vec<_>>()
            });
            for (k, path_proof) in keys(20, 104_729).zip(proofs) {
                let verified = path_proof
                    .verify::<Sha2Hasher>(k.view_bits::<Msb0>(), db.tip_root)
                    .expect("proof verifies against the root");
                match db.model.hash(&k) {
                    None => assert!(verified.confirm_nonexistence(&k).unwrap()),
                    Some(value_hash) => {
                        let leaf = LeafData {
                            key_path: k,
                            value_hash,
                        };
                        assert!(verified.confirm_value(&leaf).unwrap());
                    }
                }
            }
        }
        db.verify_durable();
    });
}

/// A rollback restores the root and the values of the commit it undoes.
#[test]
fn commit_then_rollback() {
    serial("commit_then_rollback", || {
        let mut rec = Recorder::new("commit_then_rollback");
        let db = ChainedDb::open(
            0,
            &Workload {
                prefill: 1_000,
                ..SMALL
            },
        );

        for iter in 0..scaled(8) {
            // Rewrites, fresh keys and deletions.
            let mut actuals: Vec<_> = (0..30)
                .map(|i| {
                    let k = key(0, (iter * 31 + i * 97) % 2_000);
                    let value = (i % 3 != 0).then(|| iter.to_le_bytes().to_vec());
                    (k, KeyReadWrite::Write(value))
                })
                .collect();
            actuals.sort_by(|a, b| a.0.cmp(&b.0));
            actuals.dedup_by(|a, b| a.0 == b.0);
            let touched: Vec<_> = actuals.iter().map(|(k, _)| *k).collect();

            let finished = db
                .nomt
                .begin_session(SessionParams::default())
                .finish(actuals)
                .unwrap();
            let committed_root = finished.root();
            assert_ne!(committed_root.into_inner(), db.tip_root);
            rec.time("commit", || finished.commit(&db.nomt).unwrap());
            assert_eq!(db.nomt.root(), committed_root);

            rec.time("rollback", || db.nomt.rollback(1).unwrap());
            assert_eq!(
                db.nomt.root().into_inner(),
                db.tip_root,
                "root after rollback"
            );
            let session = db.nomt.begin_session(SessionParams::default());
            for k in touched {
                let read = session.read(k).unwrap();
                assert_eq!(read.as_ref(), db.model.get(&k), "value after rollback");
            }
        }
        db.verify_durable();
    });
}

/// Reopening a populated database, timed. `verify_durable` checks the contents.
#[test]
fn reopen() {
    serial("reopen", || {
        let mut rec = Recorder::new("reopen");
        let workload = Workload {
            prefill: sized(10_000, 100_000),
            ..SMALL
        };
        let mut db = ChainedDb::open(0, &workload);
        for _ in 0..scaled(3) {
            let Ok(nomt) = Arc::try_unwrap(db.nomt) else {
                unreachable!()
            };
            rec.time("close", || drop(nomt));
            let nomt = rec.time("open", || {
                open(&db.dir.path().join("db"), true, None, false)
            });
            assert_eq!(nomt.root().into_inner(), db.tip_root);
            db.nomt = Arc::new(nomt);
        }
        db.verify_durable();
    });
}

// ---------------------------------------------------------------------------------------------
// Slowdown guards
// ---------------------------------------------------------------------------------------------

/// `measured` may take up to `factor` times `base`, plus `floor` for timer and scheduling noise.
struct Limit {
    factor: f64,
    floor: Duration,
}

/// Fails if `measured` is over the limit in each of three attempts. An attempt returns the
/// samples of the base and of the measured configuration; their medians are compared.
fn guard(name: &str, limit: Limit, mut attempt: impl FnMut() -> (Vec<Duration>, Vec<Duration>)) {
    let mut failures = String::new();
    for i in 1..=3 {
        let (base, measured) = attempt();
        let allowed = median(&base).mul_f64(limit.factor) + limit.floor;
        let quartiles = |samples: &[Duration]| {
            format!(
                "{:.1?}/{:.1?}/{:.1?}",
                quantile(samples, 25),
                median(samples),
                quantile(samples, 75)
            )
        };
        let line = format!(
            "GUARD {name} attempt {i}: ratio={:.3} (limit {} + {:?}), base p25/p50/p75={} n={}, \
             measured={} n={}, allowed={allowed:.1?}",
            median(&measured).as_secs_f64() / median(&base).as_secs_f64().max(1e-9),
            limit.factor,
            limit.floor,
            quartiles(&base),
            base.len(),
            quartiles(&measured),
            measured.len(),
        );
        println!("{line}");
        if median(&measured) <= allowed {
            return;
        }
        failures.push_str(&line);
        failures.push('\n');
    }
    panic!("slowdown guard `{name}` was over its limit in 3 attempts:\n{failures}");
}

/// Guards the block time of workload `b` against workload `a`, on two databases fed the same
/// blocks in turn. Commits of full chains are not timed.
fn guard_blocks(name: &str, limit: Limit, a: Workload, b: Workload, warm_up: (u64, u64)) {
    guard(name, limit, || {
        let mut db_a = ChainedDb::open(0, &a);
        let mut db_b = ChainedDb::open(0, &b);
        let step = |db: &mut ChainedDb, w: &Workload, iter: u64| {
            if let Some(commit) = db.full_chain_commit(w) {
                commit();
            }
            db.block(iter, w).total()
        };
        for iter in 0..warm_up.0 {
            step(&mut db_a, &a, iter);
        }
        for iter in 0..warm_up.1 {
            step(&mut db_b, &b, iter);
        }
        let (mut base, mut measured) = (Vec::new(), Vec::new());
        for round in 0..scaled(30) {
            base.push(step(&mut db_a, &a, warm_up.0 + round));
            measured.push(step(&mut db_b, &b, warm_up.1 + round));
        }
        (base, measured)
    });
}

/// G1. A session's fixed cost is a small fraction of the cost of a session that does real work.
///
/// This is the guard for 12435fe: with 64 update tasks per session, each computing its key range
/// bit by bit, `finish` of an empty session cost several milliseconds in unoptimized builds.
#[test]
fn guard_fixed_session_cost() {
    serial("guard_fixed_session_cost", || {
        let limit = Limit {
            factor: FIXED_COST_FRACTION,
            floor: Duration::from_micros(100),
        };
        guard("fixed_session_cost", limit, || {
            let mut db = ChainedDb::open(0, &UNBOUNDED);
            let work = Workload {
                writes: 2_000,
                reads: 0,
                ..UNBOUNDED
            };
            let empty = Workload {
                writes: 0,
                reads: 0,
                ..UNBOUNDED
            };
            let (mut base, mut measured) = (Vec::new(), Vec::new());
            for round in 0..scaled(12) {
                base.push(db.block(round, &work).finish);
                measured.push(db.block(round, &empty).finish);
            }
            (base, measured)
        });
    });
}

/// G4. Ten times the writes cost about ten times as much, not a hundred.
#[test]
fn guard_linear_scaling() {
    serial("guard_linear_scaling", || {
        let limit = Limit {
            factor: 10.0 * SCALING_SLACK,
            floor: Duration::from_micros(500),
        };
        guard("linear_scaling", limit, || {
            let mut db = ChainedDb::open(
                0,
                &Workload {
                    prefill: 5_000,
                    ..UNBOUNDED
                },
            );
            let size = |writes| Workload {
                writes,
                reads: 0,
                ..UNBOUNDED
            };
            let (mut base, mut measured) = (Vec::new(), Vec::new());
            for round in 0..scaled(12) {
                base.push(db.block(round, &size(200)).finish);
                measured.push(db.block(round, &size(2_000)).finish);
            }
            (base, measured)
        });
    });
}

/// G2. More commit workers do not make a small block slower.
#[test]
fn guard_commit_concurrency() {
    serial("guard_commit_concurrency", || {
        let with = |commit_concurrency| Workload {
            commit_concurrency: Some(commit_concurrency),
            ..UNBOUNDED
        };
        for workers in [8, 64] {
            let limit = Limit {
                factor: CONCURRENCY_FACTOR,
                floor: Duration::from_micros(200),
            };
            guard_blocks(
                &format!("commit_concurrency_{workers}"),
                limit,
                with(1),
                with(workers),
                (5, 5),
            );
        }
    });
}

/// G3. A session on a deep overlay chain costs about as much as one on a shallow chain.
#[test]
fn guard_chain_depth() {
    serial("guard_chain_depth", || {
        // Both databases start populated, so the 49 extra warm-up blocks of the deep one barely
        // change the size of its trie.
        let shallow = Workload {
            prefill: 2_000,
            chain: 1,
            ..SMALL
        };
        let deep = Workload {
            prefill: 2_000,
            ..UNBOUNDED
        };
        let limit = Limit {
            factor: CHAIN_DEPTH_FACTOR,
            floor: Duration::from_micros(200),
        };
        guard_blocks("chain_depth_50", limit, shallow, deep, (1, 50));
    });
}

/// G5. Collecting a witness costs a bounded multiple of the session without one.
#[test]
fn guard_witness_overhead() {
    serial("guard_witness_overhead", || {
        let witness = Workload {
            witness: true,
            ..UNBOUNDED
        };
        let limit = Limit {
            factor: WITNESS_FACTOR,
            floor: Duration::from_micros(200),
        };
        guard_blocks("witness_overhead", limit, UNBOUNDED, witness, (5, 5));
    });
}

/// G6. Recording a rollback delta costs a bounded multiple of the session without one.
#[test]
fn guard_rollback_overhead() {
    serial("guard_rollback_overhead", || {
        let no_rollback = Workload {
            rollback: false,
            ..UNBOUNDED
        };
        let limit = Limit {
            factor: ROLLBACK_FACTOR,
            floor: Duration::from_micros(200),
        };
        guard_blocks("rollback_overhead", limit, no_rollback, UNBOUNDED, (5, 5));
    });
}

/// G11. Warming up the keys of a small session costs a bounded multiple of not doing so.
#[test]
fn guard_warm_up_overhead() {
    serial("guard_warm_up_overhead", || {
        let warm_up = Workload {
            warm_up: true,
            ..UNBOUNDED
        };
        let limit = Limit {
            factor: WARM_UP_FACTOR,
            floor: Duration::from_micros(200),
        };
        guard_blocks("warm_up_overhead", limit, UNBOUNDED, warm_up, (5, 5));
    });
}

/// Background threads that repeat a piece of work while switched on.
struct Background {
    on: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    /// Pieces of work started, over all threads.
    started: Arc<AtomicU64>,
    idle: Arc<Vec<AtomicBool>>,
    threads: Vec<JoinHandle<()>>,
}

impl Background {
    /// One thread per element of `work`, initially off.
    fn spawn<F: FnMut() + Send + 'static>(work: Vec<F>) -> Self {
        let on = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicU64::new(0));
        let idle = Arc::new(
            (0..work.len())
                .map(|_| AtomicBool::new(false))
                .collect::<Vec<_>>(),
        );
        let threads = work
            .into_iter()
            .enumerate()
            .map(|(i, mut work)| {
                let (on, stop, started, idle) =
                    (on.clone(), stop.clone(), started.clone(), idle.clone());
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        if on.load(Ordering::Relaxed) {
                            idle[i].store(false, Ordering::Relaxed);
                            started.fetch_add(1, Ordering::Relaxed);
                            work();
                        } else {
                            idle[i].store(true, Ordering::Relaxed);
                            std::thread::sleep(Duration::from_micros(200));
                        }
                    }
                })
            })
            .collect();
        Background {
            on,
            stop,
            started,
            idle,
            threads,
        }
    }

    /// Switches the work on or off and waits until every thread has followed.
    fn switch(&self, on: bool) {
        let started = self.started.load(Ordering::Relaxed);
        self.on.store(on, Ordering::Relaxed);
        let followed = || {
            if on {
                self.started.load(Ordering::Relaxed) >= started + 2 * self.threads.len() as u64
            } else {
                self.idle.iter().all(|idle| idle.load(Ordering::Relaxed))
            }
        };
        while !followed() {
            std::thread::sleep(Duration::from_micros(100));
        }
    }

    fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads {
            thread.join().unwrap();
        }
    }
}

/// Twenty writes to existing keys of a database prefilled with `keys` keys, sorted.
fn rewrites(db: u64, seed: u64, keys: u64) -> Vec<(KeyPath, KeyReadWrite)> {
    let mut actuals: Vec<_> = (0..20)
        .map(|i| {
            let k = key(db, (seed * 31 + i * 7919) % keys);
            (k, KeyReadWrite::Write(Some(seed.to_le_bytes().to_vec())))
        })
        .collect();
    actuals.sort_by(|a, b| a.0.cmp(&b.0));
    actuals.dedup_by(|a, b| a.0 == b.0);
    actuals
}

/// G7. Commits to one database do not slow sessions on another.
#[test]
fn guard_cross_database_isolation() {
    serial("guard_cross_database_isolation", || {
        let limit = Limit {
            factor: ISOLATION_FACTOR,
            floor: Duration::from_micros(300),
        };
        guard("cross_database_isolation", limit, || {
            let mut x = ChainedDb::open(0, &UNBOUNDED);
            let y = ChainedDb::open(
                1,
                &Workload {
                    prefill: 1_000,
                    ..SMALL
                },
            );
            let committer = Background::spawn(vec![{
                let y = y.nomt.clone();
                let mut seed = 0;
                move || {
                    seed += 1;
                    y.begin_session(SessionParams::default())
                        .finish(rewrites(1, seed, 1_000))
                        .unwrap()
                        .commit(&y)
                        .unwrap();
                }
            }]);

            let (mut base, mut measured) = (Vec::new(), Vec::new());
            let mut iter = 0;
            for _ in 0..scaled(6) {
                for (on, samples) in [(false, &mut base), (true, &mut measured)] {
                    committer.switch(on);
                    for _ in 0..5 {
                        samples.push(x.block(iter, &UNBOUNDED).total());
                        iter += 1;
                    }
                }
            }
            committer.stop();
            (base, measured)
        });
    });
}

/// G8. A commit is not held off by threads that open one short session after another on its
/// database while each also holds a session on a second database.
///
/// The commit has to wait for the sessions that are open when it starts, and no longer: sessions
/// that begin after it must queue behind it.
#[test]
fn guard_commit_not_starved() {
    serial("guard_commit_not_starved", || {
        let limit = Limit {
            factor: STARVATION_FACTOR,
            floor: Duration::from_millis(5),
        };
        guard("commit_not_starved", limit, || {
            let populated = Workload {
                prefill: 1_000,
                ..SMALL
            };
            let target = ChainedDb::open(0, &populated);
            let other = ChainedDb::open(1, &populated);

            // The readers give way after `GIVE_WAY`, so that a starved commit shows up as a
            // sample of that size instead of hanging the test.
            const GIVE_WAY: Duration = Duration::from_secs(2);
            let epoch = Instant::now();
            let give_way_at_ms = Arc::new(AtomicU64::new(0));
            let reader = |n: u64| {
                let (target, other) = (target.nomt.clone(), other.nomt.clone());
                let give_way_at_ms = give_way_at_ms.clone();
                let mut held: Option<Session<Sha2Hasher>> = None;
                move || {
                    if epoch.elapsed().as_millis() as u64 >= give_way_at_ms.load(Ordering::Relaxed)
                    {
                        std::thread::sleep(Duration::from_micros(200));
                        return;
                    }
                    // Held for as long as the thread lives, and created on it.
                    held.get_or_insert_with(|| other.begin_session(SessionParams::default()));
                    let session = target.begin_session(SessionParams::default());
                    let start = Instant::now();
                    let mut i = n;
                    while start.elapsed() < Duration::from_micros(300) {
                        session.read(key(0, i % 1_000)).unwrap();
                        i += 1;
                    }
                }
            };
            let readers = Background::spawn(vec![reader(0), reader(500)]);

            let (mut base, mut measured) = (Vec::new(), Vec::new());
            let mut seed = 0;
            for _ in 0..scaled(5) {
                for (on, samples) in [(false, &mut base), (true, &mut measured)] {
                    seed += 1;
                    let finished = target
                        .nomt
                        .begin_session(SessionParams::default())
                        .finish(rewrites(0, seed, 1_000))
                        .unwrap();
                    let root = finished.root();
                    let give_way = epoch.elapsed() + GIVE_WAY;
                    give_way_at_ms.store(give_way.as_millis() as u64, Ordering::Relaxed);
                    readers.switch(on);
                    let start = Instant::now();
                    finished.commit(&target.nomt).unwrap();
                    samples.push(start.elapsed());
                    assert_eq!(target.nomt.root(), root);
                    readers.switch(false);
                }
            }
            readers.stop();
            (base, measured)
        });
    });
}

/// A session on the committed state of `db` that overwrites twenty keys and is sealed into an
/// overlay, which is checked against the model and dropped. Returns how long the session took.
fn forked_session(nomt: &Db, model: &Model, seed: u64) -> Duration {
    let actuals = rewrites(0, seed, model.values.len() as u64);
    // Building the expected trie costs far more than the session; check one root in eight.
    let expected_root = (seed % 8 == 0).then(|| model.root_with(&actuals));

    let start = Instant::now();
    let session = nomt.begin_session(SessionParams::default());
    let mut reads = Vec::with_capacity(actuals.len());
    for (k, _) in &actuals {
        session.warm_up(*k);
        reads.push(session.read(*k).unwrap());
    }
    let finished = session.finish(actuals.clone()).unwrap();
    let overlay = finished.into_overlay();
    let elapsed = start.elapsed();

    for ((k, _), read) in actuals.iter().zip(reads) {
        assert_eq!(read.as_ref(), model.get(k), "read");
    }
    if let Some(expected_root) = expected_root {
        assert_eq!(overlay.root().into_inner(), expected_root, "root of a fork");
    }
    elapsed
}

/// A populated database, with warm-up enabled, to run forked sessions against.
fn fork_base() -> (Arc<Db>, Arc<Model>, tempfile::TempDir) {
    let db = ChainedDb::open(
        0,
        &Workload {
            prefill: 2_000,
            warm_up: true,
            ..SMALL
        },
    );
    (db.nomt, Arc::new(db.model), db.dir)
}

/// Sessions running on four threads at once all produce the right overlays, and don't deadlock.
///
/// Timings are printed but not guarded: with every session also running a warm-up and a rollback
/// thread, four of them share the cores, and each takes about three times as long as alone.
/// That is too close to the four times of sessions that fully serialize to tell them apart.
#[test]
fn sessions_on_four_threads() {
    serial("sessions_on_four_threads", || {
        let mut rec = Recorder::new("sessions_on_four_threads");
        let (nomt, model, _dir) = fork_base();
        let per_thread = scaled(20);
        for seed in 0..per_thread {
            rec.record("alone", forked_session(&nomt, &model, seed));
        }
        let barrier = Arc::new(Barrier::new(4));
        let threads: Vec<_> = (0..4)
            .map(|t| {
                let (nomt, model, barrier) = (nomt.clone(), model.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    (0..per_thread)
                        .map(|i| forked_session(&nomt, &model, 1_000 + t * 100 + i))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for thread in threads {
            for sample in thread.join().unwrap() {
                rec.record("one_of_four", sample);
            }
        }
    });
}

/// G9. Sessions that are open and idle on other threads do not slow a session down.
///
/// This is the guard for the bug d8d55e8 fixed: each session's warm-up occupied a commit worker
/// until the session finished, so a session waited for the idle ones ahead of it.
#[test]
fn guard_idle_sessions() {
    serial("guard_idle_sessions", || {
        const HOLDERS: u64 = 3;
        let limit = Limit {
            factor: IDLE_SESSIONS_FACTOR,
            floor: Duration::from_micros(300),
        };
        guard("idle_sessions", limit, || {
            let (nomt, model, _dir) = fork_base();

            // Holders give way after `GIVE_WAY`, so that a session blocked by them shows up as a
            // sample of that size instead of hanging the test.
            const GIVE_WAY: Duration = Duration::from_secs(2);
            let hold = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let holding = Arc::new(AtomicU64::new(0));
            let holders: Vec<_> = (0..HOLDERS)
                .map(|h| {
                    let nomt = nomt.clone();
                    let (hold, stop, holding) = (hold.clone(), stop.clone(), holding.clone());
                    std::thread::spawn(move || {
                        while !stop.load(Ordering::Relaxed) {
                            if !hold.load(Ordering::Relaxed) {
                                std::thread::sleep(Duration::from_micros(200));
                                continue;
                            }
                            let session = nomt.begin_session(SessionParams::default());
                            for i in 0..20 {
                                session.warm_up(key(0, h * 100 + i));
                            }
                            holding.fetch_add(1, Ordering::Relaxed);
                            let start = Instant::now();
                            while hold.load(Ordering::Relaxed) && start.elapsed() < GIVE_WAY {
                                std::thread::sleep(Duration::from_micros(100));
                            }
                            holding.fetch_sub(1, Ordering::Relaxed);
                            drop(session);
                        }
                    })
                })
                .collect();

            let (mut base, mut measured) = (Vec::new(), Vec::new());
            let mut seed = 0;
            for _ in 0..4 {
                for (on, samples) in [(false, &mut base), (true, &mut measured)] {
                    hold.store(on, Ordering::Relaxed);
                    let target = if on { HOLDERS } else { 0 };
                    while holding.load(Ordering::Relaxed) != target {
                        std::thread::sleep(Duration::from_micros(100));
                    }
                    for _ in 0..scaled(8) {
                        samples.push(forked_session(&nomt, &model, seed));
                        seed += 1;
                    }
                }
            }
            hold.store(false, Ordering::Relaxed);
            stop.store(true, Ordering::Relaxed);
            for holder in holders {
                holder.join().unwrap();
            }
            (base, measured)
        });
    });
}

/// G10. A session costs about as much after hundreds of sessions as at the start.
#[test]
fn guard_no_drift() {
    serial("guard_no_drift", || {
        let limit = Limit {
            factor: DRIFT_FACTOR,
            floor: Duration::from_micros(100),
        };
        // Every attempt is compared with the start of the first one: a cost that accumulates in
        // the process, not in the database, would make a later attempt slow from its start.
        let mut first_start = None;
        guard("no_drift", limit, || {
            let (nomt, model, _dir) = fork_base();
            let samples: Vec<_> = (0..scaled(400))
                .map(|seed| forked_session(&nomt, &model, seed))
                .collect();
            let quarter = samples.len() / 4;
            let start = first_start.get_or_insert_with(|| samples[..quarter].to_vec());
            (start.clone(), samples[samples.len() - quarter..].to_vec())
        });
    });
}

// Limits.
//
// Each is set from the ratios observed over 20 runs per profile (optimized, unoptimized and
// coverage-instrumented) on a machine busy with other work, quoted as `min..max`, and from what
// the regression it is meant for looks like.

/// Observed 0.003..0.030. Before the fix of 12435fe: 0.06..0.07 unoptimized, 0.17..0.18 with
/// coverage instrumentation.
const FIXED_COST_FRACTION: f64 = 0.04;
/// Observed 5.8..7.7 for ten times the writes, i.e. 0.58..0.77 of proportional.
const SCALING_SLACK: f64 = 1.5;
/// Observed 0.79..1.06.
const CONCURRENCY_FACTOR: f64 = 2.0;
/// Observed 0.85..1.04.
const CHAIN_DEPTH_FACTOR: f64 = 2.0;
/// Observed 1.07..1.35.
const WITNESS_FACTOR: f64 = 2.5;
/// Observed 0.99..1.28.
const ROLLBACK_FACTOR: f64 = 2.5;
/// Observed 0.95..1.52.
const ISOLATION_FACTOR: f64 = 3.0;
/// Observed 0.86..1.20. With sessions counted per thread instead of per thread and database
/// (0e2dd95): 2.8..24.
const STARVATION_FACTOR: f64 = 2.5;
/// Observed 0.93..1.13. With the warm-up on a commit worker (before d8d55e8) the session waits
/// for the idle ones to end.
const IDLE_SESSIONS_FACTOR: f64 = 2.0;
/// Observed 0.88..1.14.
const WARM_UP_FACTOR: f64 = 2.0;
/// Observed 0.88..1.22.
const DRIFT_FACTOR: f64 = 2.0;
