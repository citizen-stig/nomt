//! Block workloads checked against a model.
//!
//! Each workload runs a stream of blocks the way a chain node does: a session per block on top of
//! a chain of uncommitted overlays, reads, `finish`, `into_overlay`, and a commit of the oldest
//! overlay once the chain is full, on the same thread or on another one.
//!
//! A model of the expected state is kept next to each database and checked on every block: reads
//! against the model (including values only in uncommitted overlays), every root against a trie
//! built independently from the model, the chaining of previous roots, and witnesses. At the end
//! the rest of the chain is committed and the database is checked against the model, before and
//! after reopening it.

use nomt::{
    hasher::{Sha2Hasher, ValueHasher},
    proof,
    trie::{KeyPath, LeafData, Node, ValueHash},
    InvalidAncestors, KeyReadWrite, Nomt, Options, Overlay, SessionParams, Witness, WitnessMode,
};
use std::{
    collections::{BTreeMap, VecDeque},
    path::Path,
    sync::{mpsc, Arc, Barrier},
    time::Duration,
};

type Db = Nomt<Sha2Hasher>;

/// Runs `body` and fails, rather than hangs, if it does not return.
fn with_watchdog(name: &'static str, body: impl FnOnce() + Send + 'static) {
    const LIMIT: Duration = Duration::from_secs(300);
    let (done_tx, done_rx) = mpsc::channel();
    let thread = std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            body();
            let _ = done_tx.send(());
        })
        .unwrap();
    match done_rx.recv_timeout(LIMIT) {
        Ok(()) => thread.join().unwrap(),
        // The body panicked.
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            std::panic::resume_unwind(thread.join().unwrap_err())
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("{name}: still running after {LIMIT:?}: hang or deadlock")
        }
    }
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

    /// If the chain is full, returns the commit of its oldest overlay.
    fn full_chain_commit(&mut self, w: &Workload) -> Option<impl FnOnce() + Send> {
        if w.chain == 0 || self.chain.len() < w.chain {
            return None;
        }
        let oldest = self.chain.pop_back().unwrap();
        let nomt = self.nomt.clone();
        Some(move || {
            let root = oldest.root();
            oldest.commit(&nomt).unwrap();
            assert_eq!(nomt.root(), root, "root after committing an overlay");
        })
    }

    /// One block on top of the chain. `iter` selects the keys and the written value.
    fn block(&mut self, iter: u64, w: &Workload) {
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

        assert_eq!(
            session.prev_root().into_inner(),
            self.tip_root,
            "a session starts from the root of the newest overlay"
        );

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

        let mut finished = session.finish(actuals).unwrap();

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

        if w.chain == 0 {
            finished.commit(&self.nomt).unwrap();
            assert_eq!(self.nomt.root().into_inner(), root, "root after a commit");
        } else {
            let overlay = finished.into_overlay();
            assert_eq!(overlay.root().into_inner(), root);
            self.chain.push_front(overlay);
        }
        self.tip_root = root;
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

/// Runs the workload and returns the final root of each database.
fn run_blocks(w: Workload) -> Vec<Node> {
    let mut dbs: Vec<_> = (0..w.dbs as u64)
        .map(|id| ChainedDb::open(id, &w))
        .collect();

    for iter in 0..w.iters {
        // Finality: the oldest overlay of each full chain is committed.
        let mut commits = Vec::new();
        for db in &mut dbs {
            if let Some(commit) = db.full_chain_commit(&w) {
                match w.commit {
                    Commit::Inline => commit(),
                    Commit::Thread => commits.push(std::thread::spawn(commit)),
                }
            }
        }
        for db in &mut dbs {
            db.block(iter, &w);
        }
        for commit in commits {
            commit.join().unwrap();
        }
    }

    dbs.into_iter().map(ChainedDb::verify_durable).collect()
}
/// The same blocks end at the same root however they are chained, committed and parallelized.
#[test]
fn blocks_agree_across_configurations() {
    with_watchdog("blocks_agree_across_configurations", || {
        let base = Workload { iters: 16, ..SMALL };
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
            roots.push((name, run_blocks(workload)[0]));
        }
        for (name, root) in &roots {
            assert_eq!(*root, roots[0].1, "{name} ends at a different root");
        }
    });
}

/// Sessions that read and write nothing leave the root alone.
#[test]
fn empty_blocks() {
    with_watchdog("empty_blocks", || {
        let workload = Workload {
            prefill: 100,
            writes: 0,
            reads: 0,
            iters: 8,
            ..SMALL
        };
        let before = ChainedDb::open(0, &workload).tip_root;
        assert_eq!(run_blocks(workload), [before]);
        let direct = Workload {
            chain: 0,
            ..workload
        };
        assert_eq!(run_blocks(direct), [before]);
    });
}

#[test]
fn medium_blocks_with_witness() {
    with_watchdog("medium_blocks_with_witness", || {
        run_blocks(Workload {
            writes: 2_000,
            reads: 2_000,
            chain: 2,
            witness: true,
            commit_concurrency: Some(8),
            iters: 4,
            ..SMALL
        });
    });
}

#[test]
fn large_blocks_committed_directly() {
    with_watchdog("large_blocks_committed_directly", || {
        run_blocks(Workload {
            writes: 4_000,
            reads: 0,
            chain: 0,
            iters: 3,
            ..SMALL
        });
    });
}

#[test]
fn small_blocks_on_a_populated_database() {
    with_watchdog("small_blocks_on_a_populated_database", || {
        run_blocks(Workload {
            prefill: 10_000,
            iters: 12,
            ..SMALL
        });
    });
}

/// Two databases whose oldest overlays are committed on other threads while the next block's
/// sessions open.
#[test]
fn two_databases_committing_on_other_threads() {
    with_watchdog("two_databases_committing_on_other_threads", || {
        run_blocks(Workload {
            dbs: 2,
            commit: Commit::Thread,
            iters: 12,
            ..SMALL
        });
    });
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

/// A session on the committed state that overwrites twenty keys and is sealed into an overlay,
/// which is checked against the model and dropped.
fn forked_session(nomt: &Db, model: &Model, seed: u64) {
    let actuals = rewrites(0, seed, model.values.len() as u64);
    // Building the expected trie costs far more than the session; check one root in eight.
    let expected_root = (seed % 8 == 0).then(|| model.root_with(&actuals));

    let session = nomt.begin_session(SessionParams::default());
    let mut reads = Vec::with_capacity(actuals.len());
    for (k, _) in &actuals {
        session.warm_up(*k);
        reads.push(session.read(*k).unwrap());
    }
    let overlay = session.finish(actuals.clone()).unwrap().into_overlay();

    for ((k, _), read) in actuals.iter().zip(reads) {
        assert_eq!(read.as_ref(), model.get(k), "read");
    }
    if let Some(expected_root) = expected_root {
        assert_eq!(overlay.root().into_inner(), expected_root, "root of a fork");
    }
}

/// Sessions running on four threads at once, each with a warm-up and a rollback thread, all read
/// the committed state and produce the right overlays, and don't deadlock.
#[test]
fn sessions_on_four_threads() {
    with_watchdog("sessions_on_four_threads", || {
        let db = ChainedDb::open(
            0,
            &Workload {
                prefill: 2_000,
                warm_up: true,
                ..SMALL
            },
        );
        let (nomt, model) = (db.nomt.clone(), Arc::new(db.model));
        let barrier = Arc::new(Barrier::new(4));
        let threads: Vec<_> = (0..4)
            .map(|t| {
                let (nomt, model, barrier) = (nomt.clone(), model.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    for i in 0..20 {
                        forked_session(&nomt, &model, t * 100 + i);
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(
            nomt.root().into_inner(),
            db.tip_root,
            "nothing was committed"
        );
    });
}
