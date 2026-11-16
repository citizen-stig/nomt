//! Isolated benchmark of `Session::finish` with the access profile of a Sovereign SDK node.
//!
//! See `docs/sov-finalization-under-100-ms.md`, section "Input spec for an isolated
//! `session.finish` benchmark".
//!
//! `finish_bench seed <db> <state>` builds the tree from genesis until it holds `SEED_LEAVES`
//! leaves and saves the generator state. `finish_bench run <db> <state>` continues from that
//! state for `WARM_UP_SLOTS + MEASURED_SLOTS` slots and prints `finish_*` metrics.

use nomt::{hasher::BinaryHasher, trie::KeyPath, KeyReadWrite, Nomt, Options, SessionParams};
use sha2::{Digest, Sha256};
use std::time::Instant;

type Hasher = BinaryHasher<Sha256>;

const SEED: u64 = 20261116;
const GENESIS_KEYS: u64 = 1054;
const SEED_LEAVES: u64 = 5_320_000;
const WARM_UP_SLOTS: u64 = 10;
const MEASURED_SLOTS: u64 = 20;
const DELETED: u32 = u32::MAX;

fn open(path: &str) -> Nomt<Hasher> {
    let mut opts = Options::new();
    opts.path(path);
    opts.bitbox_seed(SEED.to_le_bytes().repeat(2).try_into().unwrap());
    opts.rollback(true);
    opts.max_rollback_log_len(1);
    opts.commit_concurrency(6);
    opts.hashtable_buckets(64_000_000);
    opts.preallocate_ht(false);
    opts.leaf_cache_size(2048);
    opts.page_cache_upper_levels(3);
    opts.prepopulate_page_cache(true);
    opts.metrics(true);
    Nomt::open(opts).unwrap()
}

struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn key_path(idx: u64) -> KeyPath {
    Sha256::digest(idx.to_le_bytes()).into()
}

/// 36 bytes: a SHA-256 followed by a little-endian u32 length, as the SDK stores values.
fn value(idx: u64, version: u32) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(idx.to_le_bytes());
    h.update(version.to_le_bytes());
    let mut v = h.finalize().to_vec();
    v.extend_from_slice(&8u32.to_le_bytes());
    v
}

/// Generator state: one version per key index ever inserted, `DELETED` for removed keys.
struct State {
    slot: u64,
    live: u64,
    versions: Vec<u32>,
    touched: Vec<u64>,
}

impl State {
    fn save(&self, path: &str) {
        let mut buf = Vec::with_capacity(16 + self.versions.len() * 4);
        buf.extend_from_slice(&self.slot.to_le_bytes());
        buf.extend_from_slice(&self.live.to_le_bytes());
        for v in &self.versions {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        std::fs::write(path, buf).unwrap();
    }

    fn load(path: &str) -> Self {
        let buf = std::fs::read(path).unwrap();
        let slot = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let live = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let versions: Vec<u32> = buf[16..]
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        let touched = vec![u64::MAX; versions.len()];
        State {
            slot,
            live,
            versions,
            touched,
        }
    }

    fn pick_existing(&mut self, rng: &mut SplitMix) -> u64 {
        loop {
            let idx = rng.below(self.versions.len() as u64);
            if self.versions[idx as usize] != DELETED && self.touched[idx as usize] != self.slot {
                self.touched[idx as usize] = self.slot;
                return idx;
            }
        }
    }

    /// The sorted access list for the next slot, applied to the generator state.
    fn next_slot(&mut self) -> Vec<(KeyPath, KeyReadWrite)> {
        self.slot += 1;
        let mut rng = SplitMix(SEED ^ self.slot.wrapping_mul(0x2545f4914f6cdd1d));
        // Consecutive slots alternate between larger and smaller batches, 50k..145k.
        let total = if self.slot % 2 == 0 {
            97_500 + rng.below(47_500)
        } else {
            50_000 + rng.below(47_500)
        };
        let updates = (total * 68 / 100).min(self.live / 2);
        let inserts = total - total * 68 / 100 - 5;

        let mut access = Vec::with_capacity(total as usize);
        for _ in 0..updates {
            let idx = self.pick_existing(&mut rng);
            let v = &mut self.versions[idx as usize];
            let prior = value(idx, *v);
            *v += 1;
            access.push((
                key_path(idx),
                KeyReadWrite::ReadThenWrite(Some(prior), Some(value(idx, *v))),
            ));
        }
        {
            let idx = self.pick_existing(&mut rng);
            let prior = value(idx, self.versions[idx as usize]);
            self.versions[idx as usize] = DELETED;
            self.live -= 1;
            access.push((
                key_path(idx),
                KeyReadWrite::ReadThenWrite(Some(prior), None),
            ));
        }
        for _ in 0..4 {
            let idx = self.pick_existing(&mut rng);
            let v = &mut self.versions[idx as usize];
            *v += 1;
            access.push((key_path(idx), KeyReadWrite::Write(Some(value(idx, *v)))));
        }
        for _ in 0..inserts {
            let idx = self.versions.len() as u64;
            self.versions.push(0);
            self.touched.push(self.slot);
            self.live += 1;
            access.push((
                key_path(idx),
                KeyReadWrite::ReadThenWrite(None, Some(value(idx, 0))),
            ));
        }
        access.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        access
    }
}

/// Runs one slot: `finish` (timed), then `into_overlay` and the overlay commit (untimed).
fn apply(nomt: &Nomt<Hasher>, access: Vec<(KeyPath, KeyReadWrite)>) -> f64 {
    let session = nomt.begin_session(SessionParams::default());
    let start = Instant::now();
    let finished = session.finish(access).unwrap();
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    finished.into_overlay().commit(nomt).unwrap();
    elapsed
}

fn seed(db: &str, state_path: &str) {
    let _ = std::fs::remove_dir_all(db);
    let nomt = open(db);
    let mut state = State {
        slot: 0,
        live: GENESIS_KEYS,
        versions: vec![0; GENESIS_KEYS as usize],
        touched: vec![0; GENESIS_KEYS as usize],
    };
    let mut genesis: Vec<_> = (0..GENESIS_KEYS)
        .map(|idx| (key_path(idx), KeyReadWrite::Write(Some(value(idx, 0)))))
        .collect();
    genesis.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    apply(&nomt, genesis);
    while state.live < SEED_LEAVES {
        let access = state.next_slot();
        let ms = apply(&nomt, access);
        if state.slot % 20 == 0 {
            eprintln!(
                "seed slot {} leaves {} finish {:.1} ms",
                state.slot, state.live, ms
            );
        }
    }
    drop(nomt);
    state.save(state_path);
    println!("seed_slots: {}", state.slot);
    println!("seed_leaves: {}", state.live);
}

fn run(db: &str, state_path: &str) {
    let mut state = State::load(state_path);
    let nomt = open(db);
    let mut times = Vec::new();
    let mut accesses = 0usize;
    for i in 0..WARM_UP_SLOTS + MEASURED_SLOTS {
        let access = state.next_slot();
        let n = access.len();
        let ms = apply(&nomt, access);
        eprintln!("slot {} accesses {} finish {:.2} ms", state.slot, n, ms);
        if i >= WARM_UP_SLOTS {
            times.push(ms);
            accesses += n;
        }
    }
    let total: f64 = times.iter().sum();
    let mean = total / times.len() as f64;
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| times[((times.len() as f64 * p).ceil() as usize).saturating_sub(1)];
    println!("finish_mean_ms: {:.3}", mean);
    println!("finish_p50_ms: {:.3}", pct(0.5));
    println!("finish_p90_ms: {:.3}", pct(0.9));
    println!("finish_max_ms: {:.3}", times[times.len() - 1]);
    println!(
        "finish_us_per_access: {:.4}",
        total * 1000.0 / accesses as f64
    );
    println!("leaves: {}", state.live);
    println!("final_root: {}", hex(&nomt.root().into_inner()));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("seed") => seed(&args[2], &args[3]),
        Some("run") => run(&args[2], &args[3]),
        _ => panic!("usage: finish_bench seed|run <db> <state>"),
    }
}
