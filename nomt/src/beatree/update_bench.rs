//! Seeded Beatree update measurements, available only with the `benchmarks` feature.

use super::{allocator::FREELIST_EMPTY, Key, SyncData, Tree, ValueChange};
use crate::{
    io::{start_io_pool, IoPool, PagePool, PAGE_SIZE},
    task::join_task,
};
use criterion::Criterion;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{
    fs::OpenOptions,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

const ENTRIES: usize = 100_000;
const UPDATES: usize = 1_000;
const VALUE_BYTES: usize = 256;
const WORKERS: usize = 4;

/// Measurements at the update's existing preparation/completion boundary.
#[derive(Default)]
pub(crate) struct Measurements {
    prepare_cpu: Duration,
    prepare_wall: Duration,
    pub(crate) write_wait: Duration,
    pages: usize,
}

/// Clock pair covering preparation, including the worker threads and overlapped I/O.
pub(crate) struct Preparation {
    wall: Instant,
    cpu: Duration,
}

impl Preparation {
    /// Start measuring the preparation interval.
    pub(crate) fn start() -> Self {
        Self {
            wall: Instant::now(),
            cpu: process_cpu(),
        }
    }

    /// Finish preparation after all page writes have been submitted.
    pub(crate) fn finish(self, pages: usize) -> Measurements {
        Measurements {
            prepare_cpu: process_cpu() - self.cpu,
            prepare_wall: self.wall.elapsed(),
            pages,
            ..Measurements::default()
        }
    }
}

fn process_cpu() -> Duration {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is a valid writable timespec. This clock sums CPU across all
    // process threads; a caller-thread clock would miss Beatree's worker CPU.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut time) };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    Duration::new(time.tv_sec as u64, time.tv_nsec as u32)
}

struct Sample {
    meta: SyncData,
    durability: Duration,
    total: Duration,
}

fn update(tree: &Tree, changes: Vec<(Key, ValueChange)>) -> Sample {
    // Construct and stage the changeset before starting the update measurement.
    Tree::commit(&tree.shared, changes);
    let sync = tree.sync.lock();
    let start = Instant::now();
    let (meta, index, post_io) =
        Tree::prepare_sync(&sync, &tree.shared, &tree.read_transaction_counter).unwrap();
    let durability = Instant::now();
    sync.bbn_fsync.fsync();
    sync.ln_fsync.fsync();
    sync.bbn_fsync.wait().unwrap();
    sync.ln_fsync.wait().unwrap();
    let durability = durability.elapsed();
    join_task(&post_io);
    Tree::finish_sync(&tree.shared, index);
    Sample {
        meta,
        durability,
        total: start.elapsed(),
    }
}

fn changes(keys: &[Key], byte: u8) -> Vec<(Key, ValueChange)> {
    keys.iter()
        .map(|&key| (key, ValueChange::Insert(vec![byte; VALUE_BYTES])))
        .collect()
}

fn open(path: &Path, pool: &IoPool, meta: Option<&SyncData>) -> Tree {
    // Match Store::open: direct I/O on Linux except on tmpfs or when the
    // filesystem check fails. Buffered writes would measure a different path.
    #[cfg(target_os = "linux")]
    let direct = crate::sys::linux::fs_check(&std::fs::File::open(path).unwrap())
        .map(|fs| !fs.is_tmpfs())
        .unwrap_or(false);
    let file = |name| {
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(target_os = "linux")]
        if direct {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_DIRECT);
        }
        Arc::new(options.open(path.join(name)).unwrap())
    };
    Tree::open(
        pool.page_pool().clone(),
        pool,
        meta.map_or(FREELIST_EMPTY.0, |m| m.ln_freelist_pn),
        meta.map_or(FREELIST_EMPTY.0, |m| m.bbn_freelist_pn),
        meta.map_or(1, |m| m.ln_bump),
        meta.map_or(1, |m| m.bbn_bump),
        file("bbn"),
        file("ln"),
        WORKERS,
        64,
    )
    .unwrap()
}

/// Benchmark each phase independently using Criterion's saved-baseline comparison.
/// The supplied directory must be disposable and on the filesystem being measured.
pub fn benchmark(c: &mut Criterion, path: &Path) {
    let mut rng = StdRng::seed_from_u64(0xBEA7_2026);
    let keys: Vec<Key> = (0..ENTRIES)
        .map(|_| {
            let mut key = [0; 32];
            rng.fill_bytes(&mut key);
            key
        })
        .collect();
    let mut unique = keys.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), ENTRIES);
    drop(unique);

    let mut pool = start_io_pool(2, PagePool::new());
    let mut group = c.benchmark_group("beatree_update/100k_1k_256b_4workers");
    group.sample_size(20);
    for metric in [
        "prepare_cpu",
        "prepare_wall",
        "write_wait",
        "writes_complete",
        "durability_wait",
        "total",
    ] {
        super::create(path).unwrap();
        let tree = open(path, &pool, None);
        update(&tree, changes(&keys, 0));
        // Prime both the leaf cache and the allocator's free-page reuse cycle.
        update(&tree, changes(&keys[..UPDATES], 1));
        let mut last = update(&tree, changes(&keys[..UPDATES], 2));
        let mut byte = 2u8;
        let mut min_pages = usize::MAX;
        let mut max_pages = 0;
        group.bench_function(metric, |b| {
            b.iter_custom(|iterations| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    byte = if byte == 1 { 2 } else { 1 };
                    last = update(&tree, changes(&keys[..UPDATES], byte));
                    let m = &last.meta.measurements;
                    min_pages = min_pages.min(m.pages);
                    max_pages = max_pages.max(m.pages);
                    elapsed += match metric {
                        "prepare_cpu" => m.prepare_cpu,
                        "prepare_wall" => m.prepare_wall,
                        "write_wait" => m.write_wait,
                        "writes_complete" => m.prepare_wall + m.write_wait,
                        "durability_wait" => last.durability,
                        "total" => last.total,
                        _ => unreachable!(),
                    };
                }
                elapsed
            });
        });
        if max_pages != 0 {
            eprintln!(
                "{metric}: pages/update={min_pages}..={max_pages}, bytes/update={}..={}",
                min_pages * PAGE_SIZE,
                max_pages * PAGE_SIZE
            );
        }

        // Reopen with the returned allocator metadata and an empty leaf cache.
        // Check changed AND untouched values, outside all measured intervals.
        drop(tree);
        let reopened = open(path, &pool, Some(&last.meta));
        for (i, &key) in keys.iter().enumerate() {
            let expected = if i < UPDATES { byte } else { 0 };
            assert_eq!(reopened.lookup(key), Some(vec![expected; VALUE_BYTES]));
        }
    }
    group.finish();
    pool.shutdown();
}
