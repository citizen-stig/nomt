mod common;

use common::account_path;
use nomt::{
    hasher::Blake3Hasher, KeyReadWrite, MetricsLevel, Nomt, Options, SessionParams, WitnessMode,
};
use std::path::{Path, PathBuf};

const ACCOUNTS: u64 = 20_000;
const OVERFLOW_ID: u64 = ACCOUNTS;
// Larger than the maximum value stored inline in a leaf, so it spans several overflow pages.
const OVERFLOW_VALUE_LEN: usize = 64 * 1024;

fn open(path: &Path, level: MetricsLevel, prepopulate_page_cache: bool) -> Nomt<Blake3Hasher> {
    let mut o = Options::new();
    o.path(path);
    o.metrics_level(level);
    o.bitbox_seed([0; 16]);
    o.hashtable_buckets(64_000);
    o.commit_concurrency(1);
    o.io_workers(1);
    // Small caches so that a cold reopen has to go to disk.
    o.page_cache_size(1);
    o.leaf_cache_size(1);
    o.prepopulate_page_cache(prepopulate_page_cache);
    Nomt::open(o).unwrap()
}

fn commit(nomt: &Nomt<Blake3Hasher>, mut actuals: Vec<(nomt::trie::KeyPath, KeyReadWrite)>) {
    actuals.sort_by_key(|(k, _)| *k);
    let session =
        nomt.begin_session(SessionParams::default().witness_mode(WitnessMode::disabled()));
    for (key, _) in &actuals {
        session.warm_up(*key);
    }
    session.finish(actuals).unwrap().commit(nomt).unwrap();
}

/// Create a fresh database at `path` with `ACCOUNTS` small values and one overflow value.
fn populate(path: &Path) {
    let _ = std::fs::remove_dir_all(path);
    let nomt = open(path, MetricsLevel::Off, false);
    let mut actuals: Vec<_> = (0..ACCOUNTS)
        .map(|id| {
            (
                account_path(id),
                KeyReadWrite::Write(Some(id.to_le_bytes().to_vec())),
            )
        })
        .collect();
    actuals.push((
        account_path(OVERFLOW_ID),
        KeyReadWrite::Write(Some(vec![7; OVERFLOW_VALUE_LEN])),
    ));
    commit(&nomt, actuals);
}

/// Update every tenth account without reading its value: all disk reads here come from the merkle
/// seek (page loads, leaf fetches, elided page reconstruction) and from the beatree update.
fn update_every_tenth(nomt: &Nomt<Blake3Hasher>) {
    let actuals: Vec<_> = (0..ACCOUNTS)
        .step_by(10)
        .map(|id| {
            (
                account_path(id),
                KeyReadWrite::Write(Some((id + 1).to_le_bytes().to_vec())),
            )
        })
        .collect();
    commit(nomt, actuals);
}

/// Read the overflow value, returning how many `ln` reads it took.
fn read_overflow_value(nomt: &Nomt<Blake3Hasher>) -> u64 {
    let ln_reads_before = nomt.metrics().get_ln_reads();
    let session = nomt.begin_session(SessionParams::default());
    let value = session.read(account_path(OVERFLOW_ID)).unwrap().unwrap();
    assert_eq!(value.len(), OVERFLOW_VALUE_LEN);
    drop(session);
    nomt.metrics().get_ln_reads() - ln_reads_before
}

/// Disk reads of the commit path (merkle seek and beatree update) and of value reads must show up
/// in the metrics, not only page cache lookups.
#[test]
fn metrics_count_disk_reads() {
    let path = PathBuf::from("test/metrics_count_disk_reads");
    populate(&path);

    // Page cache prepopulation reads the hash-table, but is not a page fetch after a cache miss.
    {
        let nomt = open(&path, MetricsLevel::Full, true);
        let metrics = nomt.metrics();
        assert!(metrics.get_ht_reads() > 1);
        assert_eq!(metrics.get_page_fetch_time(), None);
    }

    // Reopen with cold caches.
    let nomt = open(&path, MetricsLevel::Full, false);
    let metrics = nomt.metrics();
    assert_eq!(metrics.metrics_level(), MetricsLevel::Full);
    let ln_reads_at_open = metrics.get_ln_reads();

    update_every_tenth(&nomt);

    assert!(metrics.get_page_requests() > 0);
    assert!(metrics.get_page_cache_misses() > 0);
    assert!(metrics.get_ht_reads() > 0);
    assert!(metrics.get_page_fetch_time().is_some());

    let leaf_cache_requests = metrics.get_leaf_cache_requests();
    let leaf_cache_misses = metrics.get_leaf_cache_misses();
    assert!(leaf_cache_misses > 0);
    assert!(leaf_cache_requests >= leaf_cache_misses);
    // Every leaf cache miss reads the leaf from the `ln` file.
    assert!(metrics.get_ln_reads() > ln_reads_at_open);
    assert!(metrics.get_ln_reads() >= leaf_cache_misses);

    // A blocking value read of an overflow value reads all of its overflow pages.
    assert!(read_overflow_value(&nomt) > (OVERFLOW_VALUE_LEN / 4096) as u64);
    assert!(metrics.get_value_fetch_time().is_some());
}

/// The `Io` level counts the same disk reads, without the per-lookup counters and the value read
/// timer.
#[test]
fn io_level_counts_disk_reads() {
    let path = PathBuf::from("test/metrics_io_level_counts_disk_reads");
    populate(&path);

    let nomt = open(&path, MetricsLevel::Io, false);
    let metrics = nomt.metrics();
    assert_eq!(metrics.metrics_level(), MetricsLevel::Io);

    update_every_tenth(&nomt);

    assert!(metrics.get_page_cache_misses() > 0);
    assert!(metrics.get_ht_reads() > 0);
    assert!(metrics.get_page_fetch_time().is_some());
    assert!(metrics.get_leaf_cache_misses() > 0);
    assert!(metrics.get_ln_reads() >= metrics.get_leaf_cache_misses());
    assert!(read_overflow_value(&nomt) > (OVERFLOW_VALUE_LEN / 4096) as u64);

    // Not collected at this level.
    assert!(std::panic::catch_unwind(|| metrics.get_page_requests()).is_err());
    assert!(std::panic::catch_unwind(|| metrics.get_value_fetch_time()).is_err());
}
