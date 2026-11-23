use nomt::{hasher::Blake3Hasher, KeyReadWrite, Nomt, Options, SessionParams};
use nomt_test_utils::account_path;
use std::{os::unix::fs::FileExt as _, path::Path, sync::mpsc, time::Duration};

fn options(path: &Path) -> Options {
    let mut o = Options::new();
    o.path(path);
    o.commit_concurrency(1);
    o.io_workers(1);
    o.bitbox_seed([0; 16]);
    o.hashtable_buckets(64_000);
    o
}

fn commit(nomt: &Nomt<Blake3Hasher>, value: u64) {
    let session = nomt.begin_session(SessionParams::default());
    let mut actuals = (0..2000)
        .map(|id| {
            (
                account_path(id),
                KeyReadWrite::Write(Some(value.to_le_bytes().to_vec())),
            )
        })
        .collect::<Vec<_>>();
    actuals.sort_by_key(|(k, _)| *k);
    session.finish(actuals).unwrap().commit(nomt).unwrap();
}

// A3-6: a free-list page whose prev pointer forms a cycle must make open fail, not loop forever.
// This must stay the only test in this binary: the looping thread is only stopped by process exit.
#[test]
fn audit_a3_6_free_list_cycle_hangs_open() {
    let path = std::path::PathBuf::from("test/audit_a3_6_free_list_cycle");
    let _ = std::fs::remove_dir_all(&path);
    let nomt = Nomt::<Blake3Hasher>::open(options(&path)).unwrap();
    for value in 1..=3 {
        commit(&nomt, value);
    }
    drop(nomt);

    let mut meta = [0u8; 12];
    std::fs::File::open(path.join("meta"))
        .unwrap()
        .read_exact_at(&mut meta, 0)
        .unwrap();
    let ln_freelist_pn = u32::from_le_bytes(meta[8..12].try_into().unwrap());
    assert_ne!(ln_freelist_pn, 0, "no ln free list was produced");
    std::fs::OpenOptions::new()
        .write(true)
        .open(path.join("ln"))
        .unwrap()
        .write_all_at(&ln_freelist_pn.to_le_bytes(), ln_freelist_pn as u64 * 4096)
        .unwrap();

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(Nomt::<Blake3Hasher>::open(options(&path)).is_err());
    });
    let failed = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("open did not return within 5s on a free list whose head points to itself");
    assert!(failed, "open accepted a cyclic free list");
}
