use nomt::{hasher::Blake3Hasher, KeyReadWrite, Nomt, Options, SessionParams};
use nomt_test_utils::account_path;
use std::{ffi::CString, path::Path, sync::mpsc, time::Duration};

fn open(path: &Path) -> Nomt<Blake3Hasher> {
    let mut o = Options::new();
    o.path(path);
    o.commit_concurrency(1);
    o.io_workers(1);
    o.bitbox_seed([0; 16]);
    o.hashtable_buckets(64_000);
    Nomt::open(o).unwrap()
}

fn finish(nomt: &Nomt<Blake3Hasher>, ids: std::ops::Range<u64>, commit: bool) -> bool {
    let session = nomt.begin_session(SessionParams::default());
    let mut actuals = ids
        .map(|id| (account_path(id), KeyReadWrite::Write(Some(vec![1; 8]))))
        .collect::<Vec<_>>();
    actuals.sort_by_key(|(k, _)| *k);
    match session.finish(actuals) {
        Ok(finished) if commit => finished.commit(nomt).is_ok(),
        r => r.is_ok(),
    }
}

fn io_uring_fds() -> Vec<i32> {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            let link = std::fs::read_link(entry.path()).ok()?;
            (link.to_str()? == "anon_inode:[io_uring]")
                .then(|| entry.file_name().to_str().unwrap().parse().unwrap())
        })
        .collect()
}

// A7-6: when the I/O worker dies on an io_uring_enter error, waiting callers must be woken with
// an error. The error is injected by replacing the ring fd, so io_uring_enter fails.
// This must stay the only test in this binary: it expects exactly one ring and leaks a thread.
#[test]
fn audit_a7_6_dead_io_worker_hangs_callers() {
    let path = std::path::PathBuf::from("test/audit_a7_6_io_worker_death");
    let _ = std::fs::remove_dir_all(&path);
    let nomt = open(&path);
    assert!(finish(&nomt, 0..2000, true));
    drop(nomt);

    let nomt = open(&path);
    let rings = io_uring_fds();
    assert_eq!(rings.len(), 1);
    let null = CString::new("/dev/null").unwrap();
    unsafe {
        let fd = libc::open(null.as_ptr(), libc::O_RDWR);
        assert!(fd >= 0);
        assert_eq!(libc::dup2(fd, rings[0]), rings[0]);
        libc::close(fd);
    }

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| finish(&nomt, 0..1, false)));
        let _ = tx.send(matches!(r, Ok(true)));
    });
    let succeeded = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("Session::finish never returned after the I/O worker died");
    assert!(!succeeded);
}
