use nomt::{hasher::Blake3Hasher, KeyReadWrite, Nomt, Options, SessionParams};
use nomt_test_utils::account_path;
use std::{ffi::CString, sync::mpsc, time::Duration};

fn open(path: &std::path::Path) -> Nomt<Blake3Hasher> {
    let mut o = Options::new();
    o.path(path);
    o.commit_concurrency(1);
    o.io_workers(1);
    o.bitbox_seed([0; 16]);
    o.hashtable_buckets(64_000);
    Nomt::open(o).unwrap()
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

#[test]
fn audit_a1_4_io_worker_submit_error_leaves_callers_blocked() {
    // A1-4
    let path = std::path::PathBuf::from("test/audit_a1_4_io_worker_panic");
    let _ = std::fs::remove_dir_all(&path);
    let nomt = open(&path);
    let session = nomt.begin_session(SessionParams::default());
    let mut actuals = (0..2000)
        .map(|id| (account_path(id), KeyReadWrite::Write(Some(vec![1; 8]))))
        .collect::<Vec<_>>();
    actuals.sort_by_key(|(k, _)| *k);
    session.finish(actuals).unwrap().commit(&nomt).unwrap();
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
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            nomt.begin_session(SessionParams::default())
                .prove(account_path(7))
                .is_ok()
        }));
        let _ = tx.send(r);
    });
    let returned = rx.recv_timeout(Duration::from_secs(10));
    assert!(
        returned.is_ok(),
        "Session::prove never returned after io_uring_enter failed in the I/O worker"
    );
}
