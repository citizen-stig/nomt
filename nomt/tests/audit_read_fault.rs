use nomt::{hasher::Blake3Hasher, KeyReadWrite, Nomt, Options, Root, SessionParams};
use nomt_test_utils::account_path;
use std::{
    ffi::CString,
    path::{Path, PathBuf},
    sync::mpsc,
    time::Duration,
};

const ACCOUNTS: u64 = 2000;

fn open(path: &Path, rollback: bool) -> Nomt<Blake3Hasher> {
    let mut o = Options::new();
    o.path(path);
    o.commit_concurrency(1);
    o.io_workers(1);
    o.bitbox_seed([0; 16]);
    o.hashtable_buckets(64_000);
    o.rollback(rollback);
    Nomt::open(o).unwrap()
}

fn commit(nomt: &Nomt<Blake3Hasher>, writes: impl IntoIterator<Item = (u64, u64)>) -> Root {
    let session = nomt.begin_session(SessionParams::default());
    let mut actuals = writes
        .into_iter()
        .map(|(id, v)| {
            (
                account_path(id),
                KeyReadWrite::Write(Some(v.to_le_bytes().to_vec())),
            )
        })
        .collect::<Vec<_>>();
    actuals.sort_by_key(|(k, _)| *k);
    let finished = session.finish(actuals).unwrap();
    let root = finished.root();
    finished.commit(nomt).unwrap();
    root
}

fn fd_of(path: &Path) -> i32 {
    let target = std::fs::canonicalize(path).unwrap();
    for entry in std::fs::read_dir("/proc/self/fd").unwrap() {
        let entry = entry.unwrap();
        if std::fs::read_link(entry.path()).map_or(false, |l| l == target) {
            return entry.file_name().to_str().unwrap().parse().unwrap();
        }
    }
    panic!("no open fd for {}", path.display());
}

/// Makes every read on `fd` fail with EBADF by pointing it at a write-only file. Returns the
/// saved descriptor for `restore`.
fn fail_reads(fd: i32) -> i32 {
    let null = CString::new("/dev/null").unwrap();
    unsafe {
        let saved = libc::dup(fd);
        assert!(saved >= 0);
        let wronly = libc::open(null.as_ptr(), libc::O_WRONLY);
        assert!(wronly >= 0);
        assert_eq!(libc::dup2(wronly, fd), fd);
        libc::close(wronly);
        saved
    }
}

fn restore(fd: i32, saved: i32) {
    unsafe {
        assert_eq!(libc::dup2(saved, fd), fd);
        libc::close(saved);
    }
}

// A7-4: a rollback that fails before its commit must leave the rollback log matching the state.
#[test]
fn audit_a7_4_failed_rollback_keeps_log_consistent() {
    let path = PathBuf::from("test/audit_a7_4_failed_rollback");
    let _ = std::fs::remove_dir_all(&path);

    let nomt = open(&path, true);
    commit(&nomt, (0..ACCOUNTS).map(|i| (i, 1000)));
    let root_after_second = commit(&nomt, [(7, 1)]);
    let root_after_third = commit(&nomt, [(9, 2)]);
    drop(nomt);

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let nomt = open(&path, true);
        let ht_fd = fd_of(&path.join("ht"));
        let saved = fail_reads(ht_fd);
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| nomt.rollback(1)));
        restore(ht_fd, saved);
        let failed = match failed {
            Ok(Ok(())) => "ok".to_string(),
            Ok(Err(e)) => format!("err: {e:#}"),
            Err(_) => "panic".to_string(),
        };
        let poisoned = nomt.is_poisoned();
        let root_after_failure = nomt.root();
        let retry = nomt.rollback(1).map_err(|e| format!("{e:#}"));
        let balance = |id| {
            let v = nomt.read(account_path(id)).unwrap().unwrap();
            u64::from_le_bytes(v[..].try_into().unwrap())
        };
        let balances = (balance(7), balance(9));
        let _ = tx.send((
            failed,
            poisoned,
            root_after_failure,
            retry,
            nomt.root(),
            balances,
        ));
    });
    let (failed, poisoned, root_after_failure, retry, root_after_retry, balances) = rx
        .recv_timeout(Duration::from_secs(120))
        .expect("rollback hung");

    eprintln!("first rollback with failing merkle reads: {failed}; poisoned: {poisoned}; retry: {retry:?}");
    assert!(
        failed.starts_with("err"),
        "fault injection did not produce an Err"
    );
    assert_eq!(root_after_failure, root_after_third);
    eprintln!("after retry (account 7, account 9) = {balances:?}; state before the last commit was (1, 1000)");
    assert_eq!(
        root_after_retry, root_after_second,
        "rollback(1) after a failed rollback(1) did not restore the state before the last commit"
    );
}

// A3-4: a failed leaf read must surface as Err from Nomt::read.
#[test]
fn audit_a3_4_blocking_leaf_read_error_panics() {
    let path = PathBuf::from("test/audit_a3_4_leaf_read_error");
    let _ = std::fs::remove_dir_all(&path);

    let nomt = open(&path, false);
    commit(&nomt, (0..ACCOUNTS).map(|i| (i, 1000)));
    drop(nomt);

    let nomt = open(&path, false);
    let ln_fd = fd_of(&path.join("ln"));
    let saved = fail_reads(ln_fd);
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| nomt.read(account_path(7))));
    restore(ln_fd, saved);

    match result {
        Ok(read) => assert!(
            read.is_err(),
            "read succeeded although the leaf read failed"
        ),
        Err(_) => panic!("Nomt::read panicked on a leaf read error instead of returning Err"),
    }
}

const A6_5_CHILD: &str = "AUDIT_A6_5_CHILD";

// A6-5: a failed prior-value read during finish must surface as an error, not abort the process.
#[test]
fn audit_a6_5_prior_read_error_aborts_process() {
    use std::os::unix::process::ExitStatusExt as _;

    let path = PathBuf::from("test/audit_a6_5_prior_read_error");
    if std::env::var_os(A6_5_CHILD).is_some() {
        let nomt = open(&path, true);
        let ln_fd = fd_of(&path.join("ln"));
        let saved = fail_reads(ln_fd);
        let session = nomt.begin_session(SessionParams::default());
        let r = session.finish(vec![(account_path(7), KeyReadWrite::Write(Some(vec![1])))]);
        restore(ln_fd, saved);
        eprintln!("child: finish returned is_err={}", r.is_err());
        return;
    }

    let _ = std::fs::remove_dir_all(&path);
    let nomt = open(&path, true);
    commit(&nomt, (0..ACCOUNTS).map(|i| (i, 1000)));
    drop(nomt);

    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "audit_a6_5_prior_read_error_aborts_process",
            "--nocapture",
        ])
        .env(A6_5_CHILD, "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    for line in stderr
        .lines()
        .filter(|l| l.contains("panicked") || l.contains("abort") || l.contains("child:"))
    {
        eprintln!("child stderr: {line}");
    }
    assert_eq!(
        out.status.signal(),
        None,
        "process was killed by a signal when a prior-value read failed during Session::finish"
    );
}

// A7-8: a failed prior-value read must not panic out of dropping the session.
#[test]
fn audit_a7_8_prior_read_error_panics_in_session_drop() {
    let path = PathBuf::from("test/audit_a7_8_prior_read_error");
    let _ = std::fs::remove_dir_all(&path);
    let nomt = open(&path, true);
    commit(&nomt, (0..ACCOUNTS).map(|i| (i, 1000)));
    drop(nomt);

    let nomt = open(&path, true);
    let ln_fd = fd_of(&path.join("ln"));
    let saved = fail_reads(ln_fd);
    let session = nomt.begin_session(SessionParams::default());
    session.preserve_prior_value(account_path(7));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(session)));
    restore(ln_fd, saved);
    assert!(
        r.is_ok(),
        "dropping the session panicked after a prior-value read error"
    );
}
