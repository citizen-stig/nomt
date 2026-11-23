use nomt::{hasher::Blake3Hasher, KeyReadWrite, Nomt, Options, SessionParams};
use std::{path::PathBuf, sync::mpsc, time::Duration};

// Hardening e947bdb: max_rollback_log_len(0) is accepted by the setter and must not break commits.
#[test]
fn audit_rollback_log_len_zero_commit_succeeds() {
    let path = PathBuf::from("test/audit_rollback_log_len_zero");
    let _ = std::fs::remove_dir_all(&path);
    let mut o = Options::new();
    o.path(path);
    o.commit_concurrency(1);
    o.rollback(true);
    o.max_rollback_log_len(0);
    let nomt = Nomt::<Blake3Hasher>::open(o).unwrap();

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let session = nomt.begin_session(SessionParams::default());
            let finished = session
                .finish(vec![([1; 32], KeyReadWrite::Write(Some(vec![1])))])
                .unwrap();
            finished.commit(&nomt)
        }));
        let _ = tx.send(r.map(|r| r.map_err(|e| e.to_string())).map_err(|_| ()));
    });
    let outcome = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("commit hung");
    assert_eq!(outcome, Ok(Ok(())), "Err(()) means the commit panicked");
}
