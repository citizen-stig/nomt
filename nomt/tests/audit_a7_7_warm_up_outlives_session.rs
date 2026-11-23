use nomt::{hasher::Blake3Hasher, KeyReadWrite, Nomt, Options, SessionParams};
use nomt_test_utils::account_path;

fn options(path: &std::path::Path) -> Options {
    let mut o = Options::new();
    o.path(path);
    o.commit_concurrency(1);
    o.io_workers(1);
    o.bitbox_seed([0; 16]);
    o.hashtable_buckets(4096);
    o.warm_up(true);
    o
}

#[test]
fn audit_a7_7_reopen_after_dropping_session_and_handle() {
    // A7-7
    let path = std::path::PathBuf::from("test/audit_a7_7_warm_up_outlives_session");
    let _ = std::fs::remove_dir_all(&path);

    let nomt = Nomt::<Blake3Hasher>::open(options(&path)).unwrap();
    let mut actuals = (0..2000)
        .map(|id| (account_path(id), KeyReadWrite::Write(Some(vec![1; 8]))))
        .collect::<Vec<_>>();
    actuals.sort_by_key(|(k, _)| *k);
    nomt.begin_session(SessionParams::default())
        .finish(actuals)
        .unwrap()
        .commit(&nomt)
        .unwrap();
    drop(nomt);

    let mut failures = Vec::new();
    for round in 0..200 {
        let nomt = Nomt::<Blake3Hasher>::open(options(&path)).unwrap();
        let session = nomt.begin_session(SessionParams::default());
        for id in 0..500 {
            session.warm_up(account_path(id));
        }
        drop(session);
        drop(nomt);

        if let Err(e) = Nomt::<Blake3Hasher>::open(options(&path)) {
            failures.push(format!("round {round}: {e:#}"));
            while Nomt::<Blake3Hasher>::open(options(&path)).is_err() {
                std::thread::yield_now();
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of 200 reopen attempts failed right after drop(session); drop(nomt): first: {}",
        failures.len(),
        failures[0]
    );
}
