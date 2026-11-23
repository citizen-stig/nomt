use nomt::{hasher::Blake3Hasher, KeyReadWrite, Nomt, Options, SessionParams};
use std::{
    sync::{mpsc, Arc},
    time::Duration,
};

fn open(name: &str) -> Arc<Nomt<Blake3Hasher>> {
    let path = std::path::PathBuf::from("test").join(name);
    let _ = std::fs::remove_dir_all(&path);
    let mut o = Options::new();
    o.path(path);
    o.hashtable_buckets(4096);
    o.io_workers(1);
    Arc::new(Nomt::open(o).unwrap())
}

fn second_session_while_commit_queued(name: &str, create_first_elsewhere: bool) -> bool {
    let nomt = open(name);
    let key = [1; 32];

    let (tx, rx) = mpsc::channel();
    std::thread::spawn({
        let nomt = nomt.clone();
        move || {
            let first = if create_first_elsewhere {
                std::thread::spawn({
                    let nomt = nomt.clone();
                    move || nomt.begin_session(SessionParams::default())
                })
                .join()
                .unwrap()
            } else {
                nomt.begin_session(SessionParams::default())
            };

            let committer = std::thread::spawn({
                let nomt = nomt.clone();
                move || {
                    nomt.begin_session(SessionParams::default())
                        .finish(vec![(key, KeyReadWrite::Write(Some(vec![1])))])
                        .unwrap()
                        .commit(&nomt)
                        .unwrap()
                }
            });
            std::thread::sleep(Duration::from_millis(1000));

            let second = nomt.begin_session(SessionParams::default());
            drop((first, second));
            committer.join().unwrap();
            let _ = tx.send(());
        }
    });

    rx.recv_timeout(Duration::from_secs(15)).is_ok()
}

#[test]
fn audit_a7_2_moved_session_deadlocks_behind_queued_commit() {
    // A7-2
    assert!(
        second_session_while_commit_queued("audit_a7_2_control", false),
        "control: first session created on the holding thread"
    );
    assert!(
        second_session_while_commit_queued("audit_a7_2_moved_session", true),
        "begin_session never returned: thread holds a session created on another thread while a commit is queued"
    );
}
