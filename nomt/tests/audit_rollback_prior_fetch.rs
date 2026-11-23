use nomt::{hasher::Blake3Hasher, KeyReadWrite, Nomt, Options, SessionParams};
use std::{path::Path, sync::mpsc, time::Duration};

fn open(path: &Path) -> Nomt<Blake3Hasher> {
    let mut o = Options::new();
    o.path(path);
    o.commit_concurrency(1);
    o.io_workers(1);
    o.bitbox_seed([0; 16]);
    o.hashtable_buckets(4096);
    o.rollback(true);
    o.warm_up(false);
    Nomt::open(o).unwrap()
}

fn write(nomt: &Nomt<Blake3Hasher>, key: [u8; 32], value: Option<Vec<u8>>) {
    nomt.begin_session(SessionParams::default())
        .finish(vec![(key, KeyReadWrite::Write(value))])
        .unwrap()
        .commit(nomt)
        .unwrap();
}

const KEY: [u8; 32] = [0x42; 32];
const A6_3_CHILD: &str = "AUDIT_A6_3_CHILD";

#[test]
fn audit_a6_3_prior_fetch_of_large_overflow_value_aborts() {
    // A6-3
    use std::os::unix::process::ExitStatusExt as _;

    let path = std::path::PathBuf::from("test/audit_a6_3_large_overflow_prior");
    if std::env::var_os(A6_3_CHILD).is_some() {
        let nomt = open(&path);
        let session = nomt.begin_session(SessionParams::default());
        session.preserve_prior_value(KEY);
        let finished = session.finish(vec![(KEY, KeyReadWrite::Write(None))]);
        eprintln!("child: finish returned is_ok={}", finished.is_ok());
        finished.unwrap().commit(&nomt).unwrap();
        nomt.rollback(1).unwrap();
        assert_eq!(nomt.read(KEY).unwrap(), Some(vec![7u8; 100_000]));
        return;
    }

    let _ = std::fs::remove_dir_all(&path);
    let nomt = open(&path);
    write(&nomt, KEY, Some(vec![7u8; 100_000]));
    write(&nomt, [0x01; 32], Some(vec![1]));
    write(&nomt, [0xf1; 32], Some(vec![2]));
    drop(nomt);

    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "audit_a6_3_prior_fetch_of_large_overflow_value_aborts",
            "--nocapture",
        ])
        .env(A6_3_CHILD, "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    for line in stderr.lines().filter(|l| {
        l.contains("panicked")
            || l.contains("index out of")
            || l.contains("abort")
            || l.contains("child:")
    }) {
        eprintln!("child stderr: {line}");
    }
    assert!(
        out.status.success(),
        "deleting a 100 kB value with a cold leaf cache killed the process: signal {:?}, code {:?}",
        out.status.signal(),
        out.status.code()
    );
}

#[test]
fn audit_a6_4_session_drop_after_nomt_hangs_on_pending_prior_lookup() {
    // A6-4
    let path = std::path::PathBuf::from("test/audit_a6_4_session_outlives_nomt");
    let _ = std::fs::remove_dir_all(&path);
    let nomt = open(&path);
    write(&nomt, KEY, Some(vec![7u8; 40_000]));
    write(&nomt, [0x01; 32], Some(vec![1]));
    write(&nomt, [0xf1; 32], Some(vec![2]));
    drop(nomt);

    let drop_session_after_nomt = |preserve: bool| {
        let nomt = open(&path);
        let session = nomt.begin_session(SessionParams::default());
        drop(nomt);

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            if preserve {
                session.preserve_prior_value(KEY);
            }
            drop(session);
            let _ = tx.send(());
        });
        rx.recv_timeout(Duration::from_secs(10)).is_ok()
    };
    assert!(
        drop_session_after_nomt(false),
        "control: no pending prior lookup"
    );
    assert!(
        drop_session_after_nomt(true),
        "dropping the session after the Nomt handle never returned"
    );
}
