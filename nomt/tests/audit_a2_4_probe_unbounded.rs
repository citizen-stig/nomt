use nomt::{hasher::Blake3Hasher, KeyReadWrite, Nomt, Options, SessionParams};
use std::{sync::mpsc, time::Duration};

#[test]
fn audit_a2_4_probe_does_not_terminate_without_empty_bucket() {
    // A2-4
    let path = std::path::PathBuf::from("test/audit_a2_4_probe_unbounded");
    let _ = std::fs::remove_dir_all(&path);
    let mut o = Options::new();
    o.path(path);
    o.commit_concurrency(1);
    o.io_workers(1);
    o.bitbox_seed([0; 16]);
    o.hashtable_buckets(2);
    let nomt = Nomt::<Blake3Hasher>::open(o).unwrap();

    let finished = nomt
        .begin_session(SessionParams::default())
        .finish(
            (0..=255u8)
                .map(|i| {
                    let mut k = [0u8; 32];
                    k[0] = i;
                    (k, KeyReadWrite::Write(Some(vec![i])))
                })
                .collect(),
        )
        .unwrap();

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(finished.commit(&nomt).is_err());
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(20)),
        Ok(true),
        "committing 65 pages into a 2-bucket table should fail with BucketExhaustion"
    );
}
