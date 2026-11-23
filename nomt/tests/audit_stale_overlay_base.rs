use nomt::{hasher::Blake3Hasher, KeyReadWrite, Nomt, Options, SessionParams};
use std::{sync::mpsc, time::Duration};

fn key(b0: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = b0;
    k
}

#[test]
fn audit_a7_3_session_on_overlay_whose_base_was_superseded() {
    // A7-3
    let path = std::path::PathBuf::from("test/audit_a7_3_stale_overlay_base");
    let _ = std::fs::remove_dir_all(&path);
    let mut o = Options::new();
    o.path(path);
    o.commit_concurrency(1);
    o.io_workers(1);
    o.bitbox_seed([0; 16]);
    o.hashtable_buckets(4096);
    let nomt = Nomt::<Blake3Hasher>::open(o).unwrap();

    let (a, b, c) = (key(0x00), key(0x10), key(0x01));
    nomt.begin_session(SessionParams::default())
        .finish(vec![
            (a, KeyReadWrite::Write(Some(vec![1]))),
            (b, KeyReadWrite::Write(Some(vec![2]))),
        ])
        .unwrap()
        .commit(&nomt)
        .unwrap();

    let overlay = nomt
        .begin_session(SessionParams::default())
        .finish(vec![(c, KeyReadWrite::Write(Some(vec![3])))])
        .unwrap()
        .into_overlay();

    nomt.begin_session(SessionParams::default())
        .finish(vec![(a, KeyReadWrite::Write(None))])
        .unwrap()
        .commit(&nomt)
        .unwrap();

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let params = match SessionParams::default().overlay([&overlay]) {
                Ok(params) => params,
                Err(_) => return "rejected: overlay".to_string(),
            };
            let session = nomt.begin_session(params);
            let read = session.read(a).unwrap();
            match session.prove(a) {
                Ok(_) => format!("accepted: read(a) = {read:?}, prove(a) returned a proof"),
                Err(e) => format!("rejected: prove: {e:#}"),
            }
        }));
        let _ = tx.send(outcome.unwrap_or_else(|p| {
            format!(
                "panic: {}",
                p.downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default()
            )
        }));
    });
    let outcome = rx.recv_timeout(Duration::from_secs(20)).expect("hung");
    assert!(
        outcome.starts_with("rejected"),
        "session over an overlay whose base is no longer the database state: {outcome}"
    );
}
