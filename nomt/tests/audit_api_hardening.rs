use nomt::{hasher::Blake3Hasher, KeyReadWrite, Nomt, Options, SessionParams};
use std::{sync::mpsc, time::Duration};

fn options(name: &str) -> Options {
    let path = std::path::PathBuf::from("test").join(name);
    let _ = std::fs::remove_dir_all(&path);
    let mut o = Options::new();
    o.path(path);
    o.commit_concurrency(1);
    o.io_workers(1);
    o.bitbox_seed([0; 16]);
    o.hashtable_buckets(4096);
    o
}

fn key(b0: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = b0;
    k
}

fn panic_message(p: Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<String>()
        .cloned()
        .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

#[test]
fn audit_a4_5_finish_on_overlay_with_superseded_base() {
    // A4-5
    let nomt = Nomt::<Blake3Hasher>::open(options("audit_a4_5_superseded_base")).unwrap();
    let (a, b) = (key(0x00), key(0x80));
    let write = |k, v| {
        nomt.begin_session(SessionParams::default())
            .finish(vec![(k, KeyReadWrite::Write(v))])
            .unwrap()
    };
    write(a, Some(vec![1])).commit(&nomt).unwrap();
    let o1 = write(b, Some(vec![2])).into_overlay();
    write(a, None).commit(&nomt).unwrap();

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Ok(params) = SessionParams::default().overlay([&o1]) else {
                return "rejected: overlay".to_string();
            };
            match nomt
                .begin_session(params)
                .finish(vec![(a, KeyReadWrite::Write(Some(vec![9])))])
            {
                Ok(_) => "accepted: finish returned Ok".to_string(),
                Err(e) => format!("rejected: finish: {e:#}"),
            }
        }));
        let _ = tx.send(outcome.unwrap_or_else(|p| format!("panic: {}", panic_message(p))));
    });
    let outcome = rx.recv_timeout(Duration::from_secs(20)).expect("hung");
    assert!(outcome.starts_with("rejected"), "{outcome}");
}

#[test]
fn audit_a7_9_commit_while_same_thread_holds_a_session() {
    // A7-9
    let nomt = Nomt::<Blake3Hasher>::open(options("audit_a7_9_self_deadlock")).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = nomt.begin_session(SessionParams::default());
        let finished = nomt
            .begin_session(SessionParams::default())
            .finish(vec![(key(1), KeyReadWrite::Write(Some(vec![1])))])
            .unwrap();
        let r = finished.commit(&nomt).is_ok();
        drop(reader);
        let _ = tx.send(r);
    });
    assert!(
        rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "commit neither completed nor returned an error while its own thread holds a session"
    );
}

#[test]
fn audit_a7_12_page_cache_size_zero() {
    // A7-12
    let mut o = options("audit_a7_12_page_cache_size_zero");
    o.page_cache_size(0);
    let opened = std::panic::catch_unwind(move || Nomt::<Blake3Hasher>::open(o).map(|_| ()));
    assert!(
        opened.is_ok(),
        "Nomt::open panicked: {}",
        panic_message(opened.unwrap_err())
    );
}

#[test]
fn audit_a7_5_root_after_failed_commit() {
    // A7-5
    let o = options("audit_a7_5_root_after_failed_commit");
    let nomt = Nomt::<Blake3Hasher>::open(o).unwrap();
    let root_before = nomt.root();

    let finished = nomt
        .begin_session(SessionParams::default())
        .finish(vec![(key(1), KeyReadWrite::Write(Some(vec![1])))])
        .unwrap();

    let ln = std::fs::canonicalize("test/audit_a7_5_root_after_failed_commit/ln").unwrap();
    let ln_fd: i32 = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .map(|e| e.unwrap())
        .find(|e| std::fs::read_link(e.path()).map_or(false, |l| l == ln))
        .map(|e| e.file_name().to_str().unwrap().parse().unwrap())
        .unwrap();
    let null = std::ffi::CString::new("/dev/null").unwrap();
    unsafe {
        let rdonly = libc::open(null.as_ptr(), libc::O_RDONLY);
        assert!(rdonly >= 0);
        assert_eq!(libc::dup2(rdonly, ln_fd), ln_fd);
        libc::close(rdonly);
    }

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            finished.commit(&nomt).map_err(|e| format!("{e:#}"))
        }));
        let _ = tx.send((r.map_err(panic_message), nomt.is_poisoned(), nomt.root()));
    });
    let (r, poisoned, root_after) = rx.recv_timeout(Duration::from_secs(30)).expect("hung");
    eprintln!("commit with failing leaf writes: {r:?}; poisoned: {poisoned}");
    assert!(
        matches!(r, Ok(Err(_))),
        "fault injection did not produce an Err"
    );
    assert_eq!(
        root_after, root_before,
        "root() reports the root of a commit that returned Err"
    );
}
