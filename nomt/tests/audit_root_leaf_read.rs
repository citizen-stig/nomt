use nomt::{hasher::Blake3Hasher, KeyReadWrite, Nomt, Options, SessionParams};
use std::path::{Path, PathBuf};

fn options(path: &Path) -> Options {
    let mut o = Options::new();
    o.path(path);
    o.commit_concurrency(1);
    o.io_workers(1);
    o.bitbox_seed([0; 16]);
    o.hashtable_buckets(64_000);
    o
}

/// Opens a single-key database whose first leaf read fails with EIO.
///
/// The database lives on tmpfs so the store opens `ln` without O_DIRECT, and `ln` is replaced by a
/// symlink to /proc/self/mem, where a read at the leaf's offset (an unmapped address) returns EIO.
fn open_with_failing_leaf_read(name: &str) {
    let path = PathBuf::from("/dev/shm").join(format!("{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);

    let nomt = Nomt::<Blake3Hasher>::open(options(&path)).unwrap();
    let session = nomt.begin_session(SessionParams::default());
    let finished = session
        .finish(vec![([7; 32], KeyReadWrite::Write(Some(vec![1, 2, 3])))])
        .unwrap();
    let root = finished.root();
    finished.commit(&nomt).unwrap();
    drop(nomt);

    std::fs::rename(path.join("ln"), path.join("ln.orig")).unwrap();
    std::os::unix::fs::symlink("/proc/self/mem", path.join("ln")).unwrap();

    let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Nomt::<Blake3Hasher>::open(options(&path)).map(|nomt| nomt.root())
    }));
    let _ = std::fs::remove_dir_all(&path);

    match opened {
        Err(_) => panic!("open panicked instead of returning Err"),
        Ok(Err(_)) => {}
        Ok(Ok(opened_root)) => assert_eq!(
            opened_root, root,
            "open returned Ok with a different root although the leaf read failed"
        ),
    }
}

// A3-9: compute_root_node must not use the buffer of a failed leaf read.
#[test]
fn audit_a3_9_root_from_failed_leaf_read() {
    open_with_failing_leaf_read("nomt_audit_a3_9");
}

// A4-4: same defect as A3-9, reported independently.
#[test]
fn audit_a4_4_root_from_failed_leaf_read() {
    open_with_failing_leaf_read("nomt_audit_a4_4");
}

// A7-11: same defect as A3-9, reported independently.
#[test]
fn audit_a7_11_root_from_failed_leaf_read() {
    open_with_failing_leaf_read("nomt_audit_a7_11");
}
