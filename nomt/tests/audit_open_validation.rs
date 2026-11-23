use nomt::{hasher::Blake3Hasher, KeyReadWrite, Nomt, Options, Root, SessionParams};
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

fn fresh(name: &str) -> PathBuf {
    let path = PathBuf::from("test").join(name);
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn commit_one_key(nomt: &Nomt<Blake3Hasher>) -> Root {
    let session = nomt.begin_session(SessionParams::default());
    let finished = session
        .finish(vec![([7; 32], KeyReadWrite::Write(Some(vec![1, 2, 3])))])
        .unwrap();
    let root = finished.root();
    finished.commit(nomt).unwrap();
    root
}

fn open_catching(o: Options) -> Result<anyhow::Result<Nomt<Blake3Hasher>>, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Nomt::<Blake3Hasher>::open(o)
    }))
    .map_err(|p| {
        p.downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    })
}

// A1-5: an ln file shorter than the committed bump must not open with a different root.
#[test]
fn audit_a1_5_truncated_ln_is_read_as_valid() {
    let path = fresh("audit_a1_5_truncated_ln");
    let nomt = Nomt::<Blake3Hasher>::open(options(&path)).unwrap();
    let root = commit_one_key(&nomt);
    drop(nomt);

    let ln = std::fs::OpenOptions::new()
        .write(true)
        .open(path.join("ln"))
        .unwrap();
    assert!(ln.metadata().unwrap().len() > 4096);
    ln.set_len(4096).unwrap();
    drop(ln);

    match open_catching(options(&path)) {
        Err(panic) => panic!("open panicked instead of returning Err: {panic}"),
        Ok(Err(_)) => {}
        Ok(Ok(nomt)) => assert_eq!(
            nomt.root(),
            root,
            "open succeeded on a truncated ln file and reports a different root"
        ),
    }
}

// A1-9: a directory left by a crash right after `.lock` was created must still initialise.
#[test]
fn audit_a1_9_lock_only_directory_cannot_be_opened() {
    let path = fresh("audit_a1_9_lock_only");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::File::create(path.join(".lock")).unwrap();

    let r = Nomt::<Blake3Hasher>::open(options(&path));
    assert!(r.is_ok(), "open failed: {:#}", r.err().unwrap());
}

// A2-7: a directory left by a crash between creating `meta` and creating `ht` must still initialise.
#[test]
fn audit_a2_7_partially_created_directory_cannot_be_opened() {
    let path = fresh("audit_a2_7_partial_create");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::File::create(path.join(".lock")).unwrap();
    std::fs::File::create(path.join("meta")).unwrap();

    let r = Nomt::<Blake3Hasher>::open(options(&path));
    assert!(r.is_ok(), "open failed: {:#}", r.err().unwrap());
}

// A2-5: a WAL entry with an out-of-range bucket must be rejected with an error.
#[test]
fn audit_a2_5_wal_out_of_range_bucket_panics() {
    let path = fresh("audit_a2_5_wal_bucket");
    let nomt = Nomt::<Blake3Hasher>::open(options(&path)).unwrap();
    commit_one_key(&nomt);
    let seqn = nomt.sync_seqn();
    drop(nomt);

    let mut wal = vec![0u8; 4096];
    wal[0] = 1;
    wal[1..5].copy_from_slice(&seqn.to_le_bytes());
    wal[5] = 3;
    wal[6..14].copy_from_slice(&u64::MAX.to_le_bytes());
    wal[14] = 2;
    std::fs::write(path.join("wal"), wal).unwrap();

    match open_catching(options(&path)) {
        Err(panic) => panic!("open panicked instead of returning Err: {panic}"),
        Ok(r) => assert!(r.is_err(), "open accepted an out-of-range WAL bucket"),
    }
}

// A2-6: zero hash-table buckets must be rejected with an error.
#[test]
fn audit_a2_6_zero_hashtable_buckets_panics() {
    let path = fresh("audit_a2_6_zero_buckets");
    let mut o = options(&path);
    o.hashtable_buckets(0);

    match open_catching(o) {
        Err(panic) => panic!("open panicked instead of returning Err: {panic}"),
        Ok(r) => assert!(r.is_err(), "open accepted zero hash-table buckets"),
    }
}

// A2-8: a zero-length rehash marker (crash between create and write) must not block open.
#[test]
fn audit_a2_8_empty_rehash_marker_blocks_open() {
    let path = fresh("audit_a2_8_empty_marker");
    let nomt = Nomt::<Blake3Hasher>::open(options(&path)).unwrap();
    let root = commit_one_key(&nomt);
    drop(nomt);

    std::fs::File::create(path.join("ht.rehashing-marker")).unwrap();

    match Nomt::<Blake3Hasher>::open(options(&path)) {
        Ok(nomt) => assert_eq!(nomt.root(), root),
        Err(e) => panic!("open failed: {e:#}"),
    }
}

// A1-7: a damaged BBN page must make open return an error.
#[test]
fn audit_a1_7_corrupt_bbn_page_panics_on_open() {
    use std::os::unix::fs::FileExt as _;

    let path = fresh("audit_a1_7_corrupt_bbn");
    let nomt = Nomt::<Blake3Hasher>::open(options(&path)).unwrap();
    commit_one_key(&nomt);
    drop(nomt);

    let bbn = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path.join("bbn"))
        .unwrap();
    let mut header = [0u8; 6];
    bbn.read_exact_at(&mut header, 4096).unwrap();
    assert_eq!(u32::from_le_bytes(header[..4].try_into().unwrap()), 1);
    bbn.write_all_at(&[0xFF, 0xFF], 4096 + 4).unwrap();
    drop(bbn);

    match open_catching(options(&path)) {
        Err(panic) => panic!("open panicked instead of returning Err: {panic}"),
        Ok(r) => assert!(r.is_err(), "open accepted a damaged BBN page"),
    }
}
