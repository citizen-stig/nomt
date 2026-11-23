use nomt::{
    hasher::Blake3Hasher,
    trie::{KeyPath, Node},
    KeyReadWrite, Nomt, Options, SessionParams,
};
use nomt_core::hasher::ValueHasher;

fn key(b0: u8) -> KeyPath {
    let mut k = [0u8; 32];
    k[0] = b0;
    k
}

fn root_of_stored_values(nomt: &Nomt<Blake3Hasher>, keys: &[KeyPath]) -> Node {
    let mut ops = keys
        .iter()
        .filter_map(|k| {
            nomt.read(*k)
                .unwrap()
                .map(|v| (*k, Blake3Hasher::hash_value(&v)))
        })
        .collect::<Vec<_>>();
    ops.sort();
    ops.dedup();
    nomt_core::update::build_trie::<Blake3Hasher>(0, ops, |_| {})
}

fn commit_bad_actuals(name: &str, actuals: Vec<(KeyPath, KeyReadWrite)>) {
    let path = std::path::PathBuf::from("test").join(name);
    let _ = std::fs::remove_dir_all(&path);
    let mut o = Options::new();
    o.path(path);
    o.commit_concurrency(1);
    o.io_workers(1);
    o.bitbox_seed([0; 16]);
    o.hashtable_buckets(4096);
    let nomt = Nomt::<Blake3Hasher>::open(o).unwrap();

    let base = [key(0x00), key(0x80)];
    nomt.begin_session(SessionParams::default())
        .finish(
            base.iter()
                .map(|k| (*k, KeyReadWrite::Write(Some(vec![k[0], 1]))))
                .collect(),
        )
        .unwrap()
        .commit(&nomt)
        .unwrap();

    let mut keys = base.to_vec();
    keys.extend(actuals.iter().map(|(k, _)| *k));

    let finished = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        nomt.begin_session(SessionParams::default()).finish(actuals)
    }));
    let finished = match finished {
        Ok(Ok(finished)) => finished,
        Ok(Err(e)) => return eprintln!("{name}: finish returned Err: {e:#}"),
        Err(_) => return eprintln!("{name}: finish panicked"),
    };
    let finished_root = finished.root();
    finished.commit(&nomt).unwrap();

    assert_eq!(nomt.root(), finished_root);
    for k in &keys {
        eprintln!(
            "{name}: read({:#04x}..) = {:?}",
            k[0],
            nomt.read(*k).unwrap()
        );
    }
    assert_eq!(
        nomt.root().into_inner(),
        root_of_stored_values(&nomt, &keys),
        "finish() accepted the actuals and committed a root that is not the root of the stored values"
    );
}

#[test]
fn audit_a4_3_duplicate_key_in_actuals_without_debug_assertions() {
    // A4-3
    let w = |v: Option<u8>| KeyReadWrite::Write(v.map(|v| vec![v]));
    for (i, k) in [key(0x40), key(0x00)].into_iter().enumerate() {
        for (j, (first, second)) in [(Some(7), None), (None, Some(7)), (Some(7), Some(9))]
            .into_iter()
            .enumerate()
        {
            commit_bad_actuals(
                &format!("audit_a4_3_duplicate_actuals_{i}_{j}"),
                vec![(k, w(first)), (k, w(second))],
            );
        }
    }
}

#[test]
fn audit_a7_10_unsorted_actuals_without_debug_assertions() {
    // A7-10
    commit_bad_actuals(
        "audit_a7_10_unsorted_actuals",
        vec![
            (key(0x41), KeyReadWrite::Write(Some(vec![8]))),
            (key(0x40), KeyReadWrite::Write(Some(vec![7]))),
        ],
    );
}
