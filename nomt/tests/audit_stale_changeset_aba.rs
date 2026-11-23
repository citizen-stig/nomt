use bitvec::prelude::*;
use nomt::{
    hasher::Blake3Hasher,
    trie::{KeyPath, LeafData},
    FinishedSession, KeyReadWrite, Nomt, Options, Root, SessionParams,
};
use nomt_core::hasher::ValueHasher;
use std::path::PathBuf;

fn open(name: &str, clean: bool, buckets: u32) -> Nomt<Blake3Hasher> {
    let path = {
        let mut p = PathBuf::from("test");
        p.push(name);
        p
    };
    if clean && path.exists() {
        std::fs::remove_dir_all(&path).unwrap();
    }
    let mut o = Options::new();
    o.path(path);
    o.commit_concurrency(1);
    o.bitbox_seed([0; 16]);
    o.hashtable_buckets(buckets);
    o.rollback(true);
    Nomt::open(o).unwrap()
}

type Writes = Vec<(KeyPath, Option<Vec<u8>>)>;

fn finish(nomt: &Nomt<Blake3Hasher>, mut writes: Writes) -> FinishedSession {
    writes.sort();
    let session = nomt.begin_session(SessionParams::default());
    session
        .finish(
            writes
                .into_iter()
                .map(|(k, v)| (k, KeyReadWrite::Write(v)))
                .collect(),
        )
        .unwrap()
}

fn commit(nomt: &Nomt<Blake3Hasher>, writes: Writes) -> Root {
    finish(nomt, writes).commit(nomt).unwrap();
    nomt.root()
}

fn pk(b1: u8, b2: u8) -> KeyPath {
    let mut k = [0u8; 32];
    k[1] = b1 & 0x0f;
    k[2] = b2;
    k
}

fn top(b0: u8) -> KeyPath {
    let mut k = [0u8; 32];
    k[0] = b0;
    k
}

fn assert_proves(nomt: &Nomt<Blake3Hasher>, key: KeyPath, value: &[u8]) {
    let root = nomt.root().into_inner();
    let session = nomt.begin_session(SessionParams::default());
    let proof = session.prove(key).unwrap();
    let verified = proof
        .verify::<Blake3Hasher>(key.view_bits::<Msb0>(), root)
        .unwrap_or_else(|e| panic!("proof for {key:02x?} does not verify against root: {e:?}"));
    let leaf = LeafData {
        key_path: key,
        value_hash: <Blake3Hasher as ValueHasher>::hash_value(value),
    };
    assert!(
        verified.confirm_value(&leaf).unwrap(),
        "proof for {key:02x?} does not show the committed value"
    );
    assert_eq!(session.read(key).unwrap().as_deref(), Some(value));
}

#[test]
fn audit_a4_1_stale_session_duplicates_fresh_page_after_rollback() {
    // A4-1
    a4_1("audit_a4_1_control", false);
    a4_1("audit_a4_1_stale_session_aba", true);
}

fn a4_1(name: &str, interleave: bool) {
    let nomt = open(name, true, 64_000);

    let mut state: Writes = (0..19u8).map(|i| (pk(i, i), Some(vec![i; 8]))).collect();
    state.push((top(0x40), Some(vec![1])));
    state.push((top(0x80), Some(vec![2])));
    let r = commit(&nomt, state.clone());

    let k20a = pk(0x0f, 0xa0);
    let k20b = pk(0x0f, 0xb0);
    let fa = finish(&nomt, vec![(k20a, Some(vec![0xaa; 8]))]);
    let fa_root = fa.root();

    if interleave {
        commit(&nomt, vec![(k20b, Some(vec![0xbb; 8]))]);
        nomt.rollback(1).unwrap();
    }
    assert_eq!(nomt.root(), r);

    if fa.commit(&nomt).is_err() {
        return;
    }
    state.push((k20a, Some(vec![0xaa; 8])));

    drop(nomt);
    let nomt = open(name, false, 64_000);
    assert_eq!(nomt.root(), fa_root);
    for (k, v) in &state {
        assert_proves(&nomt, *k, v.as_ref().unwrap());
    }
}

#[test]
fn audit_a7_1_stale_session_rewrites_parent_with_stale_elision_bit() {
    // A7-1
    a7_1("audit_a7_1_control", false);
    a7_1("audit_a7_1_stale_session_aba", true);
}

fn a7_1(name: &str, interleave: bool) {
    let nomt = open(name, true, 64_000);

    let mut state: Writes = (0..20u8).map(|i| (pk(i, i), Some(vec![i; 8]))).collect();
    state.extend((1..4u8).map(|i| (top(i), Some(vec![i; 8]))));
    commit(&nomt, state);
    commit(&nomt, (5..20u8).map(|i| (pk(i, i), None)).collect());

    let b = finish(&nomt, vec![(top(1), Some(vec![0x11; 8]))]);

    if interleave {
        commit(&nomt, (0..5u8).map(|i| (pk(i, i), None)).collect());
        nomt.rollback(1).unwrap();
    }
    assert_eq!(nomt.root(), b.prev_root());

    if b.commit(&nomt).is_err() {
        return;
    }

    for i in 0..5u8 {
        assert_proves(&nomt, pk(i, i), &[i; 8]);
    }
}

#[test]
fn audit_a2_2_stale_overlay_writes_page_into_tombstoned_bucket() {
    // A2-2
    a2_2("audit_a2_2_control", false);
    a2_2("audit_a2_2_stale_overlay_aba", true);
}

fn a2_2(name: &str, interleave: bool) {
    let nomt = open(name, true, 64_000);

    let mut state: Writes = Vec::new();
    for b1 in 0..0x0cu8 {
        for b2 in [0x00u8, 0x80] {
            state.push((pk(b1, b2), Some(vec![b1, b2])));
        }
    }
    state.push((top(0x40), Some(vec![1])));
    state.push((top(0x80), Some(vec![2])));
    commit(&nomt, state.clone());

    let k1 = pk(0x00, 0x00);
    let k2 = pk(0x08, 0x00);
    let r0 = commit(
        &nomt,
        state
            .iter()
            .filter(|(k, _)| k[0] == 0 && *k != k1 && *k != k2)
            .map(|(k, _)| (*k, None))
            .collect(),
    );

    let x = finish(&nomt, vec![(k1, Some(vec![0xee; 4]))]).into_overlay();
    let x_root = x.root();

    if interleave {
        commit(&nomt, vec![(k1, None), (k2, None)]);
        commit(&nomt, vec![(k1, Some(vec![0, 0])), (k2, Some(vec![8, 0]))]);
    }
    assert_eq!(nomt.root(), r0);

    if x.commit(&nomt).is_err() {
        return;
    }

    drop(nomt);
    let nomt = open(name, false, 64_000);
    assert_eq!(nomt.root(), x_root);
    assert_proves(&nomt, k1, &[0xee; 4]);
    assert_proves(&nomt, k2, &[8, 0]);
}

#[test]
fn audit_a6_1_stale_session_writes_to_stale_buckets_after_rollback() {
    // A6-1
    a6_1("audit_a6_1_control", false);
    a6_1("audit_a6_1_stale_session_aba", true);
}

fn a6_1(name: &str, interleave: bool) {
    let nomt = open(name, true, 128);

    let keys = |j: u8| {
        let mut a = top(j << 2);
        a[1] = 0x55;
        let mut b = top((j << 2) | 0x02);
        b[1] = 0x55;
        [a, b]
    };

    for batch in (0..64u8).rev().collect::<Vec<_>>().chunks(8) {
        commit(
            &nomt,
            batch
                .iter()
                .flat_map(|j| keys(*j))
                .map(|k| (k, Some(vec![k[0]; 8])))
                .collect(),
        );
    }
    let r0 = nomt.root();

    let a = finish(
        &nomt,
        (0..64u8)
            .map(|j| (keys(j)[0], Some(vec![0xa5; 8])))
            .collect(),
    );
    let a_root = a.root();

    if interleave {
        commit(&nomt, (0..64u8).flat_map(keys).map(|k| (k, None)).collect());
        nomt.rollback(1).unwrap();
    }
    assert_eq!(nomt.root(), r0);

    if a.commit(&nomt).is_err() {
        return;
    }

    drop(nomt);
    let nomt = open(name, false, 128);
    assert_eq!(nomt.root(), a_root);
    for j in 0..64u8 {
        let [ka, kb] = keys(j);
        assert_proves(&nomt, ka, &[0xa5; 8]);
        assert_proves(&nomt, kb, &[kb[0]; 8]);
    }
}
