mod common;

use common::Test;
use nomt::{
    hasher::{Blake3Hasher, NodeHasher, ValueHasher},
    trie::{InternalData, LeafData},
    PanicOnSyncMode,
};

fn leaf(first: u8, value: u8) -> [u8; 32] {
    Blake3Hasher::hash_leaf(&LeafData {
        key_path: key(first),
        value_hash: Blake3Hasher::hash_value(&[value]),
    })
}

fn internal(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    Blake3Hasher::hash_internal(&InternalData { left, right })
}

fn key(first: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = first;
    k
}

fn swap_subtrees(t: &mut Test) {
    t.write(key(0x00), None);
    t.write(key(0x40), None);
    t.write(key(0x80), Some(vec![3]));
    t.write(key(0xC0), Some(vec![4]));
}

fn seed(name: &str) {
    let mut t = Test::new_with_params(name, 1, 64_000, None, true);
    t.write(key(0x00), Some(vec![1]));
    t.write(key(0x40), Some(vec![2]));
    t.commit();
}

// A2-1: a commit that reaches the meta write must recover to the root it computed.
#[test]
fn audit_a2_1_wal_drops_cleared_then_uncleared_node() {
    let control = "audit_a2_1_control";
    seed(control);
    let mut t = Test::new_with_params(control, 1, 64_000, None, false);
    swap_subtrees(&mut t);
    let (expected_root, _) = t.commit();
    drop(t);
    let t = Test::new_with_params(control, 1, 64_000, None, false);
    assert_eq!(t.root(), expected_root, "control: clean commit and reopen");
    drop(t);

    let name = "audit_a2_1_crash";
    seed(name);
    let mut t = Test::new_with_params(name, 1, 64_000, Some(PanicOnSyncMode::PostMeta), false);
    swap_subtrees(&mut t);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        t.commit();
    }));
    assert!(r.is_err());
    drop(t);

    let mut t = Test::new_with_params(name, 1, 64_000, None, false);
    let recovered_root = t.root();
    assert_eq!(t.read(key(0x00)), None);
    assert_eq!(t.read(key(0x40)), None);
    assert_eq!(t.read(key(0x80)), Some(vec![3]));
    assert_eq!(t.read(key(0xC0)), Some(vec![4]));
    let stale_root = internal(
        internal(leaf(0x00, 1), leaf(0x40, 2)),
        internal(leaf(0x80, 3), leaf(0xC0, 4)),
    );
    eprintln!(
        "recovered root equals H(stale node0, new node1): {}",
        recovered_root.into_inner() == stale_root
    );
    assert_eq!(
        recovered_root, expected_root,
        "values of the commit are durable, but WAL recovery produced a different root"
    );
}
