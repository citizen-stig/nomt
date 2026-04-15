mod common;

use common::{account_path, key_diverging_at, Test};
use nomt::{hasher::Blake3Hasher, trie::NodeKind, KeyReadWrite, Value};
use nomt_core::hasher::ValueHasher;
use nomt_core::proof::{verify_multi_proof, verify_multi_proof_update, MultiProof};
use nomt_core::trie::{KeyPath, Node, ValueHash};
use std::path::Path;

#[test]
fn root_on_empty_db() {
    let t = Test::new("compute_root_empty");
    let root = t.root();
    assert_eq!(
        NodeKind::of::<Blake3Hasher>(&root.into_inner()),
        NodeKind::Terminator
    );
}

#[test]
fn root_on_leaf() {
    {
        let mut t = Test::new("compute_root_leaf");
        t.write([1; 32], Some(vec![1, 2, 3]));
        t.commit();
    }

    let t = Test::new_with_params("compute_root_leaf", 1, 1, None, false);
    let root = t.root();
    assert_eq!(
        NodeKind::of::<Blake3Hasher>(&root.into_inner()),
        NodeKind::Leaf
    );
}

#[test]
fn root_on_internal() {
    {
        let mut t = Test::new("compute_root_internal");
        t.write([0; 32], Some(vec![1, 2, 3]));
        t.write([1; 32], Some(vec![1, 2, 3]));
        t.commit();
    }

    let t = Test::new_with_params("compute_root_internal", 1, 1, None, false);
    let root = t.root();
    assert_eq!(
        NodeKind::of::<Blake3Hasher>(&root.into_inner()),
        NodeKind::Internal
    );
}

#[test]
fn simple_roots_match() {
    let accesses = vec![
        ([0; 32], KeyReadWrite::Write(Some(vec![1, 2, 3]))),
        ([1; 32], KeyReadWrite::Write(Some(vec![1, 2, 3]))),
    ];

    test_root_match_with_inputs("simple_roots_match", Vec::new(), &accesses);
}

fn test_root_match_with_inputs(
    name: impl AsRef<Path>,
    prev_data: Vec<(KeyPath, Option<Value>)>,
    accesses: &[(KeyPath, KeyReadWrite)],
) {
    let mut t = Test::new(name);
    {
        for (key_path, write) in prev_data {
            t.write(key_path, write.clone());
        }
        t.commit();
    }
    let prev_root = t.root();
    for (key_path, operation) in accesses {
        match operation {
            KeyReadWrite::Read(y) => {
                let x = t.read(*key_path);
                assert_eq!(&x, y);
            }
            KeyReadWrite::Write(v) => {
                t.write(*key_path, v.clone());
            }
            KeyReadWrite::ReadThenWrite(r, v) => {
                let x = t.read(*key_path);
                assert_eq!(&x, r);
                t.write(*key_path, v.clone());
            }
        }
    }

    let (prover_root, witness) = t.commit();
    let nomt::Witness {
        path_proofs,
        operations: nomt::WitnessedOperations { .. },
    } = witness;
    let mut inner = path_proofs.into_iter().map(|p| p.inner).collect::<Vec<_>>();
    inner.sort_by(|a, b| a.terminal.path().cmp(b.terminal.path()));
    let multi_proof = MultiProof::from_path_proofs(inner);

    let verifier_root = run_verifier(multi_proof, accesses, prev_root.into_inner()).unwrap();

    assert_eq!(
        prover_root.into_inner(),
        verifier_root,
        "Verifier and Prover have mismatched next state roots"
    );
}

fn run_verifier(
    multi_proof: MultiProof,
    accesses: &[(KeyPath, KeyReadWrite)],
    prev_root: Node,
) -> anyhow::Result<Node> {
    let verified = verify_multi_proof::<Blake3Hasher>(&multi_proof, prev_root)
        .expect("multiproof must verify against the prior root");

    let mut updates: Vec<(KeyPath, Option<ValueHash>)> = accesses
        .iter()
        .filter_map(|(k, op)| match op {
            KeyReadWrite::Write(v) | KeyReadWrite::ReadThenWrite(_, v) => {
                Some((*k, v.as_deref().map(Blake3Hasher::hash_value)))
            }
            KeyReadWrite::Read(_) => None,
        })
        .collect();
    updates.sort_by(|a, b| a.0.cmp(&b.0));

    verify_multi_proof_update::<Blake3Hasher>(&verified, updates)
        .map_err(|e| anyhow::anyhow!("Failed to verify_multi_proof_update: {e:?}"))
}

fn run_depth_sweep_case(name: &str, depth: usize) {
    let k0 = key_diverging_at(depth, false);
    let k1 = key_diverging_at(depth, true);

    // Sanity: the pair differs in exactly one bit, at MSB-position `depth`.
    let xor: Vec<u8> = k0.iter().zip(k1.iter()).map(|(a, b)| a ^ b).collect();
    let set_bits: u32 = xor.iter().map(|b| b.count_ones()).sum();
    assert_eq!(set_bits, 1, "keys should differ in exactly one bit");
    let diverging_byte = depth / 8;
    let diverging_mask = 1u8 << (7 - (depth % 8));
    assert_eq!(
        xor[diverging_byte], diverging_mask,
        "divergence should be at MSB-position {depth}"
    );

    let (k_lo, k_hi) = if k0 < k1 { (k0, k1) } else { (k1, k0) };
    let accesses = vec![
        (k_lo, KeyReadWrite::Write(Some(vec![0xAA]))),
        (k_hi, KeyReadWrite::Write(Some(vec![0xBB]))),
    ];
    test_root_match_with_inputs(name, Vec::new(), &accesses);
}

macro_rules! depth_sweep_test {
    ($name:ident, $depth:expr) => {
        #[test]
        fn $name() {
            run_depth_sweep_case(stringify!($name), $depth);
        }
    };
}

depth_sweep_test!(depth_sweep_d0, 0);
depth_sweep_test!(depth_sweep_d1, 1);
depth_sweep_test!(depth_sweep_d7, 7);
depth_sweep_test!(depth_sweep_d8, 8);
depth_sweep_test!(depth_sweep_d15, 15);
depth_sweep_test!(depth_sweep_d16, 16);
depth_sweep_test!(depth_sweep_d127, 127);
depth_sweep_test!(depth_sweep_d255, 255);

#[test]
fn overwrite_and_empty_value() {
    let k_a = key_diverging_at(16, false);
    let k_b = key_diverging_at(16, true);
    let prev = vec![
        (k_a, Some(vec![1, 2, 3])),
        (k_b, Some(vec![9, 9, 9])),
    ];
    let accesses = vec![
        (k_a, KeyReadWrite::Write(Some(vec![1, 2, 3]))), // idempotent same-value overwrite
        (k_b, KeyReadWrite::Write(Some(vec![]))),        // empty value, distinct from None
    ];
    test_root_match_with_inputs("overwrite_and_empty_value", prev, &accesses);
}

#[test]
fn delete_collapses_internal_to_leaf() {
    let k_a = key_diverging_at(16, false);
    let k_b = key_diverging_at(16, true);
    let prev = vec![
        (k_a, Some(vec![0xAA])),
        (k_b, Some(vec![0xBB])),
    ];
    let accesses = vec![(k_b, KeyReadWrite::Write(None))];
    test_root_match_with_inputs("delete_collapses_internal_to_leaf", prev, &accesses);
}

#[test]
fn delete_last_key_to_terminator() {
    let k = key_diverging_at(32, true);
    let prev = vec![(k, Some(vec![0xAA]))];
    let accesses = vec![(k, KeyReadWrite::Write(None))];
    test_root_match_with_inputs("delete_last_key_to_terminator", prev, &accesses);
}

#[test]
fn delete_nonexistent_key() {
    let k_a = key_diverging_at(8, false);
    let k_b = key_diverging_at(8, true); // not in prev_data
    let prev = vec![(k_a, Some(vec![0xAA]))];
    let accesses = vec![(k_b, KeyReadWrite::Write(None))];
    test_root_match_with_inputs("delete_nonexistent_key", prev, &accesses);
}

#[test]
fn read_then_write_mixed() {
    let k0 = key_diverging_at(0, true);
    let k1 = key_diverging_at(8, true);
    let k2 = key_diverging_at(64, true);
    let k_missing = key_diverging_at(128, true);
    let v0 = vec![0xA0];
    let v1 = vec![0xA1];
    let v2 = vec![0xA2];
    let prev = vec![
        (k0, Some(v0.clone())),
        (k1, Some(v1.clone())),
        (k2, Some(v2.clone())),
    ];
    let accesses = vec![
        (k0, KeyReadWrite::Read(Some(v0))),
        (k1, KeyReadWrite::ReadThenWrite(Some(v1), Some(vec![0xB1]))),
        (k_missing, KeyReadWrite::Read(None)),
    ];
    test_root_match_with_inputs("read_then_write_mixed", prev, &accesses);
}

#[test]
fn cluster_asymmetric_tree() {
    let mk = |first_byte: u8| {
        let mut k = KeyPath::default();
        k[0] = first_byte;
        k
    };
    let accesses = vec![
        (mk(0x10), KeyReadWrite::Write(Some(vec![1]))),
        (mk(0x20), KeyReadWrite::Write(Some(vec![2]))),
        (mk(0x40), KeyReadWrite::Write(Some(vec![3]))),
        (mk(0xA0), KeyReadWrite::Write(Some(vec![4]))),
    ];
    test_root_match_with_inputs("cluster_asymmetric_tree", Vec::new(), &accesses);
}

#[test]
fn same_key_writes_in_batch() {
    let k = key_diverging_at(24, false);
    let k_other = key_diverging_at(24, true);
    let prev = vec![(k_other, Some(vec![0xCC]))];
    // Two writes to the same key in one batch; harness HashMap + verifier BTreeMap both
    // keep the last write.
    let accesses = vec![
        (k, KeyReadWrite::Write(Some(vec![1]))),
        (k, KeyReadWrite::Write(Some(vec![2]))),
    ];
    test_root_match_with_inputs("same_key_writes_in_batch", prev, &accesses);
}

#[test]
fn many_keys_round_trip() {
    let prev: Vec<_> = (0..32)
        .map(|i| (account_path(i), Some(vec![i as u8, 0x01])))
        .collect();
    let mut accesses: Vec<(KeyPath, KeyReadWrite)> = Vec::new();
    // Insert 16 new keys.
    for i in 32..48 {
        accesses.push((
            account_path(i),
            KeyReadWrite::Write(Some(vec![i as u8, 0x02])),
        ));
    }
    // Overwrite 8 existing keys.
    for i in 0..8 {
        accesses.push((
            account_path(i),
            KeyReadWrite::Write(Some(vec![i as u8, 0x03])),
        ));
    }
    // Delete 8 existing keys.
    for i in 8..16 {
        accesses.push((account_path(i), KeyReadWrite::Write(None)));
    }
    test_root_match_with_inputs("many_keys_round_trip", prev, &accesses);
}

#[test]
fn many_keys_inserts_only() {
    let prev: Vec<_> = (0..32)
        .map(|i| (account_path(i), Some(vec![i as u8, 0x01])))
        .collect();
    let accesses: Vec<(KeyPath, KeyReadWrite)> = (32..48)
        .map(|i| {
            (
                account_path(i),
                KeyReadWrite::Write(Some(vec![i as u8, 0x02])),
            )
        })
        .collect();
    test_root_match_with_inputs("many_keys_inserts_only", prev, &accesses);
}

#[test]
fn many_keys_overwrites_only() {
    let prev: Vec<_> = (0..32)
        .map(|i| (account_path(i), Some(vec![i as u8, 0x01])))
        .collect();
    let accesses: Vec<(KeyPath, KeyReadWrite)> = (0..8)
        .map(|i| {
            (
                account_path(i),
                KeyReadWrite::Write(Some(vec![i as u8, 0x03])),
            )
        })
        .collect();
    test_root_match_with_inputs("many_keys_overwrites_only", prev, &accesses);
}

#[test]
fn many_keys_deletes_only() {
    let prev: Vec<_> = (0..32)
        .map(|i| (account_path(i), Some(vec![i as u8, 0x01])))
        .collect();
    let accesses: Vec<(KeyPath, KeyReadWrite)> = (8..16)
        .map(|i| (account_path(i), KeyReadWrite::Write(None)))
        .collect();
    test_root_match_with_inputs("many_keys_deletes_only", prev, &accesses);
}