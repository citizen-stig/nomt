mod common;

use common::Test;
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
