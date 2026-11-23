mod common;

use common::Test;
use nomt::{hasher::Blake3Hasher, trie::LeafData, Witness};
use nomt_core::{proof, trie::Node, witness::WitnessedRead};

fn verify_like_example(prev_root: Node, new_root: Node, witness: &Witness) -> Result<(), String> {
    let mut updates = Vec::new();
    for (i, witnessed_path) in witness.path_proofs.iter().enumerate() {
        let verified = witnessed_path
            .inner
            .verify::<Blake3Hasher>(&witnessed_path.path.path(), prev_root)
            .map_err(|e| format!("{e:?}"))?;

        for read in witness
            .operations
            .reads
            .iter()
            .skip_while(|r| r.path_index != i)
            .take_while(|r| r.path_index == i)
        {
            let ok = match read.value {
                None => verified.confirm_nonexistence(&read.key).unwrap(),
                Some(value_hash) => {
                    let leaf = LeafData {
                        key_path: read.key,
                        value_hash,
                    };
                    verified.confirm_value(&leaf).unwrap()
                }
            };
            if !ok {
                return Err("read does not match the proof".to_string());
            }
        }

        let mut write_ops = Vec::new();
        for write in witness
            .operations
            .writes
            .iter()
            .skip_while(|r| r.path_index != i)
            .take_while(|r| r.path_index == i)
        {
            write_ops.push((write.key, write.value));
        }

        if !write_ops.is_empty() {
            updates.push(proof::PathUpdate {
                inner: verified,
                ops: write_ops,
            });
        }
    }

    let root =
        proof::verify_update::<Blake3Hasher>(prev_root, &updates).map_err(|e| format!("{e:?}"))?;
    if root != new_root {
        return Err("new root mismatch".to_string());
    }
    Ok(())
}

#[test]
fn audit_a5_2_example_verifier_skips_out_of_run_reads() {
    // A5-2
    let mut t = Test::new("audit_a5_2_witness_example_pattern");
    for id in 0..8 {
        common::set_balance(&mut t, id, 1000);
    }
    let prev_root = t.commit().0.into_inner();

    for id in 0..4 {
        assert_eq!(common::read_balance(&mut t, id), Some(1000));
    }
    common::set_balance(&mut t, 5, 7);
    let (new_root, mut witness) = t.commit();
    let new_root = new_root.into_inner();

    assert!(witness.path_proofs.len() >= 2);
    assert_eq!(verify_like_example(prev_root, new_root, &witness), Ok(()));

    let forged_key = witness
        .operations
        .reads
        .iter()
        .find(|r| r.path_index == 0)
        .unwrap()
        .key;
    witness.operations.reads.push(WitnessedRead {
        key: forged_key,
        value: Some([0xff; 32]),
        path_index: 0,
    });

    assert!(
        verify_like_example(prev_root, new_root, &witness).is_err(),
        "witness carrying a forged read (value hash ff..ff) was accepted"
    );
}
