use nomt_core::{
    hasher::Blake3Hasher,
    proof::{verify_multi_proof, MultiProof, PathProof, PathProofTerminal},
    trie::TERMINATOR,
    trie_pos::TriePosition,
};

#[test]
fn audit_a5_1_multiproof_from_proofs_sharing_a_terminal() {
    // A5-1
    let proof_of_absence = PathProof {
        terminal: PathProofTerminal::Terminator(TriePosition::new()),
        siblings: vec![],
    };
    let multi = MultiProof::from_path_proofs(vec![proof_of_absence.clone(), proof_of_absence]);
    let verified = verify_multi_proof::<Blake3Hasher>(&multi, TERMINATOR).unwrap();
    assert!(verified.confirm_nonexistence(&[0x00; 32]).unwrap());
    assert!(verified.confirm_nonexistence(&[0xff; 32]).unwrap());
}
