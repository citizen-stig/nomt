use super::Delta;
use std::io::Cursor;

// A6-7: a delta record with bytes left over after the two arrays must be rejected.
#[test]
fn audit_a6_7_delta_decode_ignores_trailing_bytes() {
    let mut delta = Delta {
        priors: Default::default(),
    };
    delta.priors.insert([1; 32], Some(vec![7; 8]));
    let mut bytes = delta.encode();
    assert!(Delta::decode(&mut Cursor::new(&bytes)).is_ok());

    bytes.extend_from_slice(&[0xAB; 37]);
    assert!(
        Delta::decode(&mut Cursor::new(&bytes)).is_err(),
        "decode accepted a record with 37 trailing bytes"
    );
}
