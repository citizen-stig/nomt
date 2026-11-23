mod common;
use common::Test;

#[rustfmt::skip]
const KEYS_AND_VALUE_SIZES: [(u8, usize); 14] = [
    (1, 950), (2, 950), (3, 1200),
    (4, 1100), (5, 1100), (6, 440), (7, 440),
    (8, 1332), (9, 1200), (10, 430), (11, 32),
    (12, 1000), (13, 1000), (14, 1000),
];

const TO_DELETE: [u8; 3] = [3, 4, 5];

fn key(id: u8) -> [u8; 32] {
    let mut key = [0; 32];
    key[0] = id;
    key
}

fn missing_after_delete(name: &str, commit_concurrency: usize) -> Vec<u8> {
    let mut t = Test::new_with_params(name, commit_concurrency, 64_000, None, true);

    for (k, value_size) in KEYS_AND_VALUE_SIZES {
        t.write(key(k), Some(vec![k; value_size]));
    }
    t.commit();

    for k in TO_DELETE {
        t.write(key(k), None);
    }
    t.commit();

    KEYS_AND_VALUE_SIZES
        .iter()
        .filter(|(k, _)| !TO_DELETE.contains(k))
        .filter(|(k, value_size)| t.read(key(*k)) != Some(vec![*k; *value_size]))
        .map(|(k, _)| *k)
        .collect()
}

#[test]
fn audit_a3_1_range_extension_overwrites_inserted_leaf() {
    // A3-1
    assert_eq!(
        missing_after_delete("audit_a3_1_one_worker", 1),
        Vec::<u8>::new(),
        "control: commit_concurrency = 1"
    );
    assert_eq!(
        missing_after_delete("audit_a3_1_two_workers", 2),
        Vec::<u8>::new(),
        "untouched keys lost with commit_concurrency = 2"
    );
}
