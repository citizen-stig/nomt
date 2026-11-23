use std::sync::Arc;

use super::branch_updater::{
    tests::{make_branch, prefixed_key},
    BaseBranch, BranchGauge, BranchUpdater, DigestResult, HandleNewBranch,
};
use crate::beatree::{
    allocator::PageNumber,
    branch::{node::get_key, BranchNode, BRANCH_NODE_BODY_SIZE},
    ops::bit_ops::separator_len,
    Key,
};
use crate::io::PagePool;

#[derive(Default)]
struct Collect(Vec<(Key, BranchNode)>);

impl HandleNewBranch for Collect {
    fn handle_new_branch(
        &mut self,
        separator: Key,
        node: BranchNode,
        _cutoff: Option<Key>,
    ) -> std::io::Result<()> {
        self.0.push((separator, node));
        Ok(())
    }
}

fn gauge_body_size(keys: impl Iterator<Item = Key>) -> usize {
    let mut gauge = BranchGauge::default();
    for k in keys {
        gauge.ingest_key(k, separator_len(&k));
    }
    gauge.body_size()
}

fn set_bit(key: &mut Key, bit: usize) {
    key[bit / 8] |= 0x80 >> (bit % 8);
}

fn rebuild_with_tail(base: Vec<(Key, usize)>, tail: (Key, u32)) -> BranchNode {
    let pool = PagePool::new();
    let mut updater = BranchUpdater::new(pool, Some(BaseBranch::new(make_branch(base))), None);
    updater.ingest(tail.0, Some(PageNumber(tail.1)));
    let mut out = Collect::default();
    let DigestResult::Finished = updater.digest(&mut out).unwrap() else {
        panic!("unexpected NeedsMerge")
    };
    assert_eq!(out.0.len(), 1);
    out.0.pop().unwrap().1
}

fn assert_node_matches(node: &BranchNode, expected: &[(Key, u32)]) {
    assert_eq!(node.n() as usize, expected.len());
    for (i, (key, pn)) in expected.iter().enumerate() {
        assert_eq!(
            node.node_pointer(i),
            *pn,
            "node_pointer({i}) changed (n = {})",
            node.n()
        );
        assert_eq!(get_key(node, i), *key, "separator {i} changed");
    }
}

#[test]
fn audit_a1_1_first_separator_oversized_on_prefix_shrink() {
    // A1-1
    let mut base = vec![([0u8; 32], 4096usize)];
    for i in 0..398usize {
        let mut k = [0u8; 32];
        k[1] = 0x10 | (i >> 8) as u8;
        k[2] = i as u8;
        let len = 43 + (i < 343) as usize;
        set_bit(&mut k, len - 1);
        assert_eq!(separator_len(&k), len);
        base.push((k, 5000 + i));
    }
    let mut tail = [0u8; 32];
    tail[1] = 0x20;

    let mut expected: Vec<(Key, u32)> = base.iter().map(|(k, pn)| (*k, *pn as u32)).collect();
    expected.push((tail, 9999));

    assert_eq!(
        gauge_body_size(expected.iter().map(|(k, _)| *k)),
        BRANCH_NODE_BODY_SIZE
    );

    let node = rebuild_with_tail(base, (tail, 9999));
    assert_eq!(node.prefix_len(), 10);
    assert_node_matches(&node, &expected);
}

#[test]
fn audit_a3_2_gauge_undercounts_kept_short_first_separator() {
    // A3-2
    let mut k0 = [0u8; 32];
    k0[0] = 0x80;
    let mut tail = [0u8; 32];
    tail[0] = 0xC0;
    let mid = |i: usize| {
        let mut k = k0;
        k[16..18].copy_from_slice(&(i as u16).to_be_bytes());
        k
    };

    let mut found = None;
    'search: for m in 100..250usize {
        for ext in (143..256).rev() {
            let mut keys = vec![k0];
            keys.extend((1..=m).map(mid));
            if ext > 143 {
                set_bit(&mut keys[m], ext);
            }
            keys.push(tail);
            if gauge_body_size(keys.iter().copied()) == BRANCH_NODE_BODY_SIZE {
                found = Some(keys);
                break 'search;
            }
        }
    }
    let keys = found.expect("no exactly-full configuration found");

    let expected: Vec<(Key, u32)> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (*k, 70_000 + i as u32))
        .collect();
    let base = expected[..expected.len() - 1]
        .iter()
        .map(|(k, pn)| (*k, *pn as usize))
        .collect();

    let node = rebuild_with_tail(base, *expected.last().unwrap());
    assert_eq!(node.prefix_len(), 1);
    assert_node_matches(&node, &expected);
}

#[test]
fn audit_a1_2_carried_prefix_truncated_on_large_prefix_shrink() {
    // A1-2
    let mut expected = Vec::new();
    for i in 0..8u8 {
        let mut k = [0u8; 32];
        k[0] = 0x07;
        k[1..8].fill(0xff);
        k[8] = 0xf1 + 2 * i;
        expected.push((k, 100 + i as u32));
    }
    let base = expected.iter().map(|(k, pn)| (*k, *pn as usize)).collect();
    let mut tail = [0u8; 32];
    tail[0] = 0x08;
    expected.push((tail, 99));

    let node = rebuild_with_tail(base, (tail, 99));
    assert_eq!(node.prefix_len(), 4);
    assert_node_matches(&node, &expected);
}

#[test]
fn audit_a1_3_stale_source_len_drops_separator_bits() {
    // A1-3
    let mut k0 = [0u8; 32];
    k0[0] = 0x40;
    let mut k1 = [0u8; 32];
    k1[..9].copy_from_slice(&[0xbd, 0x9b, 0xa9, 0x28, 0xdd, 0x85, 0x46, 0xd8, 0xb0]);
    let mut k2 = [0u8; 32];
    k2[..16].copy_from_slice(&[
        0xbd, 0x9b, 0xa9, 0x28, 0xdd, 0x85, 0x46, 0xd8, 0xc4, 0x00, 0x78, 0x61, 0xb5, 0x4b, 0xb3,
        0x20,
    ]);

    let pool = PagePool::new();
    let base = make_branch(vec![(k0, 10), (k1, 11), (k2, 12)]);
    let mut updater = BranchUpdater::new(pool, Some(BaseBranch::new(base)), None);
    updater.ingest(k0, None);
    let mut out = Collect::default();
    let DigestResult::Finished = updater.digest(&mut out).unwrap() else {
        panic!("unexpected NeedsMerge")
    };
    assert_eq!(out.0.len(), 1);
    let node = &out.0[0].1;
    assert_eq!(node.prefix_len(), 65);
    assert_node_matches(node, &[(k1, 11), (k2, 12)]);
}

#[test]
fn audit_a3_3_keep_chunk_starting_in_uncompressed_tail() {
    // A3-3
    let key = |i| prefixed_key(0x00, 24, i);
    let key2 = |i| prefixed_key(0xff, 24, i);
    let left = make_branch((0..200).map(|i| (key(i), i)).collect());
    let right = make_branch((0..200).map(|i| (key2(i), 1000 + i)).collect());

    let pool = PagePool::new();
    let mut updater = BranchUpdater::new(pool.clone(), Some(BaseBranch::new(left)), Some(key2(0)));
    let mut out = Collect::default();
    let DigestResult::NeedsMerge(_) = updater.digest(&mut out).unwrap() else {
        panic!("expected NeedsMerge")
    };
    updater.reset_base(Some(BaseBranch::new(right)), None);
    let DigestResult::Finished = updater.digest(&mut out).unwrap() else {
        panic!("unexpected NeedsMerge")
    };
    out.0.sort_by_key(|(sep, _)| *sep);
    let node = Arc::new(out.0.remove(0).1);
    let n = node.n() as usize;
    let pc = node.prefix_compressed() as usize;
    assert!(
        pc + 2 < n,
        "need two uncompressed tail separators: pc={pc} n={n}"
    );

    let mut expected: Vec<(Key, u32)> = (0..n)
        .map(|i| (get_key(&node, i), node.node_pointer(i)))
        .collect();
    expected[pc].1 = 424242;

    let mut updater = BranchUpdater::new(pool, Some(BaseBranch::new(node)), None);
    updater.ingest(expected[pc].0, Some(PageNumber(424242)));
    let mut out = Collect::default();
    let DigestResult::Finished = updater.digest(&mut out).unwrap() else {
        panic!("unexpected NeedsMerge")
    };
    assert_eq!(out.0.len(), 1);
    assert_node_matches(&out.0[0].1, &expected);
}
