use crate::{
    beatree::{
        branch::{node::get_key, BranchNode, BranchNodeBuilder},
        ops::bit_ops::separator_len,
    },
    io::PagePool,
};
use std::sync::Arc;

// A1-6: run under Miri (Stacked Borrows trips on the shared derefs, Tree Borrows on cells_mut).
#[test]
fn audit_a1_6_fatpage_deref_and_cells_mut_aliasing() {
    let pool = PagePool::new();

    let mut page = pool.alloc_fat_page();
    page.fill(7);
    let page = Arc::new(page);
    let first: &[u8] = &page;
    let other = page.clone();
    std::thread::spawn(move || assert_eq!(other[0], 7))
        .join()
        .unwrap();
    assert_eq!(first[0], 7);

    let mut keys = vec![[0u8; 32]; 10];
    for (i, key) in keys.iter_mut().enumerate() {
        key[0] = 0x11;
        if i != 0 {
            key[1] = 128;
            key[2] = i as u8;
        }
    }
    let mut builder = BranchNodeBuilder::new(BranchNode::new_in(&pool), 10, 10, 8);
    for (i, k) in keys.iter().enumerate() {
        builder.push(*k, separator_len(k), i as u32);
    }
    let base = builder.finish();

    let mut builder = BranchNodeBuilder::new(BranchNode::new_in(&pool), 3, 3, 8);
    builder.push_chunk(&base, 1, 4, [].into_iter());
    let branch = builder.finish();
    assert_eq!(get_key(&branch, 0), keys[1]);
    assert_eq!(get_key(&branch, 1), keys[2]);
    assert_eq!(get_key(&branch, 2), keys[3]);
}
