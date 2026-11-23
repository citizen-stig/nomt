use nomt_core::page_id::{ChildPageIndex, PageId, MAX_PAGE_DEPTH, ROOT_PAGE_ID};

fn page_id(first: u8, depth: usize) -> PageId {
    let mut id = ROOT_PAGE_ID
        .child_page_id(ChildPageIndex::new(first).unwrap())
        .unwrap();
    for _ in 1..depth {
        id = id.child_page_id(ChildPageIndex::new(0).unwrap()).unwrap();
    }
    id
}

#[test]
fn audit_a1_8_page_id_encode_collides_at_max_depth() {
    // A1-8
    let a = page_id(0, MAX_PAGE_DEPTH);
    let b = page_id(16, MAX_PAGE_DEPTH);
    assert_ne!(a, b);
    assert_ne!(
        a.encode(),
        b.encode(),
        "depth-42 ids [0,0,..] and [16,0,..]"
    );

    let c = page_id(15, MAX_PAGE_DEPTH);
    let d = page_id(0, MAX_PAGE_DEPTH - 1);
    assert_ne!(
        c.encode(),
        d.encode(),
        "depth-42 [15,0,..] and depth-41 [0,..]"
    );
}
