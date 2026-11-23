use super::{open, segment_filename, SegmentedLog};
use std::{fs::File, path::Path, sync::Arc};

fn open_log(dir: &Path, start_live: u64, end_live: u64) -> anyhow::Result<SegmentedLog> {
    open(
        dir.to_path_buf(),
        Arc::new(File::open(dir)?),
        "test".to_string(),
        1,
        start_live.into(),
        end_live.into(),
        |_, _| Ok(()),
    )
}

fn four_single_record_segments(dir: &Path) {
    let mut log = open_log(dir, 0, 0).unwrap();
    for i in 0..4u8 {
        log.append(&[i; 10]).unwrap();
    }
    drop(log);
    for id in 1..=4 {
        assert!(dir.join(segment_filename::format("test", id)).exists());
    }
}

// A6-6: recovery interrupted between the unlinks of two dead trailing segments must be resumable.
#[test]
fn audit_a6_6_interrupted_dead_segment_removal_blocks_open() {
    let control = tempfile::TempDir::new().unwrap();
    four_single_record_segments(control.path());
    open_log(control.path(), 1, 2).expect("control: uninterrupted recovery");

    let dir = tempfile::TempDir::new().unwrap();
    four_single_record_segments(dir.path());
    std::fs::remove_file(dir.path().join(segment_filename::format("test", 3))).unwrap();

    if let Err(e) = open_log(dir.path(), 1, 2) {
        panic!("open after an interrupted dead-segment removal failed: {e:#}");
    }
}
