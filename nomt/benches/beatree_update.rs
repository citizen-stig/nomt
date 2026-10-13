use criterion::{criterion_group, criterion_main, Criterion};

fn benchmark(c: &mut Criterion) {
    // TMPDIR selects the filesystem whose writeout/durability cost is measured.
    let dir = tempfile::tempdir().unwrap();
    nomt::beatree::update_bench::benchmark(c, dir.path());
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
