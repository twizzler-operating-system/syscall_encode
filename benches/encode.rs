use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use syscall_encode::tests::{test_encode, test_encode_fast, Bar, Foo, NullAbi};

fn bench_normal(bencher: &mut Bencher) {
    let abi = Arc::new(NullAbi::new());
    bencher.iter(|| {
        let foo = Foo::default();
        test_encode(&abi, foo);
    });
}

fn bench_fast(bencher: &mut Bencher) {
    let abi = Arc::new(NullAbi::new());
    bencher.iter(|| {
        let bar = Bar { x: 3, y: 12 };
        test_encode_fast(&abi, bar);
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("encode_normal", |b| bench_normal(b));
    c.bench_function("encode_fast", |b| bench_fast(b));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
