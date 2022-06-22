#[macro_use]
extern crate criterion;
extern crate core;
extern crate rand;
extern crate xorf;

use core::convert::TryFrom;
use criterion::{black_box, Criterion};
use rand::Rng;
use xorf::BinaryFuse8;

const SAMPLE_SIZE: u32 = 100_000;

fn custom(c: &mut Criterion) {
    let mut group = c.benchmark_group("custom");

    let mut rng = rand::thread_rng();
    let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();
    let filter = BinaryFuse8::try_from(&keys).unwrap();

    group.bench_function("serialize", |b| {
        b.iter(|| black_box(filter.to_bytes()));
    });

    let encoded = filter.to_bytes();
    group.bench_function("deserialize", |b| {
        b.iter(|| black_box(BinaryFuse8::try_from_bytes(&encoded).unwrap()));
    });
    group.finish();
}

fn bincode(c: &mut Criterion) {
    let mut group = c.benchmark_group("bincode");

    let mut rng = rand::thread_rng();
    let keys: Vec<u64> = (0..SAMPLE_SIZE).map(|_| rng.gen()).collect();
    let filter = BinaryFuse8::try_from(&keys).unwrap();

    group.bench_function("serialize", |b| {
        b.iter(|| black_box(bincode::serialize(&filter).unwrap()));
    });

    let encoded = bincode::serialize(&filter).unwrap();
    group.bench_function("deserialize", |b| {
        b.iter(|| black_box(bincode::deserialize::<BinaryFuse8>(&encoded).unwrap()));
    });
    group.finish();
}

criterion_group!(serde, custom, bincode);
criterion_main!(serde);
