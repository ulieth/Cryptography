#[macro_use]
extern crate criterion;
extern crate shamirs_secret_sharing;
extern crate num_bigint;

use criterion::{Criterion, BenchmarkGroup};
use shamirs_secret_sharing::*;
use num_bigint::BigInt;

use std::str::FromStr;

mod mod_inverse_benches {
  use super::*;

  pub fn bench_modular_inv(c: &mut Criterion) {
    println!("Running modular inverse benchmarks...");
    let modul1 = BigInt::from_str("7237005577332262213973186563042994240857116359379907606001950938285454250989").unwrap();
    let d1 = BigInt::from_str("182687704666362864775460604089535377456991567872").unwrap();

    let mut group: BenchmarkGroup<_> = c.benchmark_group("Modular Inverse");

    group.bench_with_input("Fermat's inverse", &d1, |b, d| {
        b.iter(|| fermat_inverse(d, &modul1))
    });

    group.finish();
  }
}

criterion_group!(benches, mod_inverse_benches::bench_modular_inv);
criterion_main!(benches);
