#[macro_use]
extern crate criterion;
extern crate shamirs_secret_sharing;
extern crate num_bigint;

use criterion::{Criterion, BenchmarkGroup};
use shamirs_secret_sharing::*;
use num_bigint::BigInt;
// string parsing traits
use std::str::FromStr;

// Module containing the benchmark functions
mod mod_inverse_benches {
  use super::*;
  // Benchmark function that tests modular inverse performance
  pub fn bench_modular_inv(c: &mut Criterion) {
    println!("Running modular inverse benchmarks...");
    // Initialize a large modulus (2^252 + something) from a string
    let modul1 = BigInt::from_str("7237005577332262213973186563042994240857116359379907606001950938285454250989").unwrap();
    // Initialize a test number to find its modular inverse
    let d1 = BigInt::from_str("182687704666362864775460604089535377456991567872").unwrap();

    // Create a new benchmark group for modular inverse operations
    let mut group: BenchmarkGroup<_> = c.benchmark_group("Modular Inverse");

    // Add a benchmark for Fermat's inverse method
    // The closure |b, d| defines what will be benchmarked
    group.bench_with_input("Fermat's inverse", &d1, |b, d| {
        // b.iter() runs the closure multiple times to get accurate measurements
        b.iter(|| fermat_inverse(d, &modul1))
    });

    group.finish();
  }
}
// Create a criterion benchmark group using the bench_modular_inv function
criterion_group!(benches, mod_inverse_benches::bench_modular_inv);
// Set up the main function to run all benchmarks
criterion_main!(benches);
