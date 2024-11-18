extern crate num;
extern crate num_bigint;
extern crate num_traits;
extern crate rand;

use num::pow::pow;
use num_bigint::RandBigInt;

use num_bigint::{BigInt, ToBigInt};
use num_traits::{One, Zero, Signed};



fn modulus(a: &BigInt, m: &BigInt) -> BigInt {
  ((a % m) + m) % m
}

pub fn create(k: u32, n: u32, q: &BigInt, s: &BigInt) -> Vec<[BigInt; 2]> {
  // k: number of shares needed to reconstruct the secret (threshold);
  // n: number of shares;
  // q: size of finite field;
  // s: secret to share;
  // the secret s must be less than the field size q for ensuring that the secret can be represented within the finite field,
  // as all arithmetic operations will be done modulo q;
  if s > q {
      println!("\nERROR: need k<p\n");
  }

  // The secret sharing is based on a polynomial of degree k - 1.
  // The basis polynomial is defined as f(x) = s + a_1x + a_2x^2 + ... + a_k-1x^k-1,
  // where s is a constant term (the secret) and a_1,a_2,...,a_k-1 are randomly generated coefficients.
  // The polynomial variable will hold the secret and the randomly generated coefficients.
  let mut polynomial: Vec<BigInt> = Vec::new();
  polynomial.push(s.clone()); // the secret s is added as the first element
  for _ in 0..k as usize - 1 {
      let mut rng = rand::thread_rng();
      let a = rng.gen_bigint(1024);
      polynomial.push(a);
  }

  // A vector shares is created to store the calculated share values.
  let mut shares: Vec<BigInt> = Vec::new();
  for i in 1..n + 1 {
      let mut share_value: BigInt = Zero::zero();
      let mut x = 0;
      for coeff in &polynomial {
          if x == 0 {
            share_value = share_value + coeff; // the constant term
          } else {
              let i_pow = pow(i, x);
              let curr_elem = i_pow * coeff;
              share_value = share_value + curr_elem;
              share_value = modulus(&share_value, &q);
          }
          x = x + 1;
      }
      shares.push(share_value);
  }
  pack_shares(shares)
}

fn pack_shares(shares: Vec<BigInt>) -> Vec<[BigInt; 2]> {
    let mut packed_shares: Vec<[BigInt; 2]> = Vec::new();
    for i in 0..shares.len() {
      let curr: [BigInt; 2] = [shares[i].clone(), (i + 1).to_bigint().unwrap()];
      packed_shares.push(curr);
    }
    packed_shares
}

fn unpack_shares(s: Vec<[BigInt; 2]>) -> (Vec<BigInt>, Vec<BigInt>) {
  let mut shares: Vec<BigInt> = Vec::new();
  let mut is: Vec<BigInt> = Vec::new();
  for i in 0..s.len() {
      shares.push(s[i][0].clone());
      is.push(s[i][1].clone());
  }
  (shares, is)
}

pub fn lagrange_interpolation(q: &BigInt, shares_packed: Vec<[BigInt; 2]>) -> BigInt {
  let mut res_n: BigInt = Zero::zero();
  let mut res_d: BigInt = Zero::zero();
  let (shares, sh_i) = unpack_shares(shares_packed);

  for i in 0..shares.len() {
      let mut lagrange_numerator: BigInt = One::one();
      let mut lagrange_denominator: BigInt = One::one();
      for j in 0..shares.len() {
          if shares[i] != shares[j] {
              let curr_l_numerator = &sh_i[j];
              let curr_l_denominator = &sh_i[j] - &sh_i[i];
              lagrange_numerator = lagrange_numerator * curr_l_numerator;
              lagrange_denominator = lagrange_denominator * curr_l_denominator;
          }
      }
      let numerator: BigInt = &shares[i] * &lagrange_numerator;
      // The else blocks ensures the polynomial interpolation
      // maintains the correct contributions despite the zero quotient.
      let quo: BigInt =
          (&numerator / &lagrange_denominator) + (&lagrange_denominator) % &lagrange_denominator;
      if quo != Zero::zero() {
          res_n = res_n + quo;
      } else {
          let res_n_mul_lagrange_den = res_n * &lagrange_denominator;
          res_n = res_n_mul_lagrange_den + numerator;
          res_d = res_d + lagrange_denominator;
      }
  }
  let modinv_mul: BigInt;
  // When calculating the Lagrange polynomial,
  // you end up needing to divide the numerator (which includes the y-values)
  // by the lagrange_denominator to find the polynomial's value at a certain point.
  // This division, in modular arithmetic, is handled by multiplying by the multiplicative inverse of the denominator.
  if res_d != Zero::zero() {
      let modinv = fermat_inverse(&res_d, &q);
      modinv_mul = res_n * modinv;
  } else {
      modinv_mul = res_n;
  }
  let r = modulus(&modinv_mul, &q);
  r
}

pub fn fermat_inverse(a: &BigInt, p: &BigInt) -> BigInt {
  assert!(p.is_positive() && a.is_positive() && a < p);
  let exp = p - BigInt::from(2); // p - 2
  a.modpow(&exp, p) // Compute a^(p-2) mod p
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_create_and_lagrange_interpolation() {
      // 2 ** 127 - 1
      // the field size
      let q = BigInt::parse_bytes(b"170141183460469231731687303715884105727", 10).unwrap();
      println!("q: {:?}", q.to_string());

      // the secret
      let s = BigInt::parse_bytes(b"12345678901234567890123456789012345678", 10).unwrap();

      // with only 3 any shares, we'll be able to reconstrcut the original secret
      let shares = create(3, 6, &q, &s);
      println!("shares: {:?}", shares);

      let mut shares_to_use: Vec<[BigInt; 2]> = Vec::new();
      shares_to_use.push(shares[2].clone());
      shares_to_use.push(shares[1].clone());
      shares_to_use.push(shares[0].clone());
      let r = lagrange_interpolation(&q, shares_to_use);
      println!("recovered secret: {:?}", r.to_string());
      println!("original secret: {:?}", s.to_string());
      assert_eq!(s, r);
  }

    #[test]
    fn fermat_modular_inverse() {
        let modul1 = BigInt::from(127u64);

        let a = BigInt::from(79u64);
        let res1 = fermat_inverse(&a, &modul1);
        let expected1 = BigInt::from(82u64);
        assert_eq!(res1, expected1);

        let b = BigInt::from(50u64);
        let res2 = fermat_inverse(&b, &modul1);
        let expected2 = BigInt::from(94u64);
        assert_eq!(res2, expected2);

        // Modulo: 2^252 + 27742317777372353535851937790883648493
        // Tested: 182687704666362864775460604089535377456991567872
        // Expected for: inverse_mod(a, l) computed on SageMath:
        // `7155219595916845557842258654134856828180378438239419449390401977965479867845`.
        let modul3 = BigInt::from_str(
            "7237005577332262213973186563042994240857116359379907606001950938285454250989",
        )
        .unwrap();
        let d = BigInt::from_str("182687704666362864775460604089535377456991567872").unwrap();
        let res4 = fermat_inverse(&d, &modul3);
        let expected4 = BigInt::from_str(
            "7155219595916845557842258654134856828180378438239419449390401977965479867845",
        )
        .unwrap();
        assert_eq!(expected4, res4);
    }
}
