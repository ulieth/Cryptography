use merkletree::{Hash, MerkleTree};
pub mod merkletree;
pub mod transcript;

use ark_ff::PrimeField;
// `ark_poly` handles polynomial operations
// DensePolynomial stores coefficients in a dense array, making it efficient for most operation
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
};
// Transcript for implementing the Fiat-Shamir transform, which converts an interactive protocol into a non-interactive one
// by generating challenges deterministically.
use transcript::Transcript;

use ark_std::{
  cfg_into_iter,
  marker::PhantomData, // Zero-sized type for generic parameters
  ops::{Div, Mul},
  rand::Rng,
  UniformRand,
};

// rho^-1
// to determine the size of the evaluation domain in relation to the polynomial degree
// Could be adjusted based on security requirements
const RHO_INVERSE: usize = 8;

pub struct LDTProof<F: PrimeField> {
    degree: usize,         // claimed degree of the polynomial
    commitments: Vec<F>,   // Merkle roots for each round. Length equals number of FRI rounds (≈ log₂(degree))
    mtproofs: Vec<Vec<F>>, // Merkle proofs for each round
    evals: Vec<F>,         // Polynomial evaluations at query points [p(z), p(-z), f_i1(z²), f_i1(-z²)]
    constants: [F; 2],     // Final constant polynomials (fL, fR)
}

// DenseUVPolynomial is a trait from the ark_poly library
// that defines the behavior for univariate polynomials stored in dense form.
// Makes it easier to access coefficients by their position.
struct FriLdt<F: PrimeField, P: DenseUVPolynomial<F>, H: Hash<F>> {
  _f: PhantomData<F>,     // PhantomData is used because the struct doesn't actually store any data of these types,
  _poly: PhantomData<P>,  // but needs to "remember" the types for its methods.
  _h: PhantomData<H>,     // PhantomData fields don't take any space in memory.
}

// The implementation provides methods for this struct
impl<F: PrimeField, P: DenseUVPolynomial<F>, H: Hash<F>> FriLdt<F, P, H> {
    // Constructor
    pub fn new() -> Self {
        Self {
            _f: PhantomData,
            _poly: PhantomData,
            _h: PhantomData,
        }
    }
    // Split polynomial into even and odd parts
    fn split(p: &P) -> (P, P) {
        let coeffs = p.coeffs();
        // Get even-indexed coefficients
        let odd: Vec<F> = coeffs.iter().step_by(2).cloned().collect();
        // Get odd-indexed coefficients
        let even: Vec<F> = coeffs.iter().skip(1).step_by(2).cloned().collect();
        return (
            P::from_coefficients_vec(odd),
            P::from_coefficients_vec(even),
        );
    }

    // Generate a FRI proof
    pub fn prove(p: &P) -> LDTProof<F> {
        // Initialize transcript
        let mut transcript: Transcript<F> = Transcript::<F>::new();
        // Get degree of input polynomial
        let d = p.degree();
        // Initialize vectors for storing proof components
        let mut commitments: Vec<F> = Vec::new();           // Merkle roots
        let mut mts: Vec<MerkleTree<F, H>> = Vec::new();    // Merkle trees

        // f_0(x) = fL_0(x^2) + x * fR_0(x^2)
        let mut f_i1 = p.clone();   // Current polynomial (starts with f_0 = p)

        // Set evaluation domain size
        // sub_order = |F_i| = rho^-1 * d
        let mut sub_order = d * RHO_INVERSE;
        let mut eval_sub_domain: GeneralEvaluationDomain<F> =
            GeneralEvaluationDomain::new(sub_order).unwrap();

        // Get random challenge point z from the domain
        let (z_pos, z) = transcript.get_challenge_in_eval_domain(eval_sub_domain, b"get z");

        let mut f_is: Vec<P> = Vec::new();    // Store polynomials for each round
        // Store evaluations f_i(z^(2^i)), f_i(-z^(2^i))
        let mut evals: Vec<F> = Vec::new();
        let mut mtproofs: Vec<Vec<F>> = Vec::new();  // Merkle proofs
        let mut f_l_i: P = P::from_coefficients_vec(Vec::new());  // Left split
        let mut f_r_i: P = P::from_coefficients_vec(Vec::new());  // Right split
        let mut i = 0;
        while f_i1.degree() >= 1 {    // Continue until reaching constant polynomial
            // Store current polynomial
            f_is.push(f_i1.clone());
            // Get random challenge for this round
            let alpha_i = transcript.get_challenge(b"get alpha_i");

            // Evaluate polynomial on subdomain
            let subdomain_evaluations: Vec<F> = cfg_into_iter!(0..eval_sub_domain.size())
                .map(|k| f_i1.evaluate(&eval_sub_domain.element(k)))
                .collect();

            // Commit to evaluations with Merkle tree
            // MerkleTree::commit(&subdomain_evaluations) works like this:

            /*        ROOT (cm_i)
                   /          \
                H(1,2)        H(3,4)
               /     \       /     \
            H(1)     H(2)  H(3)    H(4)
             |        |     |        |
             p0       p1    p3       p4  ...
            */
            let (cm_i, mt_i) = MerkleTree::<F, H>::commit(&subdomain_evaluations); // cm_i is the Merkle root
                                                                                   // mt_i is the entire tree structure
            commitments.push(cm_i);
            mts.push(mt_i);
            transcript.add(b"root_i", &cm_i);

            // Compute z^(2^i) and -z^(2^i)
            let z_2i = z.pow([2_u64.pow(i as u32)]);
            let neg_z_2i = z_2i.neg();
            // Evaluate and store f_i(z^(2^i))
            let eval_i = f_i1.evaluate(&z_2i);
            evals.push(eval_i);
            transcript.add(b"f_i(z^{2^i})", &eval_i);
            // Evaluate and store f_i(-z^(2^i))
            let eval_i = f_i1.evaluate(&neg_z_2i);
            evals.push(eval_i);
            transcript.add(b"f_i(-z^{2^i})", &eval_i);

            // Generate Merkle proof
            let mtproof = mts[i].open(F::from(z_pos as u32));
            mtproofs.push(mtproof);

            // Split polynomial into even/odd parts
            (f_l_i, f_r_i) = Self::split(&f_i1);

            // Compute next polynomial f_{i+1}(x) = f_l_i(x) + alpha_i * f_r_i(x)
            let aux = DensePolynomial::from_coefficients_slice(f_r_i.coeffs());
            f_i1 = f_l_i.clone() + P::from_coefficients_slice(aux.mul(alpha_i).coeffs());

            // Prepare for next round
            sub_order = sub_order / 2;
            eval_sub_domain = GeneralEvaluationDomain::new(sub_order).unwrap();

            i += 1;
        }
        // Verify final polynomials are constant
        if f_l_i.coeffs().len() != 1 {
            panic!("f_l_i not constant");
        }
        if f_r_i.coeffs().len() != 1 {
            panic!("f_r_i not constant");
        }

        // Get final constants
        let constant_f_l_l: F = f_l_i.coeffs()[0].clone();
        let constant_f_r_l: F = f_r_i.coeffs()[0].clone();

        // Return complete proof
        LDTProof {
            degree: p.degree(),
            commitments,
            mtproofs,
            evals,
            constants: [constant_f_l_l, constant_f_r_l],
        }
    }

    // Verify a FRI proof
    pub fn verify(proof: LDTProof<F>, degree: usize)  -> bool {
        // init transcript
        let mut transcript: Transcript<F> = Transcript::<F>::new();

        if degree != proof.degree {
            println!("proof degree missmatch");
            return false;
        }
        // TODO check that log_2(evals/2) == degree, etc

        let sub_order = RHO_INVERSE * degree;
        let eval_sub_domain: GeneralEvaluationDomain<F> =
            GeneralEvaluationDomain::new(sub_order).unwrap();

        let (z_pos, z) = transcript.get_challenge_in_eval_domain(eval_sub_domain, b"get z");

        if proof.commitments.len() != (proof.evals.len() / 2) {
            println!("sho commitments.len() != (evals.len() / 2) - 1");
            return false;
        }

        let mut i_z = 0;
        for i in (0..proof.evals.len()).step_by(2) {
            let alpha_i = transcript.get_challenge(b"get alpha_i");

            // take f_i(z^2) from evals
            let z_2i = z.pow([2_u64.pow(i_z as u32)]); // z^{2^i}
            let fi_z = proof.evals[i];
            let neg_fi_z = proof.evals[i + 1];
            // compute f_i^L(z^2), f_i^R(z^2) from the linear combination
            let L = (fi_z + neg_fi_z) * F::from(2_u32).inverse().unwrap();
            let R = (fi_z - neg_fi_z) * (F::from(2_u32) * z_2i).inverse().unwrap();

            // compute f_{i+1}(z^2) = f_i^L(z^2) + a_i f_i^R(z^2)
            let next_fi_z2 = L + alpha_i * R;

            // check: obtained f_{i+1}(z^2) == evals.f_{i+1}(z^2) (=evals[i+2])
            if i < proof.evals.len() - 2 {
                if next_fi_z2 != proof.evals[i + 2] {
                    println!(
                        "verify step i={}, should f_i+1(z^2) == evals.f_i+1(z^2) (=evals[i+2])",
                        i
                    );
                    return false;
                }
            }
            transcript.add(b"root_i", &proof.commitments[i_z]);
            transcript.add(b"f_i(z^{2^i})", &proof.evals[i]);
            transcript.add(b"f_i(-z^{2^i})", &proof.evals[i + 1]);

            // check commitment opening
            if !MerkleTree::<F, H>::verify(
                proof.commitments[i_z],
                F::from(z_pos as u32),
                proof.evals[i],
                proof.mtproofs[i_z].clone(),
            ) {
                println!("verify step i={}, MT::verify failed", i);
                return false;
            }

            // last iteration, check constant values equal to the obtained f_i^L(z^{2^i}),
            // f_i^R(z^{2^i})
            if i == proof.evals.len() - 2 {
                if L != proof.constants[0] {
                    println!("constant L not equal to the obtained one");
                    return false;
                }
                if R != proof.constants[1] {
                    println!("constant R not equal to the obtained one");
                    return false;
                }
            }
            i_z += 1;
        }

        true
    }
}
pub struct FriPcsProof<F: PrimeField> {
  p_proof: LDTProof<F>,
  g_proof: LDTProof<F>,
  mtproof_y_index: F, // TODO maybe include index in the mtproof, this would be done at the MerkleTree impl level
  mtproof_y: Vec<F>,
}

// FriPcs implements the FRI Polynomial Commitment

pub struct FriPcs<F, P, H>
where
    F: PrimeField,
    P: DenseUVPolynomial<F>,
    H: Hash<F>,
{
    _f: PhantomData<F>,
    _poly: PhantomData<P>,
    _h: PhantomData<H>,
}

impl<F: PrimeField, P: DenseUVPolynomial<F>, H: Hash<F>> FriPcs<F, P, H>
where
  for<'a, 'b> &'a P: Div<&'b P, Output = P>,
{
  pub fn commit(p: &P) -> F {
      let (cm, _, _) = Self::tree_from_domain_evals(p);
      cm
  }

  pub fn rand_in_eval_domain<R: Rng>(rng: &mut R, deg: usize) -> F {
      let sub_order = deg * RHO_INVERSE;
      let eval_domain: GeneralEvaluationDomain<F> =
          GeneralEvaluationDomain::new(sub_order).unwrap();
      let size = eval_domain.size();
      let c = usize::rand(rng);
      let pos = c % size;
      eval_domain.element(pos)
  }

  fn tree_from_domain_evals(p: &P) -> (F, MerkleTree<F, H>, Vec<F>) {
      let d = p.degree();
      let sub_order = d * RHO_INVERSE;
      let eval_sub_domain: GeneralEvaluationDomain<F> =
          GeneralEvaluationDomain::new(sub_order).unwrap();
      let subdomain_evaluations: Vec<F> = cfg_into_iter!(0..eval_sub_domain.size())
          .map(|k| p.evaluate(&eval_sub_domain.element(k)))
          .collect();
      let (cm, mt) = MerkleTree::<F, H>::commit(&subdomain_evaluations);
      (cm, mt, subdomain_evaluations)
  }

  pub fn open(p: &P, r: F) -> (F, FriPcsProof<F>) {
      let y = p.evaluate(&r);
      let y_poly: P = P::from_coefficients_vec(vec![y]);
      let mut p_y: P = p.clone();
      p_y.sub_assign(&y_poly);
      // p_y = p_y - y_poly;
      let x_r: P = P::from_coefficients_vec(vec![-r, F::one()]);

      // g(x), quotient polynomial
      let g: P = p_y.div(&x_r);

      if p.degree() != g.degree() + 1 {
          panic!("ERR p.deg: {}, g.deg: {}", p.degree(), g.degree()); // TODO err
      }

      // proof for commitment
      // reconstruct commitment_mt
      let (_, commitment_mt, subdomain_evaluations) = Self::tree_from_domain_evals(&p);
      // find y in subdomain_evaluations
      let mut y_eval_index: F = F::zero();
      for i in 0..subdomain_evaluations.len() {
          if y == subdomain_evaluations[i] {
              y_eval_index = F::from(i as u64);
              break;
          }
      }
      let mtproof_y = commitment_mt.open(y_eval_index);

      let p_proof = FriLdt::<F, P, H>::prove(p);
      let g_proof = FriLdt::<F, P, H>::prove(&g);

      (
          y,
          FriPcsProof {
              p_proof,
              g_proof,
              mtproof_y_index: y_eval_index,
              mtproof_y,
          },
      )
  }

  pub fn verify(commitment: F, proof: FriPcsProof<F>, r: F, y: F) -> bool {
      let deg_p = proof.p_proof.degree;
      let deg_g = proof.g_proof.degree;
      if deg_p != deg_g + 1 {
          return false;
      }

      // obtain z from transcript
      let sub_order = RHO_INVERSE * proof.p_proof.degree;
      let eval_sub_domain: GeneralEvaluationDomain<F> =
          GeneralEvaluationDomain::new(sub_order).unwrap();
      let mut transcript: Transcript<F> = Transcript::<F>::new();
      let (_, z) = transcript.get_challenge_in_eval_domain(eval_sub_domain, b"get z");

      // check g(z) == (f(z) - y) * (z-r)^-1
      let gz = proof.g_proof.evals[0];
      let fz = proof.p_proof.evals[0];
      let rhs = (fz - y) / (z - r);
      if gz != rhs {
          return false;
      }

      // check that commitment was for the given y
      if !MerkleTree::<F, H>::verify(commitment, proof.mtproof_y_index, y, proof.mtproof_y) {
          return false;
      }

      // check FRI-LDT for p(x)
      if !FriLdt::<F, P, H>::verify(proof.p_proof, deg_p) {
          return false;
      }

      // check FRI-LDT for g(x)
      if !FriLdt::<F, P, H>::verify(proof.g_proof, deg_p - 1) {
          return false;
      }

      return true;
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use ark_ff::Field;
  use ark_bn254::Fr; //  Implements the BN254 elliptic curve (also known as alt-bn128)
  use ark_poly::Polynomial;
  use ark_std::log2;
  use crate::merkletree::Keccak256Hash;

  #[test]
  fn test_split() {
      let mut rng = ark_std::test_rng();
      let deg = 7;
      let p = DensePolynomial::<Fr>::rand(deg, &mut rng);
      assert_eq!(p.degree(), deg);

      type FRID = FriLdt<Fr, DensePolynomial<Fr>, Keccak256Hash<Fr>>;
      let (pL, pR) = FRID::split(&p);

      // check that f(z) == fL(x^2) + x * fR(x^2), for a rand z
      let z = Fr::rand(&mut rng);
      assert_eq!(
          p.evaluate(&z),
          pL.evaluate(&z.square()) + z * pR.evaluate(&z.square())
      );
  }

  #[test]
  fn test_prove() {
      let deg = 31;
      let p = DensePolynomial::<Fr>::rand(deg, &mut ark_std::test_rng());
      assert_eq!(p.degree(), deg);
      // println!("p {:?}", p);

      type LDT = FriLdt<Fr, DensePolynomial<Fr>, Keccak256Hash<Fr>>;

      let proof = LDT::prove(&p);
      // commitments contains the commitments to each f_0, f_1, ..., f_n, with n=log2(d)
      assert_eq!(proof.commitments.len(), log2(p.coeffs().len()) as usize);
      assert_eq!(proof.evals.len(), 2 * log2(p.coeffs().len()) as usize);

      let v = LDT::verify(proof, deg);
      assert!(v);
  }

  #[test]
  fn test_polynomial_commitment() {
      let deg = 31;
      let mut rng = ark_std::test_rng();
      let p = DensePolynomial::<Fr>::rand(deg, &mut rng);

      type PCS = FriPcs<Fr, DensePolynomial<Fr>, Keccak256Hash<Fr>>;

      let commitment = PCS::commit(&p);

      // Verifier set challenge in evaluation domain for the degree
      let r = PCS::rand_in_eval_domain(&mut rng, deg);

      let (claimed_y, proof) = PCS::open(&p, r);

      let v = PCS::verify(commitment, proof, r, claimed_y);
      assert!(v);
  }
}
