use merkletree::{Hash, MerkleTree};
use ark_std::marker::PhantomData;
use ark_ff::PrimeField;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
};
// Transcript for implementing the Fiat-Shamir transform, which converts an interactive protocol into a non-interactive one
// by generating challenges deterministically.
use transcript::Transcript;

// rho^-1
// to determine the size of the evaluation domain in relation to the polynomial degree
// Could be adjusted based on security requirements
const rho1: usize = 8;

pub struct LDTProof<F: PrimeField> {
    degree: usize,         // claimed degree of the polynomial
    commitments: Vec<F>,   // Merkle roots for each round. Length equals number of FRI rounds (≈ log₂(degree))
    mtproofs: Vec<Vec<F>>, // Merkle proofs for each round
    evals: Vec<F>,         // Polynomial evaluations at query points
    constants: [F; 2],     // Final constant polynomials (fL, fR)
}

// DenseUVPolynomial is a trait from the ark_poly library
// that defines the behavior for univariate polynomials stored in dense form.
// Makes it easier to access coefficients by their position.
struct FRI_LDT<F: PrimeField, P: DenseUVPolynomial<F>, H: Hash<F>> {
  _f: PhantomData<F>,     // PhantomData is used because the struct doesn't actually store any data of these types,
  _poly: PhantomData<P>,  // but needs to "remember" the types for its methods.
  _h: PhantomData<H>,     // PhantomData fields don't take any space in memory.
}

// The implementation provides methods for this struct
impl<F: PrimeField, P: DenseUVPolynomial<F>, H: Hash<F>> FRI_LDT<F, P, H> {
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
        let mut f_i1 = p.clone();                           // Current polynomial (starts with f_0 = p)

        // Set evaluation domain size
        // sub_order = |F_i| = rho^-1 * d
        let mut sub_order = d * rho1; //
        let mut eval_sub_domain: GeneralEvaluationDomain<F> =
            GeneralEvaluationDomain::new(sub_order).unwrap();

        // Get random challenge point z from the domain
        let (z_pos, z) = transcript.get_challenge_in_eval_domain(eval_sub_domain, b"get z");

        let mut f_is: Vec<P> = Vec::new();    // Store polynomials for each round
        // Store evaluations f_i(z^(2^i)), f_i(-z^(2^i))
        let mut evals: Vec<F> = Vec::new();
        let mut mtproofs: Vec<Vec<F>> = Vec::new();  // Merkle proofs
        let mut fL_i: P = P::from_coefficients_vec(Vec::new());  // Left split
        let mut fR_i: P = P::from_coefficients_vec(Vec::new());  // Right split
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
            let (cm_i, mt_i) = MerkleTree::<F, H>::commit(&subdomain_evaluations);
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
            (fL_i, fR_i) = Self::split(&f_i1);

            // Compute next polynomial f_{i+1}(x) = fL_i(x) + alpha_i * fR_i(x)
            let aux = DensePolynomial::from_coefficients_slice(fR_i.coeffs());
            f_i1 = fL_i.clone() + P::from_coefficients_slice(aux.mul(alpha_i).coeffs());

            // Prepare for next round
            sub_order = sub_order / 2;
            eval_sub_domain = GeneralEvaluationDomain::new(sub_order).unwrap();

            i += 1;
        }
        // Verify final polynomials are constant
        if fL_i.coeffs().len() != 1 {
            panic!("fL_i not constant");
        }
        if fR_i.coeffs().len() != 1 {
            panic!("fR_i not constant");
        }

        // Get final constants
        let constant_fL_l: F = fL_i.coeffs()[0].clone();
        let constant_fR_l: F = fR_i.coeffs()[0].clone();

        // Return complete proof
        LDTProof {
            degree: p.degree(),
            commitments,
            mtproofs,
            evals,
            constants: [constant_fL_l, constant_fR_l],
        }
    }

    // Verify a FRI proof
    pub fn verify(proof: , degree: usize) -> bool { ... }
}
