$FRI$ stands for *Fast Reed-Solomon Interactive Oracle Proofs*. FRI is used to prove that a vector commitment is a low-degree polynomial.
### Why do we need FRI ?
The naive approach would involve sending all the evaluations at the Merkle tree leaves to the verifier and then letting the verifier interpolate that data. However, this is computationally expensive. FRI provides an alternative to sending all the data for interpolation. It offers a way to convince the verifier that the Merkle commitment corresponds to evaluations of a low-degree polynomial. In the initial commitment, the prover evaluates a polynomial $f(x)$ over a domain $D$, creates a Merkle tree of these evaluations, and sends the root commitment to the verifier.
FRI works by iteratively "folding" the polynomial into smaller pieces:
- Each round splits polynomial $f_i(x)$ into:
  $f_i(x) = fL_i(x²) + x·fR_i(x²)$, where  $fL_i$ contains the even-degree coefficients and $fR_i$ the odd-degree coefficients.
- Then, they are combined with a random challenge $α_i$: $f_{i+1}(x) = fL_i(x) + α_i·fR_i(x)$.
In this process the deegree halves in each round, which preserves the low-degree property and the final polynomial is constant (degree 0).
### Protocol mechanics
In the first rounds, the prover sends only the Merkle tree root, not all the data. The prover asserts that the leaves are evaluations of $f$, where $f$ is the polynomial evaluated at certain points. At the end, the verifier makes some queries to ensure that the folding was done correctly. The verifier receives Merkle roots for each round, then queries random points, checks the consistency between rounds, and verifies that the final constant matches the claimed value.
The security of FRI relies on the binding property of the Merkle commitments and the soundness of the "folding" operation with random challenges.Verification time is logarithmic in polynomial degree

This code implements FRI (Fast Reed-Solomon Interactive Oracle Proofs). The code implements two main components:
- FRI Low Degree Testing (FRI_LDT) to prove that a polynomial has a claimed degree.
- FRI Polynomial Commitment Scheme (FRI_PCS) allows committing to a polynomial and later proving its evaluation at a point.

### References
Paul Gafni, *FRI Mechanics: Folding, Committing, and Batching*;
