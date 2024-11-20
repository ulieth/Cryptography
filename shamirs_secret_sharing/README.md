The provided Rust code implements a secret-sharing scheme using Shamir's Secret Sharing algorithm. The scheme divides a secret *S* into *n* pieces of data, called shares $S_1, S_2, \ldots, S_n$, such that knowledge of any *k* or more shares $S_i$ allows for the reconstruction of the secret *S*. If represented graphically, the secret is a point on a polynomial curve, and knowing any *k* points on this curve is sufficient to reconstruct the original polynomial and the secret. The underlying mechanism relies on Lagrange interpolation, which states that *k* points on a polynomial uniquely determine a polynomial of degree less than or equal to *k - 1*. The secret *S* can be expressed as a *constant term* $a_0$ over a finite field $GF_q$, where $a_0$ must be less than the size $q$ of that field. To construct the polynomial, randomly choose $k - 1$ elements $a_1, \ldots, a_k-1$ from $GF_q$, and create the polynomial $f(x) = a_0 + a_1 * x + a_2 * x^2 + a_3 * x^3 + ... + a_{k-1} * x^{k-1}$. Compute any $n$ points from it using incremental indices for the $x$ coordinate ($i$, $f(i)$). Given any subset of $k$ shares, the secret $a_0$ can be reconstructed using the Lagrange interpolation formula:

$$
S(x) = \sum_{i=0}^{n} \left( y_i \cdot \prod_{\substack{0 \leq j \leq n \\ j \neq i}} \frac{x - x_j}{x_i - x_j} \right)
$$

Where:
- $y_i$ are the share values
- $x_i$ are the indices of the shares
- The expression $\frac{x - x_j}{x_i - x_j}$ represents a fraction that needs to be computed for each share.

In this formula, we evaluate the polynomial at a specific point based on the given shares, involving division by the Lagrange denominator, a product of terms. The code employs Fermat's Little Theorem to compute modular inverses, assuming $q$ is prime. However, this approach is not ideal. It requires the modulus to be prime, it is computationally expensive for large numbers (O(log p) multiplications), and susceptible to timing attacks due to exponentiation patterns. Since performance with large numbers is crucial in Shamir Secret Sharing scheme, the Kalinski algorithm provides better performance characteristics for the BigInt operations by using simpler operations like shifts and additions. Work in progress.
## Usage
```Rust
// Create 5 shares from the secret s over the finite field q
let shares = create(3, 5, &q, &s);

// With onlt 3 shares you will be able to recover the original secret
let mut shares_to_use: Vec<[BigInt;2]> = Vec::new();
shares_to_use.push(shares[2].clone());
shares_to_use.push(shares[1].clone());
shares_to_use.push(shares[0].clone());

// Recover the secret using the Lagrange Interpolation
let r = lagrange_interpolation(&q, shares_to_use);
assert_eq!(s, r);
