"""
Blum-Blum-Shub (BBS)
Cryptographically secure PRNG based on the Quadratic Residuosity Problem (QRP).
Security is formally proven under the assumption that QRP is computationally hard.
https://en.wikipedia.org/wiki/Blum_Blum_Shub
"""


def bbs(seed, p, q, n):
    """
    Blum-Blum-Shub bit generator.

    Recurrence: x_{k+1} = (x_k)^2 mod M,  where M = p * q
    Output    : least significant bit (LSB) of each x_{k+1}

    Security note:
        Only the LSB is provably secure per iteration.
        Up to floor(log2(log2(M))) bits can be extracted safely.
        For p=499, q=547: this is about 3 bits — pedagogical only.
        For production use, p and q must each be at least 512 bits long.

    Parameters:
        seed : initial value (must be coprime with M, != 0, != 1)
        p, q : Blum primes (p ≡ 3 mod 4, q ≡ 3 mod 4)
        n    : number of bits to generate

    Returns:
        List of n bits (0 or 1)
    """
    M = p * q
    x = (seed * seed) % M   # Pre-iteration: place seed into the set of quadratic residues mod M
    results = []
    for _ in range(n):
        x = (x * x) % M           # Squaring step
        results.append(x & 1)     # Extract LSB (the only provably secure bit)
    return results


# Small Blum primes for pedagogical/testing purposes only
# Verification: 499 mod 4 = 3  ✓   |   547 mod 4 = 3  ✓
SMALL_PRIMES = {
    'p': 499,
    'q': 547
}


if __name__ == "__main__":
    p, q = SMALL_PRIMES['p'], SMALL_PRIMES['q']
    print(f"BBS — p={p}, q={q}, M={p*q}, seed=7, 20 bits:")
    bits = bbs(7, p, q, 20)
    print(f"  {bits}")
