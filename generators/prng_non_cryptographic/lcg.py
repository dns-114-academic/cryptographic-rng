"""
Linear Congruential Generator (LCG)
Deterministic pseudo-random number generator based on a linear recurrence.
https://en.wikipedia.org/wiki/Linear_congruential_generator
"""


def lcg(seed, a, c, m, n):
    """
    Generate n numbers using an LCG.

    Formula: X_{i+1} = (a * X_i + c) mod m

    Parameters:
        seed : initial state (X_0)
        a    : multiplier
        c    : increment
        m    : modulus
        n    : number of values to generate

    Returns:
        List of n integers in [0, m-1]
    """
    x = seed
    results = []
    for _ in range(n):
        x = (a * x + c) % m   # Recurrence relation (X_0 is never included in output)
        results.append(x)
    return results


# Standard parameter sets

# Source: glibc (C standard library) — passable quality
PARAMS_GLIBC = {
    'a': 1103515245,
    'c': 12345,
    'm': 2**31
}

# RANDU — a notoriously bad LCG, included for pedagogical purposes only
PARAMS_RANDU = {
    'a': 65539,
    'c': 0,
    'm': 2**31
}

# MMIX by Knuth — good quality
PARAMS_KNUTH = {
    'a': 6364136223846793005,
    'c': 1442695040888963407,
    'm': 2**64
}


if __name__ == "__main__":
    print("LCG — glibc parameters, seed=42, 10 values:")
    output = lcg(42, **PARAMS_GLIBC, n=10)
    print(f"  {output}")
