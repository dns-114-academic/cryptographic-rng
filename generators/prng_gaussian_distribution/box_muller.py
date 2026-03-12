"""
Box-Muller Transform
Converts uniform random variables into Gaussian (normal) random variables.
https://en.wikipedia.org/wiki/Box%E2%80%93Muller_transform
"""

import math


def box_muller(u1, u2):
    """
    Standard Box-Muller transform.

    Formulas:
        Z0 = sqrt(-2 * ln(U1)) * cos(2π * U2)
        Z1 = sqrt(-2 * ln(U1)) * sin(2π * U2)

    Parameters:
        u1, u2 : two independent uniform values in (0, 1)

    Returns:
        (z0, z1) : two independent standard normal values N(0, 1)
    """
    # Guard against ln(0) = -infinity
    if u1 <= 0:
        u1 = 1e-10
    if u2 <= 0:
        u2 = 1e-10

    r = math.sqrt(-2.0 * math.log(u1))   # Rayleigh radius
    theta = 2.0 * math.pi * u2            # Uniform angle on [0, 2π)

    z0 = r * math.cos(theta)              # First Gaussian output
    z1 = r * math.sin(theta)              # Second Gaussian output

    return z0, z1


def box_muller_series(uniform_rng, seed, n):
    """
    Generate n Gaussian values from a uniform random source.

    Parameters:
        uniform_rng : uniform generator function with signature (seed, n) -> list[float] in [0, 1]
        seed        : seed for the uniform generator
        n           : number of Gaussian values to produce

    Returns:
        List of n Gaussian values N(0, 1)
    """
    # Box-Muller consumes pairs (U1, U2), so we need the smallest even number >= n
    n_uniform = ((n + 1) // 2) * 2
    uniforms = uniform_rng(seed, n_uniform)

    results = []
    for i in range(0, len(uniforms) - 1, 2):
        z0, z1 = box_muller(uniforms[i], uniforms[i + 1])
        results.extend([z0, z1])

    return results[:n]   # Trim to exactly n values (last z1 may be excess if n is odd)


if __name__ == "__main__":
    print("Box-Muller — single pair (u1=0.5, u2=0.3):")
    z0, z1 = box_muller(0.5, 0.3)
    print(f"  Z0 = {z0:.6f},  Z1 = {z1:.6f}")
