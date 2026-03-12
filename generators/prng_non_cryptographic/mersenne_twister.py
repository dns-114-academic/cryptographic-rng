"""
Mersenne Twister MT19937
PRNG with period 2^19937 - 1.
Not cryptographically secure.
https://en.wikipedia.org/wiki/Mersenne_Twister
"""

# MT19937 constants
W, N, M, R = 32, 624, 397, 31
A = 0x9908B0DF          # Twist matrix constant
F = 1812433253          # Initialization multiplier

# Tempering constants
U, D = 11, 0xFFFFFFFF
S, B = 7,  0x9D2C5680
T, C = 15, 0xEFC60000
L = 18


def init(seed):
    """
    Initialize the internal state array from a seed.

    Parameters:
        seed : 32-bit integer seed

    Returns:
        State array of N=624 32-bit values
    """
    state = [seed & 0xFFFFFFFF]
    for i in range(1, N):
        prev = state[i - 1]
        # X_i = F * (X_{i-1} XOR (X_{i-1} >> 30)) + i
        state.append((F * (prev ^ (prev >> 30)) + i) & 0xFFFFFFFF)
    return state


def twist(state):
    """
    Apply the twist transformation to regenerate the state.

    Implements the recurrence over GF(2):
        x_{k+n} = x_{k+m} XOR ((x_k^upper | x_{k+1}^lower) * A)
    """
    for i in range(N):
        upper_bit = state[i] & 0x80000000           # Most significant bit of state[i]
        lower_bits = state[(i + 1) % N] & 0x7FFFFFFF  # Lower 31 bits of state[i+1]
        x = upper_bit | lower_bits
        x_shifted = x >> 1
        if x & 1:   # If LSB is 1: XOR with twist constant A
            x_shifted ^= A
        state[i] = state[(i + M) % N] ^ x_shifted   # M=397 ensures long-range mixing
    return state


def temper(y):
    """
    Apply the tempering transformation to improve output distribution.

    All four operations are bijective over GF(2)^32 (invertible).
    """
    y ^= (y >> U) & D
    y ^= (y << S) & B
    y ^= (y << T) & C
    y ^= y >> L
    return y & 0xFFFFFFFF


def generate(seed, n):
    """
    Generate n 32-bit pseudo-random integers.

    Parameters:
        seed : integer seed
        n    : number of values to generate

    Returns:
        List of n 32-bit integers
    """
    state = init(seed)
    index = N   # Force an immediate twist on first extraction
    results = []
    for _ in range(n):
        if index >= N:       # State exhausted: regenerate
            twist(state)
            index = 0
        results.append(temper(state[index]))
        index += 1
    return results


if __name__ == "__main__":
    print("MT19937 — seed=12345, 10 values:")
    output = generate(12345, 10)
    print(f"  {output}")
