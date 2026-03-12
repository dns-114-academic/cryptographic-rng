"""
System Entropy Interface (os.urandom)
Wraps the operating system's cryptographically secure entropy source.

Under Linux  : getrandom() syscall → ChaCha20-DRBG seeded by the kernel entropy pool
               (/dev/urandom, hardware events, RDRAND, etc.)
Under Windows: CryptGenRandom()

Since Linux 5.6, /dev/random and /dev/urandom are equivalent.
os.urandom blocks only at boot until the entropy pool is initialized (~128 bits
of min-entropy gathered). After that, it is non-blocking and always safe.

This is the recommended source for any security-sensitive randomness in Python
(keys, nonces, tokens, IV, salts). Use the `secrets` module for higher-level APIs.
"""

import os


def os_generate_bytes(n):
    """
    Generate n cryptographically random bytes from the OS entropy source.

    Parameters:
        n : number of bytes to generate

    Returns:
        bytes of length n
    """
    return os.urandom(n)


def os_next_int32():
    """
    Return a random 32-bit unsigned integer.

    Returns:
        Integer in [0, 2^32 - 1]
    """
    return int.from_bytes(os.urandom(4), "big")


def os_next_float():
    """
    Return a random float in [0, 1).

    The division by 2^32 (not 2^32 - 1) ensures the upper bound is excluded,
    which is the correct convention for algorithms such as Box-Muller that
    require U in (0, 1).

    Returns:
        Float in [0.0, 1.0)
    """
    return os_next_int32() / (2**32)


if __name__ == "__main__":
    print("os.urandom — 10 random 32-bit integers:")
    for _ in range(10):
        print(f"  {os_next_int32()}")
    data = os_generate_bytes(16)
    print(f"\n16 random bytes: {data.hex()}")
