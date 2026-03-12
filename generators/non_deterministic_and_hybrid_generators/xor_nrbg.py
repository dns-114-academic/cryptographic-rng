"""
XOR NRBG — Non-Deterministic Random Bit Generator
Combines multiple entropy sources via XOR for fault-tolerant randomness.

Theoretical guarantee (XOR entropy preservation):
    If at least one source is uniformly distributed AND independent of the others,
    then the XOR combination is also uniformly distributed — regardless of how
    bad the other sources are.

    Corollary: H∞(X1 ⊕ ... ⊕ Xk) ≥ max(H1, ..., Hk)

Limitation: if ALL sources are correlated or simultaneously compromised,
the guarantee no longer holds.

https://en.wikipedia.org/wiki/Exclusive_or
"""


def xor_combine_bits(sources):
    """
    Bitwise XOR combination of multiple bit sequences.

    Parameters:
        sources : list of bit lists, e.g. [[1, 0, 1], [0, 1, 1], [1, 1, 0]]
                  All inner lists must have the same length.

    Returns:
        List of XOR-combined bits
    """
    if not sources:
        return []

    n = len(sources[0])
    result = []
    for i in range(n):
        bit = 0   # Neutral element: 0 XOR x = x
        for source in sources:
            bit ^= source[i]
        result.append(bit)
    return result


def xor_combine_bytes(sources):
    """
    Bytewise XOR combination of multiple byte sequences.
    Equivalent to running xor_combine_bits on 8 parallel bit streams.

    Parameters:
        sources : list of bytes objects (all the same length)

    Returns:
        XOR-combined bytes
    """
    if not sources:
        return b''

    n = len(sources[0])
    result = bytearray(n)   # Initialized to 0x00 (neutral element for XOR)
    for i in range(n):
        xor_val = 0
        for source in sources:
            xor_val ^= source[i]
        result[i] = xor_val
    return bytes(result)


def xor_nrbg(generators, seeds, n):
    """
    Hybrid generator: combine multiple PRNGs via XOR.

    Advantage: if one generator is compromised but the others remain healthy,
    the combined output stays unpredictable.

    Parameters:
        generators : list of generator functions, each with signature (seed, n) -> list
        seeds      : list of seeds, one per generator
        n          : number of values to produce

    Returns:
        List of n XOR-combined values
    """
    if len(generators) != len(seeds):
        raise ValueError("Number of generators must equal number of seeds")

    # Evaluate all generators independently
    outputs = [gen(seed, n) for gen, seed in zip(generators, seeds)]

    result = []
    for i in range(n):
        xor_val = 0
        for output in outputs:
            xor_val ^= output[i]
        result.append(xor_val)
    return result


if __name__ == "__main__":
    print("XOR combination — bits:")
    src_bits = [[1, 0, 1, 1], [0, 1, 1, 0], [1, 1, 0, 1]]
    print(f"  Sources : {src_bits}")
    print(f"  XOR     : {xor_combine_bits(src_bits)}")

    print("\nXOR combination — bytes:")
    src_bytes = [b'\xAA\xBB', b'\x55\x44', b'\xFF\x00']
    print(f"  Sources : {[s.hex() for s in src_bytes]}")
    print(f"  XOR     : {xor_combine_bytes(src_bytes).hex()}")

    print("\nXOR combination — two simple generators:")
    gen1 = lambda seed, n: [(seed + i) % 256 for i in range(n)]
    gen2 = lambda seed, n: [(seed * 2 + i) % 256 for i in range(n)]
    result = xor_nrbg([gen1, gen2], [42, 17], 5)
    print(f"  XOR(gen1, gen2) : {result}")
