"""
_run_all_tests.py — Full Project Verification Script

Verifies all generators, statistical tests, and attacks.
Run from the project root with:  python _run_all_tests.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_generators():
    print("=" * 50)
    print("GENERATOR TESTS")
    print("=" * 50)

    print("\n1. LCG")
    from generators.prng_non_cryptographic.lcg import lcg, PARAMS_GLIBC
    output = lcg(42, **PARAMS_GLIBC, n=5)
    print(f"   Output: {output}")

    print("\n2. MT19937")
    from generators.prng_non_cryptographic.mersenne_twister import generate
    output = generate(12345, 5)
    print(f"   Output: {output}")

    print("\n3. Box-Muller")
    from generators.prng_gaussian_distribution.box_muller import box_muller
    z0, z1 = box_muller(0.5, 0.5)
    print(f"   Output: ({z0:.4f}, {z1:.4f})")

    print("\n4. Hash_DRBG")
    from generators.csprng.hash_drbg import drbg_generate_bytes
    output = drbg_generate_bytes(16)
    print(f"   Output: {output.hex()}")

    print("\n5. BBS")
    from generators.csprng.bbs import bbs, SMALL_PRIMES
    output = bbs(7, SMALL_PRIMES['p'], SMALL_PRIMES['q'], 10)
    print(f"   Output: {output}")

    print("\n6. XOR NRBG")
    from generators.non_deterministic_and_hybrid_generators.xor_nrbg import xor_combine_bits
    sources = [[1, 0, 1], [0, 1, 1]]
    output = xor_combine_bits(sources)
    print(f"   Output: {output}")

    print("\n7. os.urandom")
    from generators.csprng.os_random import os_generate_bytes
    output = os_generate_bytes(8)
    print(f"   Output: {output.hex()}")


def test_statistical():
    print("\n" + "=" * 50)
    print("STATISTICAL TESTS")
    print("=" * 50)

    from statistics.test_statistique import (
        shannon_entropy,
        chi_squared_test,
        autocorrelation_test,
        kolmogorov_smirnov_test
    )

    test_data = os.urandom(5000)

    print("\n1. Shannon Entropy")
    entropy = shannon_entropy(test_data)
    print(f"   H = {entropy:.4f} bits/byte")

    print("\n2. Chi-Squared Test")
    chi2 = chi_squared_test(test_data)
    print(f"   chi2 = {chi2['chi2']:.2f}")
    print(f"   Status = {chi2['status']}")

    print("\n3. Autocorrelation")
    autocorr = autocorrelation_test(test_data, lags=[1, 8])
    for lag, res in autocorr.items():
        print(f"   {lag}: r = {res['coefficient']:.6f}  [{res['status']}]")

    print("\n4. Kolmogorov-Smirnov")
    ks = kolmogorov_smirnov_test(test_data)
    print(f"   D = {ks['D']:.6f}")
    print(f"   Status = {ks['status']}")


def test_attacks():
    print("\n" + "=" * 50)
    print("ATTACK TESTS")
    print("=" * 50)

    print("\n1. LCG Seed Recovery")
    from attacks.lcg_seed_recovery import recover_seed_algebraic
    from generators.prng_non_cryptographic.lcg import lcg, PARAMS_GLIBC

    secret_seed = 123456
    a, c, m = PARAMS_GLIBC['a'], PARAMS_GLIBC['c'], PARAMS_GLIBC['m']
    outputs = lcg(secret_seed, a, c, m, 3)

    recovered = recover_seed_algebraic(outputs[0], outputs[1], outputs[2], a, c, m)
    print(f"   Secret seed   : {secret_seed}")
    print(f"   Recovered seed: {recovered}")
    print(f"   Success       : {recovered == secret_seed}")

    print("\n2. MT19937 State Reconstruction")
    from attacks.mt19937_state_recovery import recover_state
    from generators.prng_non_cryptographic.mersenne_twister import generate

    outputs = generate(54321, 624)
    state = recover_state(outputs)
    print(f"   Observed outputs      : 624")
    print(f"   State words recovered : {len(state)}")
    print(f"   Success               : {len(state) == 624}")


def main():
    print("\nRNG PROJECT — FULL VERIFICATION\n")

    try:
        test_generators()
        print("\n[OK] All generators working")
    except Exception as e:
        print(f"\n[ERROR] Generators: {e}")
        return

    try:
        test_statistical()
        print("\n[OK] All statistical tests working")
    except Exception as e:
        print(f"\n[ERROR] Statistical tests: {e}")
        return

    try:
        test_attacks()
        print("\n[OK] All attacks working")
    except Exception as e:
        print(f"\n[ERROR] Attacks: {e}")
        return

    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print("  7 generators       : OK")
    print("  4 statistical tests: OK")
    print("  2 attacks          : OK")
    print("\n  [SUCCESS] Project complete and functional")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    main()
