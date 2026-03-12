"""
Pedagogical Attack: LCG Seed Recovery
Demonstrates why LCG is UNSUITABLE for cryptographic use.

Three attack methods:
    1. Algebraic inversion  — O(log m), requires 1 output
    2. Brute-force search   — O(seed_max), requires a small seed space
    3. Known-plaintext XOR  — O(seed_max), requires one (plaintext, ciphertext) pair

DISCLAIMER: These techniques are strictly pedagogical. Applying them to real
systems without explicit authorization is illegal (e.g. French law: art. 323-1 Penal Code).
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from generators.prng_non_cryptographic.lcg import lcg, PARAMS_GLIBC


# ──────────────────────────────────────────────────────────
# METHOD 1: ALGEBRAIC INVERSION
# ──────────────────────────────────────────────────────────

def recover_seed_algebraic(x1, x2, x3, a, c, m):
    """
    Recover the seed X0 from 3 consecutive LCG outputs.

    Mathematical principle:
        X1 = (a * X0 + c) mod m
        → X0 = (X1 - c) * a^{-1} mod m

    Complexity: O(log m) for the modular inverse (extended Euclidean algorithm).
    The parameters (a, c, m) are assumed to be public (Kerckhoffs' principle).

    Parameters:
        x1, x2, x3 : three consecutive observed outputs
        a, c, m     : LCG parameters

    Returns:
        Recovered seed X0, or None if the modular inverse does not exist
    """
    try:
        a_inv = pow(a, -1, m)   # Modular inverse (Python 3.8+)
    except ValueError:
        print("Error: gcd(a, m) ≠ 1 — modular inverse does not exist")
        return None

    x0 = ((x1 - c) * a_inv) % m   # x1 - c may be negative; % is always positive in Python
    return x0


# ──────────────────────────────────────────────────────────
# METHOD 2: BRUTE-FORCE SEARCH
# ──────────────────────────────────────────────────────────

def recover_seed_bruteforce(outputs, a, c, m, seed_max=1_000_000):
    """
    Exhaustive search over a limited seed space.

    Applicable scenario: weak seed (e.g. Unix timestamp, PID, short counter).
    For a timestamp in seconds, the search space is ~86 400 per day — trivial.

    Complexity: O(seed_max × len(outputs))

    Parameters:
        outputs  : list of observed outputs (≥3 for reliable validation)
        a, c, m  : LCG parameters
        seed_max : upper bound of the search space

    Returns:
        Matching seed, or None if not found
    """
    for candidate in range(seed_max):
        generated = lcg(candidate, a, c, m, len(outputs))
        if generated == outputs:
            return candidate
    return None


# ──────────────────────────────────────────────────────────
# METHOD 3: KNOWN-PLAINTEXT (XOR stream cipher)
# ──────────────────────────────────────────────────────────

def xor_bytes(b1, b2):
    """Bytewise XOR of two equal-length byte strings."""
    return bytes(a ^ b for a, b in zip(b1, b2))


def recover_seed_from_xor(plaintext, ciphertext, a, c, m, seed_max=100_000):
    """
    Known-plaintext attack on XOR encryption using an LCG keystream.

    Scenario:
        1. Victim encrypts: C = P XOR LCG_keystream
        2. Attacker knows both P (plaintext) and C (ciphertext)
        3. Attacker recovers keystream: K = P XOR C
        4. Brute-force the seed until a matching keystream is found

    Parameters:
        plaintext  : known plaintext bytes
        ciphertext : intercepted ciphertext bytes
        a, c, m    : LCG parameters
        seed_max   : seed search space upper bound

    Returns:
        Recovered seed, or None if not found
    """
    # Step 1: Recover the keystream
    keystream = xor_bytes(plaintext, ciphertext)
    keystream_ints = list(keystream)

    # Step 2: Search for the seed that produces this keystream
    for candidate in range(seed_max):
        generated = lcg(candidate, a, c, m, len(keystream))
        generated_bytes = [x % 256 for x in generated]   # Reduce each output to 1 byte

        if generated_bytes == keystream_ints:
            return candidate

    return None


# ──────────────────────────────────────────────────────────
# DEMONSTRATIONS
# ──────────────────────────────────────────────────────────

def demo_1_algebraic():
    """Demo: Seed recovery from 3 observed outputs."""
    print("=" * 60)
    print("ATTACK 1 — Algebraic inversion")
    print("=" * 60)
    print("\nThreat model:")
    print("  - Attacker observes 3 consecutive LCG outputs")
    print("  - Parameters (a, c, m) are public/known")
    print("  - Goal: recover X0 and predict all future outputs")

    a, c, m = PARAMS_GLIBC['a'], PARAMS_GLIBC['c'], PARAMS_GLIBC['m']
    secret_seed = 123_456_789

    outputs = lcg(secret_seed, a, c, m, 3)
    print(f"\n[Victim]   Secret seed   : {secret_seed}")
    print(f"[Victim]   Outputs (x1,x2,x3): {outputs[:3]}")

    print("\n[Attacker] Observes 3 outputs and inverts...")
    recovered = recover_seed_algebraic(outputs[0], outputs[1], outputs[2], a, c, m)
    print(f"[Attacker] Recovered seed : {recovered}")
    print(f"\n   ✓ Success: {recovered == secret_seed}")

    # Predict future outputs
    print("\nPredicting next 5 outputs:")
    future_real = lcg(secret_seed, a, c, m, 8)[3:]
    future_pred = lcg(recovered,   a, c, m, 8)[3:]
    print(f"  Real      : {future_real}")
    print(f"  Predicted : {future_pred}")
    print(f"  Match     : {future_real == future_pred}")

    print("\n[Conclusion] LCG fully compromised from 3 outputs — O(log m) attack.\n")


def demo_2_bruteforce():
    """Demo: Brute-force over a small seed space."""
    print("=" * 60)
    print("ATTACK 2 — Brute-force (limited seed space)")
    print("=" * 60)
    print("\nThreat model:")
    print("  - Seed is weak (e.g. PID, truncated timestamp)")
    print("  - Search space: [0, 100 000)")
    print("  - Multiple outputs available for validation")

    a, c, m = PARAMS_GLIBC['a'], PARAMS_GLIBC['c'], PARAMS_GLIBC['m']
    secret_seed = 42_424
    outputs = lcg(secret_seed, a, c, m, 5)

    print(f"\n[Victim]   Seed (in [0, 100000)): {secret_seed}")
    print(f"[Victim]   Outputs: {outputs}")

    print("\n[Attacker] Launching exhaustive search...")
    recovered = recover_seed_bruteforce(outputs, a, c, m, seed_max=100_000)
    print(f"[Attacker] Seed found: {recovered}")
    print(f"\n   ✓ Success: {recovered == secret_seed}")

    print("\n[Conclusion] Weak seeds = trivially broken. Never seed with timestamps alone.\n")


def demo_3_known_plaintext():
    """Demo: Known-plaintext attack on XOR + LCG encryption."""
    print("=" * 60)
    print("ATTACK 3 — Known-plaintext (XOR stream cipher + LCG)")
    print("=" * 60)
    print("\nThreat model:")
    print("  - Victim encrypts: C = P XOR LCG_keystream")
    print("  - Attacker knows/guesses plaintext P")
    print("  - Attacker intercepts ciphertext C")
    print("  - Goal: recover the seed and decrypt future messages")

    a, c, m = PARAMS_GLIBC['a'], PARAMS_GLIBC['c'], PARAMS_GLIBC['m']
    secret_seed = 31_337
    plaintext = b"ATTACK_AT_DAWN"

    # Victim encrypts
    keystream_vals = lcg(secret_seed, a, c, m, len(plaintext))
    keystream = bytes([x % 256 for x in keystream_vals])
    ciphertext = xor_bytes(plaintext, keystream)

    print(f"\n[Victim]   Plaintext  : {plaintext}")
    print(f"[Victim]   Ciphertext : {ciphertext.hex()}")

    # Attack
    print("\n[Attacker] Recovers keystream: K = P XOR C")
    recovered_ks = xor_bytes(plaintext, ciphertext)
    print(f"[Attacker] Keystream   : {recovered_ks.hex()}")

    print("\n[Attacker] Brute-forcing seed...")
    recovered_seed = recover_seed_from_xor(plaintext, ciphertext, a, c, m, seed_max=50_000)
    print(f"\n[Attacker] Recovered seed: {recovered_seed}")
    print(f"   ✓ Success: {recovered_seed == secret_seed}")

    # Exploit: decrypt another message
    print("\nExploitation — decrypting a second intercepted message:")
    other_plaintext = b"SECRET_KEY_42"
    other_ks_vals = lcg(recovered_seed, a, c, m, len(other_plaintext))
    other_ks = bytes([x % 256 for x in other_ks_vals[:len(other_plaintext)]])
    other_ciphertext = xor_bytes(other_plaintext, other_ks)
    decrypted = xor_bytes(other_ciphertext, other_ks)

    print(f"[Victim]   Encrypts new message: {other_ciphertext.hex()}")
    print(f"[Attacker] Decrypts            : {decrypted}")
    print(f"   ✓ Decryption correct: {decrypted == other_plaintext}")

    print("\n[Conclusion] Using LCG as a keystream is catastrophic.\n")


def run_all_attacks():
    """Run all three LCG attack demonstrations."""
    print("\n" + "=" * 60)
    print("  PEDAGOGICAL DEMOS — ATTACKS AGAINST LCG")
    print("=" * 60 + "\n")

    demo_1_algebraic()
    demo_2_bruteforce()
    demo_3_known_plaintext()


if __name__ == "__main__":
    run_all_attacks()
