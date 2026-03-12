"""
Hash_DRBG (SHA-256) — NIST SP 800-90A
Deterministic Random Bit Generator based on SHA-256.
Simplified implementation conforming to NIST SP 800-90A Rev. 1.

Internal state: {"V": bytes, "C": bytes, "reseed_counter": int}
  - V and C are seedlen = 440 bits = 55 bytes each.

Security properties:
  - Forward secrecy (prediction resistance): observing current state does not
    allow predicting past outputs, because SHA-256 is a one-way function.
  - Reseed support: fresh entropy can be injected at any time.
"""

import hashlib
import os

SEED_LEN = 55   # seedlen for SHA-256 variant: 440 bits = 55 bytes


def _sha256(data):
    """Compute the SHA-256 hash of data."""
    return hashlib.sha256(data).digest()


def _hash_df(input_data, num_bytes):
    """
    Hash Derivation Function (Hash_df) — NIST SP 800-90A §10.3.1.

    Derives num_bytes of keying material from input_data using iterated SHA-256.
    The counter prefix ensures each block is distinct even for identical inputs.

    Parameters:
        input_data : bytes to derive from
        num_bytes  : number of output bytes required

    Returns:
        Derived bytes of length num_bytes
    """
    hash_len = 32   # SHA-256 output length in bytes
    num_blocks = (num_bytes + hash_len - 1) // hash_len
    result = b""
    for counter in range(1, num_blocks + 1):
        # counter (1 byte) || num_bytes (4 bytes) || input_data
        to_hash = counter.to_bytes(1, "big") + num_bytes.to_bytes(4, "big") + input_data
        result += _sha256(to_hash)
    return result[:num_bytes]


def drbg_instantiate(entropy=None, nonce=None, personalization=b""):
    """
    Instantiate the DRBG (initialize internal state).

    Follows NIST SP 800-90A §10.1.1.2.

    Parameters:
        entropy         : initial entropy bytes. If None, uses os.urandom.
        nonce           : nonce bytes. If None, uses os.urandom.
        personalization : optional personalization string (application-specific)

    Returns:
        state : dict with keys "V", "C", "reseed_counter"
    """
    if entropy is None:
        entropy = os.urandom(SEED_LEN)
    if nonce is None:
        nonce = os.urandom(SEED_LEN // 2)

    seed_material = entropy + nonce + personalization
    seed = _hash_df(seed_material, SEED_LEN)

    V = seed
    C = _hash_df(b"\x00" + seed, SEED_LEN)   # 0x00 = domain separation for C
    return {"V": V, "C": C, "reseed_counter": 1}


def drbg_reseed(state, entropy=None):
    """
    Reseed the DRBG with fresh entropy.

    After reseed, even an attacker who compromised the old state cannot
    predict future outputs (forward secrecy restored).

    Parameters:
        state   : current DRBG state
        entropy : new entropy bytes. If None, uses os.urandom.

    Returns:
        Updated state
    """
    if entropy is None:
        entropy = os.urandom(SEED_LEN)

    # 0x01 = domain separation prefix for reseed operation
    seed = _hash_df(b"\x01" + state["V"] + entropy, SEED_LEN)
    state["V"] = seed
    state["C"] = _hash_df(b"\x00" + seed, SEED_LEN)
    state["reseed_counter"] = 1
    return state


def drbg_generate(state, num_bytes):
    """
    Generate num_bytes of pseudo-random output.

    Generation loop: W = SHA256(V) || SHA256(V+1) || ...
    State update ensures backtracking resistance via:
        V_new = (V + SHA256(0x03 || V) + C + reseed_counter) mod 2^seedlen

    Parameters:
        state     : current DRBG state (modified in place)
        num_bytes : number of output bytes to produce

    Returns:
        (output_bytes, updated_state)
    """
    hash_len = 32
    m = (num_bytes + hash_len - 1) // hash_len

    # Generation phase: hash V, V+1, V+2, ...
    W = b""
    data = state["V"]
    for _ in range(m):
        W += _sha256(data)
        int_data = (int.from_bytes(data, "big") + 1) % (2 ** (len(data) * 8))
        data = int_data.to_bytes(len(state["V"]), "big")
    output = W[:num_bytes]

    # State update (backtracking resistance)
    H = _sha256(b"\x03" + state["V"])   # 0x03 = domain separation for update
    int_v = int.from_bytes(state["V"], "big")
    int_h = int.from_bytes(H, "big")
    int_c = int.from_bytes(state["C"], "big")
    mod = 2 ** (SEED_LEN * 8)
    new_v = (int_v + int_h + int_c + state["reseed_counter"]) % mod
    state["V"] = new_v.to_bytes(SEED_LEN, "big")
    state["reseed_counter"] += 1

    return output, state


def drbg_generate_bytes(n, entropy=None, nonce=None):
    """
    Convenience function: instantiate the DRBG and generate n bytes.

    Parameters:
        n       : number of output bytes
        entropy : optional fixed entropy (for testing/reproducibility)
        nonce   : optional fixed nonce (for testing/reproducibility)

    Returns:
        bytes of length n
    """
    state = drbg_instantiate(entropy=entropy, nonce=nonce)
    output, _ = drbg_generate(state, n)
    return output


if __name__ == "__main__":
    # Deterministic example with fixed entropy/nonce (for reproducibility)
    state = drbg_instantiate(entropy=b"A" * 55, nonce=b"B" * 28)
    print("Hash_DRBG (SHA-256) — 32 bytes:")
    data, state = drbg_generate(state, 32)
    print(f"  {data.hex()}")

    print("\nAfter reseed — 32 bytes:")
    state = drbg_reseed(state, b"C" * 55)
    data, state = drbg_generate(state, 32)
    print(f"  {data.hex()}")
