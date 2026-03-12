# Cryptographic RNG — Implementation & Attacks

**Cybersecurity / Cryptography Project** | Engineering School — Jan.–Feb. 2026 | Python 

---

## Overview

Implementation and comparative analysis of pseudo-random number generators (PRNG/CSPRNG) in Python. Includes rigorous statistical tests and pedagogical attack demonstrations.

---

## Project Structure

```
rng-project/
│
├── GENERATORS/
│   ├── PRNG_non_cryptographic/
│   │   ├── lcg.py                  # Linear Congruential Generator
│   │   └── mersenne_twister.py     # Mersenne Twister MT19937
│   │
│   ├── PRNG_Gaussian_distribution/
│   │   └── box_muller.py           # Box-Muller transform
│   │
│   ├── CSPRNG/
│   │   ├── bbs.py                  # Blum-Blum-Shub
│   │   ├── hash_drbg.py            # Hash_DRBG (NIST SP 800-90A)
│   │   └── os_random.py            # os.urandom (system entropy)
│   │
│   └── Non_deterministic_and_hybrid_generators/
│       └── xor_nrbg.py             # XOR NRBG (hybrid construction)
│
├── STATISTICS/
│   └── test_statistique.py         # Statistical test suite
│
├── ATTACKS/
│   ├── lcg_seed_recovery.py        # LCG seed recovery attacks
│   └── mt19937_state_recovery.py   # MT19937 state reconstruction
│
├── _visualisations.py              # Visualization utilities
├── _run_all_tests.py               # Full test runner
└── README.md
```

---

## Implemented Generators

| Generator      | Type   | Notes                                      |
|:---------------|:-------|:-------------------------------------------|
| LCG            | PRNG   | Linear Congruential Generator              |
| MT19937        | PRNG   | Mersenne Twister (Python's `random` module)|
| Box-Muller     | PRNG   | Gaussian (normal) distribution output      |
| BBS            | CSPRNG | Blum-Blum-Shub (QRP-based security proof)  |
| Hash_DRBG      | CSPRNG | NIST SP 800-90A, SHA-256 based             |
| `os.urandom`   | CSPRNG | OS-level entropy interface                 |
| XOR NRBG       | Hybrid | Multi-source XOR combination               |

---

## Statistical Tests

| Test                   | What it measures                              | Pass threshold            |
|:-----------------------|:----------------------------------------------|:--------------------------|
| **Shannon Entropy**    | Randomness per byte                           | H > 7.9 bits/byte         |
| **Chi-squared**        | Byte distribution uniformity                  | χ² < 293.25 (df=255, α=0.05) |
| **Autocorrelation**    | Correlation between values at lags 1, 8, …    | \|r\| < 0.05              |
| **Kolmogorov-Smirnov** | Empirical CDF vs. uniform distribution        | D < 1.36/√n               |

---

## Demonstrated Attacks

| Attack               | Target   | Method                                     |
|:---------------------|:---------|:-------------------------------------------|
| Seed recovery        | LCG      | Algebraic inversion (1 output), brute-force, known-plaintext XOR |
| State reconstruction | MT19937  | 624 consecutive 32-bit outputs are sufficient |

---

## Requirements

```
Python >= 3.8
```

No third-party libraries are required for the core generators, statistics, or attacks.  
Optional dependencies for visualizations:

```
numpy
scipy
matplotlib
```

Install them with:

```bash
pip install numpy scipy matplotlib
```

---

## How to Run

### Run the full test suite

```bash
python _run_all_tests.py
```

This verifies all 7 generators, 4 statistical tests, and 2 attacks.

### Run individual modules

```bash
# Generators
python generators/prng_non_cryptographic/lcg.py
python generators/prng_non_cryptographic/mersenne_twister.py
python generators/prng_Gaussian_distribution/box_muller.py
python generators/csprng/bbs.py
python generators/csprng/hash_drbg.py
python generators/csprng/os_random.py
python generators/non_deterministic_and_hybrid_generators/xor_nrbg.py

# Statistical tests
python statistics/test_statistique.py

# Attacks
python attacks/lcg_seed_recovery.py
python attacks/mt19937_state_recovery.py
```

### Expected output of `_run_all_tests.py`

```
GENERATOR TESTS
1. LCG           → output: [...]
2. MT19937       → output: [...]
3. Box-Muller    → output: (z0, z1)
4. Hash_DRBG     → output: <hex>
5. BBS           → output: [0, 1, ...]
6. XOR NRBG      → output: [...]
7. os.urandom    → output: <hex>
[OK] All generators working

STATISTICAL TESTS
1. Shannon Entropy  → H = ~7.99 bits/byte
2. Chi-squared      → χ² ≈ 255 ± 30
3. Autocorrelation  → r ≈ 0.000 [PASS]
4. Kolmogorov-Smirnov → D < critical value
[OK] All statistical tests working

ATTACK TESTS
1. LCG seed recovery   → Success: True
2. MT19937 state recon → 624 values recovered
[OK] All attacks working

SUMMARY
7 generators : OK
4 statistical tests : OK
2 attacks : OK
[SUCCESS] Project complete and functional
```

---

## Key Takeaway

> **Statistical quality ≠ cryptographic security.**

LCG and MT19937 pass all four statistical tests with scores comparable to CSPRNGs —
yet LCG is broken with a single output (algebraic inversion in O(log m)), and MT19937
is fully reconstructed in under a millisecond after 624 observations.

Use `os.urandom` or `Hash_DRBG` for any security-sensitive context (keys, nonces, tokens).  
Use LCG or MT19937 only for simulation, games, or reproducible unit tests.

---

## References

- Blum, Blum & Shub (1986) — *A simple unpredictable pseudo-random number generator*
- Box & Muller (1958) — *A note on the generation of random normal deviates*
- Matsumoto & Nishimura (1998) — *Mersenne Twister*
- NIST SP 800-90A Rev. 1 (2015) — *Hash_DRBG standard*
- Knuth (1997) — *The Art of Computer Programming, Vol. 2*

---

*Academic project — Engineering School*
