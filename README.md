# Cryptographic RNG — Implementation & Attacks

**Course project** | école d'ingénieurs — Jan.–Feb. 2026 | Python

## Overview

Implementation and comparative analysis of PRNG/CSPRNG families, combined with practical cryptanalytic attacks.

## Generators Implemented

| Generator | Type | Notes |
|---|---|---|
| LCG | PRNG | Linear Congruential Generator |
| MT19937 | PRNG | Mersenne Twister (Python's `random`) |
| BBS | CSPRNG | Blum-Blum-Shub |
| AES-CTR DRBG | CSPRNG | NIST SP 800-90A |
| AES-CBC PRNG | CSPRNG | CBC-mode based |

## Statistical Validation

- Chi-squared test
- Shannon entropy
- Kolmogorov-Smirnov test
- Frequency / monobit test (NIST)

## Attacks

- **LCG** — seed recovery from output sequence
- **MT19937** — full state reconstruction from 624 consecutive outputs
- **AES-CTR** — nonce reuse attack
- **AES-CBC** — predictable IV attack

## Stack

`Python` · `pycryptodome` · `numpy` · `scipy`

---

*Academic project — école d'ingénieurs*
