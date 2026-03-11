# Cryptographic RNG — Implémentation & Attaques

**Projet Cybersécurité / Cryptographie** | école d'ingénieurs — Jan.–Fév. 2026 | Python (groupe de 3, 7 séances)

## Présentation

Implémentation et analyse comparative de générateurs de nombres pseudo-aléatoires (PRNG/CSPRNG) en Python. Tests statistiques rigoureux et démonstrations d'attaques pédagogiques.

## Générateurs implémentés

| Générateur | Type | Notes |
|:---|:---|:---|
| LCG | PRNG | Linear Congruential Generator |
| MT19937 | PRNG | Mersenne Twister (`random` Python) |
| Box-Muller | PRNG | Distribution gaussienne |
| BBS | CSPRNG | Blum-Blum-Shub |
| AES-CTR DRBG | CSPRNG | NIST SP 800-90A |
| AES-CBC PRNG | CSPRNG | CBC-mode based |
| `os.urandom` | CSPRNG | Entropie système |
| XOR NRBG | CSPRNG | Construction hybride |

## Tests statistiques

- **Entropie de Shannon** — mesure d'aléatoire
- **Chi-carré** — uniformité de la distribution
- **Autocorrélation** — lags 1, 8, ...
- **Kolmogorov-Smirnov** — comparaison de distributions

## Attaques démontrées

| Attaque | Cible | Méthode |
|:---|:---|:---|
| Récupération de graine | LCG | Résolution linéaire ou bruteforce |
| Reconstruction d'état | MT19937 | 624 sorties 32-bits suffisent |
| Fuite XOR | AES-CTR | Réutilisation de nonce |
| IV prévisible | AES-CBC | Prédiction du prochain bloc |

## Stack

`Python` · `numpy` · `scipy` · `matplotlib` · `pycryptodome`

---

*Projet académique — école d'ingénieurs*
