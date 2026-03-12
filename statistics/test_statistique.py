"""
Statistical Test Suite for Random Number Generators

Evaluates byte sequences (values in [0, 255]).
Significance level: α = 0.05 — a perfect generator would fail ~5% of tests by chance.

Tests implemented:
    1. Shannon Entropy
    2. Chi-squared uniformity test
    3. Autocorrelation test
    4. Kolmogorov-Smirnov test
"""

import math
from collections import Counter


# ─────────────────────────────────────────────
# 1. Shannon Entropy
# https://en.wikipedia.org/wiki/Entropy_(information_theory)
# ─────────────────────────────────────────────

def shannon_entropy(data):
    """
    Compute the Shannon entropy of a byte sequence (in bits per byte).

    H(X) = -∑ p_i * log2(p_i)

    Interpretation:
        H = 8 bits/byte → perfect entropy (fully random)
        H < 8 bits/byte → some predictability or repeated patterns

    Important limitation: Shannon entropy measures marginal distribution only.
    A sequence like [0, 1, 2, ..., 255, 0, 1, ...] would score H=8 yet is trivially
    predictable. It does NOT detect inter-symbol correlations.

    Parameters:
        data : bytes or list of integers in [0, 255]

    Returns:
        Entropy in bits per byte (float in [0.0, 8.0])
    """
    if not data:
        return 0.0

    freq = Counter(data)
    n = len(data)

    entropy = 0.0
    for count in freq.values():
        p = count / n   # Maximum likelihood estimate: p_i = count_i / n
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def shannon_entropy_report(data):
    """
    Detailed Shannon entropy report.

    Returns:
        dict with entropy, max_entropy, percentage, status
    """
    entropy = shannon_entropy(data)
    max_entropy = 8.0   # log2(256) = 8 bits

    return {
        'entropy': entropy,
        'max_entropy': max_entropy,
        'percentage': (entropy / max_entropy) * 100,
        'status': 'PASS' if entropy > 7.9 else 'FAIL'
    }


# ─────────────────────────────────────────────
# 2. Chi-Squared Uniformity Test
# https://en.wikipedia.org/wiki/Chi-squared_test
# ─────────────────────────────────────────────

def chi_squared_test(data, alpha=0.05):
    """
    Test whether byte values are uniformly distributed over [0, 255].

    H0: bytes are uniformly distributed (each value has probability 1/256)
    H1: bytes are not uniformly distributed

    Statistic:
        χ² = Σ (O_i - E)² / E,   E = n / 256,   df = 255

    Critical value for α=0.05, df=255: χ²_crit ≈ 293.25
    (i.e. ~2.1 standard deviations above the expected value of 255)

    Parameters:
        data  : bytes or list of integers in [0, 255]
        alpha : significance level (default 0.05)

    Returns:
        dict with chi2 statistic, degrees of freedom, critical value, p-value label, status
    """
    if not data:
        return None

    freq = Counter(data)
    n = len(data)
    expected = n / 256   # Expected frequency per byte value under H0

    chi2 = 0.0
    for i in range(256):
        observed = freq.get(i, 0)   # Missing values contribute (0 - E)²/E = E
        chi2 += ((observed - expected) ** 2) / expected

    df = 255
    critical_value = 293.25   # Hardcoded to avoid scipy dependency

    return {
        'chi2': chi2,
        'degrees_freedom': df,
        'critical_value': critical_value,
        'p_value': "< 0.05" if chi2 > critical_value else "> 0.05",
        'status': 'PASS' if chi2 < critical_value else 'FAIL'
    }


# ─────────────────────────────────────────────
# 3. Autocorrelation Test
# https://en.wikipedia.org/wiki/Autocorrelation
# ─────────────────────────────────────────────

def autocorrelation(data, lag=1):
    """
    Compute the autocorrelation coefficient at a given lag.

    r(k) = Cov(X_i, X_{i+k}) / Var(X)

    Interpretation:
        r ≈ 0      → no correlation (good)
        |r| > 0.05 → detectable correlation (suspicious)

    For i.i.d. data of size n: r(k) ~ N(0, 1/n)
    95% confidence interval: [-1.96/√n, +1.96/√n]
    For n=10000: ±0.0196

    Parameters:
        data : list of numeric values
        lag  : offset k (1 = consecutive values)

    Returns:
        Autocorrelation coefficient in [-1, 1]
    """
    if len(data) < lag + 1:
        return 0.0

    n = len(data) - lag
    mean = sum(data) / len(data)
    variance = sum((x - mean) ** 2 for x in data)

    if variance == 0:
        return 0.0   # Constant data: undefined → return 0 by convention

    covariance = sum((data[i] - mean) * (data[i + lag] - mean) for i in range(n))
    return covariance / variance


def autocorrelation_test(data, lags=None):
    """
    Run the autocorrelation test for multiple lag values.

    lag=1 detects consecutive correlations (most critical for LCG).
    Larger lags detect longer-range periodicities.

    Parameters:
        data : bytes or list of integers in [0, 255]
        lags : list of lag values to test (default: [1, 8, 16, 32])

    Returns:
        dict mapping 'lag_k' to {'coefficient': float, 'status': str}
    """
    if lags is None:
        lags = [1, 8, 16, 32]

    if isinstance(data, bytes):
        data = list(data)

    results = {}
    threshold = 0.05   # Tolerance threshold for |r|

    for lag in lags:
        r = autocorrelation(data, lag)
        results[f'lag_{lag}'] = {
            'coefficient': r,
            'status': 'PASS' if abs(r) < threshold else 'FAIL'
        }

    return results


# ─────────────────────────────────────────────
# 4. Kolmogorov-Smirnov Test
# https://en.wikipedia.org/wiki/Kolmogorov%E2%80%93Smirnov_test
# ─────────────────────────────────────────────

def kolmogorov_smirnov_test(data):
    """
    KS test: compare the empirical CDF to the uniform distribution on [0, 255].

    H0: data follows the uniform distribution on [0, 255]
    H1: data does not follow this distribution

    Statistic:
        D_n = sup_x |F_n(x) - F(x)|

    Asymptotic critical value (n > 35, α=0.05):
        D_crit = 1.36 / √n   (Kolmogorov, 1933)

    Unlike χ², the KS test is sensitive to the shape of the distribution,
    not just the frequencies — it detects shifts, stretches, and skewness.

    Parameters:
        data : bytes or list of integers in [0, 255]

    Returns:
        dict with D statistic, critical value, sample size, status
    """
    if not data:
        return None

    # Normalize to [0, 1] and sort
    normalized = sorted([x / 255.0 for x in data])
    n = len(normalized)

    max_diff = 0.0
    for i, value in enumerate(normalized):
        empirical = (i + 1) / n   # F_n(x): rank / n after sorting
        theoretical = value        # F(x) = x (uniform on [0, 1])
        diff = abs(empirical - theoretical)
        max_diff = max(max_diff, diff)

    critical_value = 1.36 / math.sqrt(n)

    return {
        'D': max_diff,
        'critical_value': critical_value,
        'n': n,
        'status': 'PASS' if max_diff < critical_value else 'FAIL'
    }


# ─────────────────────────────────────────────
# Full report
# ─────────────────────────────────────────────

def full_statistical_report(data):
    """
    Run all four statistical tests on a data sample.

    Parameters:
        data : bytes or list of integers in [0, 255]

    Returns:
        dict with results of all tests and a global verdict
    """
    if isinstance(data, bytes):
        data_list = list(data)
    else:
        data_list = data

    report = {
        'data_size': len(data_list),
        'shannon_entropy': shannon_entropy_report(data_list),
        'chi_squared': chi_squared_test(data_list),
        'autocorrelation': autocorrelation_test(data_list),
        'kolmogorov_smirnov': kolmogorov_smirnov_test(data_list)
    }

    tests_passed = sum([
        report['shannon_entropy']['status'] == 'PASS',
        report['chi_squared']['status'] == 'PASS',
        all(v['status'] == 'PASS' for v in report['autocorrelation'].values()),
        report['kolmogorov_smirnov']['status'] == 'PASS'
    ])

    report['global_status'] = {
        'passed': tests_passed,
        'total': 4,
        'verdict': 'PASS' if tests_passed >= 3 else 'FAIL'
    }

    return report


def print_report(report):
    """Pretty-print a full statistical report."""
    print("=" * 50)
    print("STATISTICAL TEST REPORT")
    print("=" * 50)

    print(f"\nSample size: {report['data_size']} bytes")

    print("\n1. SHANNON ENTROPY")
    ent = report['shannon_entropy']
    print(f"   Entropy    : {ent['entropy']:.4f} bits/byte")
    print(f"   Maximum    : {ent['max_entropy']:.4f} bits/byte")
    print(f"   Coverage   : {ent['percentage']:.2f}%")
    print(f"   Verdict    : {ent['status']}")

    print("\n2. CHI-SQUARED TEST (uniformity)")
    chi = report['chi_squared']
    print(f"   χ²              = {chi['chi2']:.2f}")
    print(f"   Degrees of freedom: {chi['degrees_freedom']}")
    print(f"   Critical value (α=0.05): {chi['critical_value']:.2f}")
    print(f"   p-value    : {chi['p_value']}")
    print(f"   Verdict    : {chi['status']}")

    print("\n3. AUTOCORRELATION TEST")
    for lag_name, result in report['autocorrelation'].items():
        lag_num = lag_name.split('_')[1]
        print(f"   Lag {lag_num:>2}: r = {result['coefficient']:+.6f}  [{result['status']}]")

    print("\n4. KOLMOGOROV-SMIRNOV TEST")
    ks = report['kolmogorov_smirnov']
    print(f"   D               = {ks['D']:.6f}")
    print(f"   Critical value  = {ks['critical_value']:.6f}")
    print(f"   Verdict         : {ks['status']}")

    print("\n" + "=" * 50)
    print("GLOBAL VERDICT")
    print("=" * 50)
    gs = report['global_status']
    print(f"   Tests passed : {gs['passed']}/{gs['total']}")
    print(f"   STATUS       : {gs['verdict']}")
    print("=" * 50 + "\n")


# ─────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import os

    print("Unit tests — three scenarios\n")

    print("Test 1: os.urandom (reference — expected: all PASS)")
    report1 = full_statistical_report(os.urandom(10000))
    print_report(report1)

    print("Test 2: Biased data (repeating pattern [0, 1, 2, ...])")
    biased = bytes([0, 1, 2] * 1000)
    report2 = full_statistical_report(biased)
    print_report(report2)

    print("Test 3: Constant data (0x42 repeated — worst case)")
    constant = bytes([0x42] * 1000)
    report3 = full_statistical_report(constant)
    print_report(report3)
