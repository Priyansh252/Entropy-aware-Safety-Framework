"""Empirical entropy assessment of byte samples.

IMPORTANT: Shannon entropy computed here is a *plug-in estimate of the byte-distribution of one
finite sample*. It is not the entropy of the underlying source and it does not prove (or
disprove) cryptographic security. Real RNG assessment needs source-level analysis (e.g. NIST
SP 800-90B) and health tests; none of that is claimed here.
"""
import math
import os
import random
from collections import Counter
from functools import lru_cache

SAMPLE_KINDS = ["uniform", "constant", "biased", "repeated_pattern", "repeated_values", "nonce_reuse"]

LIMITATIONS = [
    "Empirical Shannon entropy of a finite sample is not the true entropy of the source.",
    "A high value does not prove cryptographic security (e.g. the output of a fixed-seed PRNG scores high).",
    "A low value in one sample does not by itself identify a recoverable key or nonce.",
    "Byte-frequency entropy cannot see structure across values, e.g. a repeated 32-byte nonce.",
    "Small samples bias the plug-in estimator downward; compare against the ideal-uniform expectation.",
]


def shannon_entropy_bits(data: bytes) -> float:
    n = len(data)
    if n == 0:
        raise ValueError("empty sample")
    h = 0.0
    for c in Counter(data).values():
        p = c / n
        h -= p * math.log2(p)
    return h


@lru_cache(maxsize=256)
def expected_uniform_entropy(n: int) -> float:
    """Expected plug-in entropy (bits/byte) of n bytes drawn uniformly at random.
    Estimated by a small deterministic Monte Carlo (non-security use) for moderate n and by the
    Miller-Madow bias correction for large n."""
    if n <= 1:
        return 0.0
    if n > 200_000:
        return 8.0 - 255.0 / (2.0 * n * math.log(2))
    rng = random.Random(1234567)
    reps = 30 if n <= 20_000 else 8
    return sum(shannon_entropy_bits(rng.randbytes(n)) for _ in range(reps)) / reps


def _longest_run(data: bytes) -> int:
    best = cur = 1
    for i in range(1, len(data)):
        cur = cur + 1 if data[i] == data[i - 1] else 1
        best = max(best, cur)
    return best


def _duplicate_blocks(data: bytes, block: int = 32) -> dict:
    blocks = [data[i:i + block] for i in range(0, len(data) - block + 1, block)]
    cnt = Counter(blocks)
    dups = sum(c - 1 for c in cnt.values() if c > 1)
    return {"block_size": block, "blocks": len(blocks), "duplicate_blocks": dups,
            "distinct_blocks": len(cnt)}


def assess(data: bytes, block_size: int = 32) -> dict:
    n = len(data)
    if n < 2:
        raise ValueError("sample must contain at least 2 bytes")
    counts = Counter(data)
    h = shannon_entropy_bits(data)
    exp = expected_uniform_entropy(n)
    freq = [counts.get(i, 0) for i in range(256)]
    expected = n / 256.0
    chi2 = sum((c - expected) ** 2 / expected for c in freq)
    pmax = max(freq) / n
    dup = _duplicate_blocks(data, block_size)
    run = _longest_run(data)
    ratio = min(1.0, h / exp) if exp > 0 else 0.0

    indicators = []
    if len(counts) <= 8:
        indicators.append("very_small_alphabet")
    if run >= max(8, n // 8):
        indicators.append("long_constant_run")
    if dup["duplicate_blocks"] > 0:
        indicators.append("repeated_blocks")
    if ratio < 0.75:
        indicators.append("low_entropy_vs_ideal")
    elif ratio < 0.97:
        indicators.append("below_ideal_entropy")

    if "very_small_alphabet" in indicators or ratio < 0.75:
        interp = ("The byte distribution is strongly non-uniform. This is a clear statistical red flag "
                  "for this sample, but it is not a proof about any key or nonce.")
    elif "repeated_blocks" in indicators:
        interp = ("Byte-level entropy may look healthy, yet whole blocks repeat. Repeated "
                  "fixed-size values (such as nonces) are invisible to byte entropy and must be "
                  "checked directly.")
    elif ratio < 0.97:
        interp = ("Entropy is somewhat below what an ideal uniform sample of this size would give. "
                  "With small samples this can happen by chance; collect more data before concluding.")
    else:
        interp = ("The sample is statistically consistent with uniform bytes. This is NOT evidence "
                  "that the source is cryptographically secure; it only means this test found no bias.")

    return {
        "sample_size": n,
        "shannon_bits_per_byte": h,
        "normalized_entropy": h / 8.0,
        "expected_uniform_entropy": exp,
        "relative_to_ideal": ratio,
        "min_entropy_bits_per_byte": -math.log2(pmax),
        "unique_byte_values": len(counts),
        "max_frequency_ratio": pmax,
        "longest_run": run,
        "chi_square": chi2,
        "frequency": freq,
        "duplicate_blocks": dup,
        "indicators": indicators,
        "interpretation": interp,
        "limitations": LIMITATIONS,
    }


def generate_sample(kind: str, size: int, seed=None, bias: float = 0.5):
    """Synthetic samples for education. A seed gives reproducible *synthetic* data only;
    unseeded 'uniform' samples come from the OS CSPRNG."""
    if kind not in SAMPLE_KINDS:
        raise ValueError(f"unknown sample kind: {kind}")
    if size < 2:
        raise ValueError("size must be >= 2")
    seeded = seed is not None
    rng = random.Random(seed) if seeded else random.SystemRandom()
    if kind == "uniform":
        data = rng.randbytes(size) if seeded else os.urandom(size)
    elif kind == "constant":
        data = bytes([rng.randrange(256)]) * size
    elif kind == "biased":
        out = bytearray()
        for _ in range(size):
            out.append(rng.randrange(16) if rng.random() < bias else rng.randrange(256))
        data = bytes(out)
    elif kind == "repeated_pattern":
        pat = bytes(rng.randrange(256) for _ in range(8))
        data = (pat * (size // 8 + 1))[:size]
    elif kind == "repeated_values":
        alphabet = [rng.randrange(256) for _ in range(16)]
        data = bytes(rng.choice(alphabet) for _ in range(size))
    else:  # nonce_reuse: 32-byte values, half of them exact repeats of earlier ones
        m = max(2, size // 32)
        uniq = [bytes(rng.randrange(256) for _ in range(32)) for _ in range(max(1, m // 2))]
        blocks = list(uniq) + [rng.choice(uniq) for _ in range(m - len(uniq))]
        data = b"".join(blocks)
        if len(data) < size:
            data += bytes(rng.randrange(256) for _ in range(size - len(data)))
        data = data[:max(size, 64)]
    return data, {"kind": kind, "seeded_synthetic": seeded, "bias": bias if kind == "biased" else None}
