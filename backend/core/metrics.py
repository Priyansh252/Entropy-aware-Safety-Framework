"""Statistical helpers with explicit definitions."""
import math
import statistics
from typing import Iterable


def wilson_ci(k: int, n: int, z: float = 1.96):
    """Wilson score interval for a binomial proportion (95% by default)."""
    if n <= 0:
        return (None, None)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def rate(k: int, n: int) -> dict:
    lo, hi = wilson_ci(k, n)
    return {"k": int(k), "n": int(n), "rate": (k / n) if n else None, "ci_low": lo, "ci_high": hi}


def summarize(values: Iterable[float]) -> dict:
    v = [float(x) for x in values]
    n = len(v)
    if n == 0:
        return {"n": 0, "mean": None, "median": None, "std": None, "min": None, "max": None,
                "p95": None, "ci_low": None, "ci_high": None}
    mean = statistics.fmean(v)
    std = statistics.stdev(v) if n > 1 else 0.0
    half = 1.96 * std / math.sqrt(n) if n > 1 else 0.0
    s = sorted(v)
    p95 = s[min(n - 1, int(math.ceil(0.95 * n)) - 1)]
    return {"n": n, "mean": mean, "median": statistics.median(v), "std": std, "min": s[0],
            "max": s[-1], "p95": p95, "ci_low": mean - half, "ci_high": mean + half}


def confusion(tp: int, fp: int, tn: int, fn: int) -> dict:
    """Detection metrics. Positive = truly vulnerable.
    detection_rate (recall) = TP/(TP+FN); false_positive_rate = FP/(FP+TN)
    (== false rejection rate when 'flagged' means 'rejected' and negatives are safe candidates)."""
    out = {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
    out["detection_rate"] = rate(tp, tp + fn)
    out["false_positive_rate"] = rate(fp, fp + tn)
    out["precision"] = (tp / (tp + fp)) if (tp + fp) else None
    out["accuracy"] = ((tp + tn) / (tp + fp + tn + fn)) if (tp + fp + tn + fn) else None
    return out


def overhead_pct(baseline_mean, defended_mean):
    if not baseline_mean:
        return None
    return (defended_mean - baseline_mean) / baseline_mean * 100.0
