import math
import pytest
from backend.core import entropy
from backend.core.metrics import confusion, overhead_pct, rate, summarize, wilson_ci


def test_constant_sample_zero_entropy():
    assert entropy.shannon_entropy_bits(b"A" * 100) == 0.0


def test_perfectly_uniform_sample_is_8_bits():
    assert entropy.shannon_entropy_bits(bytes(range(256)) * 4) == pytest.approx(8.0)


def test_two_symbol_sample_is_1_bit():
    assert entropy.shannon_entropy_bits(b"ab" * 50) == pytest.approx(1.0)


def test_empty_and_tiny_samples_rejected():
    with pytest.raises(ValueError):
        entropy.shannon_entropy_bits(b"")
    with pytest.raises(ValueError):
        entropy.assess(b"x")


def test_uniform_vs_repeated_vs_biased_ordering():
    res = {}
    for kind in ("uniform", "biased", "repeated_pattern", "constant"):
        data, _ = entropy.generate_sample(kind, 4096, seed=3)
        res[kind] = entropy.assess(data)["shannon_bits_per_byte"]
    assert res["uniform"] > res["biased"] > res["repeated_pattern"] > res["constant"]
    assert res["uniform"] > 7.9


def test_nonce_reuse_sample_invisible_to_byte_entropy_but_blocks_flagged():
    data, _ = entropy.generate_sample("nonce_reuse", 4096, seed=5)
    a = entropy.assess(data)
    assert a["relative_to_ideal"] > 0.97 and "low_entropy_vs_ideal" not in a["indicators"]
    assert "repeated_blocks" in a["indicators"]


def test_assessment_contains_limitations_and_frequency():
    a = entropy.assess(entropy.generate_sample("uniform", 512, seed=1)[0])
    assert len(a["frequency"]) == 256 and sum(a["frequency"]) == 512
    assert a["limitations"] and 0 <= a["normalized_entropy"] <= 1


def test_seeded_samples_reproducible_unseeded_differ():
    a, _ = entropy.generate_sample("uniform", 64, seed=9)
    b, _ = entropy.generate_sample("uniform", 64, seed=9)
    c, _ = entropy.generate_sample("uniform", 64)
    d, _ = entropy.generate_sample("uniform", 64)
    assert a == b and c != d


def test_wilson_ci_known_value():
    lo, hi = wilson_ci(5, 10)
    assert lo == pytest.approx(0.2366, abs=1e-3) and hi == pytest.approx(0.7634, abs=1e-3)
    assert wilson_ci(0, 0) == (None, None)
    assert 0 <= wilson_ci(0, 20)[0] <= wilson_ci(0, 20)[1] < 0.2


def test_summarize_and_confusion_and_overhead():
    s = summarize([1, 2, 3, 4, 100])
    assert s["mean"] == 22 and s["median"] == 3 and s["n"] == 5
    c = confusion(tp=8, fp=1, tn=9, fn=2)
    assert c["detection_rate"]["rate"] == 0.8 and c["false_positive_rate"]["rate"] == pytest.approx(0.1)
    assert overhead_pct(2.0, 3.0) == pytest.approx(50.0) and overhead_pct(0, 1) is None
    assert rate(1, 4)["rate"] == 0.25
