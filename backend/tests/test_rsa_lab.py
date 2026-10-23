import math
import random
import pytest
from backend.core import rsa_lab as R


def test_batch_gcd_small_known_values():
    assert R.batch_gcd([3 * 5, 5 * 7, 11 * 13]) == [5, 5, 1]
    assert R.batch_gcd([77]) == [1]
    assert R.batch_gcd([15, 21, 35]) == [15, 21, 35]       # each shares both primes with others (gcd == n)


def test_batch_gcd_matches_pairwise_on_random_inputs():
    rng = random.Random(4)
    primes = [p for p in range(1000, 1400) if R.is_probable_prime(p)]
    for size in (2, 3, 5, 8, 13):
        ns = [rng.choice(primes) * rng.choice(primes) for _ in range(size)]
        ns = [n for n in ns if n]
        got = R.batch_gcd(ns)
        for i, n in enumerate(ns):
            ref = 1
            for j, m in enumerate(ns):
                if i != j:
                    ref = math.lcm(ref, math.gcd(n, m))
            assert (got[i] > 1) == (ref > 1)


def test_miller_rabin():
    assert R.is_probable_prime(2**61 - 1) and not R.is_probable_prime(561) and not R.is_probable_prime(1)
    assert not R.is_probable_prime((2**61 - 1) * 3)


def test_shared_prime_collection_detected_and_recovered():
    col = R.make_collection(10, 2, 1024, seed=1)
    ns = [k["n"] for k in col]
    res = R.analyze_moduli(ns)
    assert [r["status"] != "ok" for r in res] == [k["vulnerable"] for k in col]
    assert sum(k["vulnerable"] for k in col) == 4
    for k, f in zip(col, res):
        if k["vulnerable"]:
            assert f["factor"] in (k["p"], k["q"])
            v = R.verify_recovered_factor(k["n"], k["e"], f["factor"])
            assert v["verified"]


def test_normal_collection_has_no_findings():
    col = R.make_collection(8, 0, 1024, seed=2)
    assert all(r["status"] == "ok" for r in R.analyze_moduli([k["n"] for k in col]))


def test_both_primes_shared_is_still_resolved():
    col = R.make_collection(6, 0, 1024, seed=3)
    a, b, c = col[0], col[1], col[2]
    n_target = a["p"] * b["q"]       # shares p with a, q with b
    res = R.analyze_moduli([n_target, a["n"], b["n"]])
    assert res[0]["status"] == "shared_prime" and res[0]["factor"] in (a["p"], b["q"])


def test_duplicate_modulus_flagged():
    col = R.make_collection(4, 0, 1024, seed=6)
    ns = [col[0]["n"], col[0]["n"], col[1]["n"]]
    assert R.analyze_moduli(ns)[0]["status"] == "duplicate_modulus"


def test_verify_recovered_factor_rejects_bad_factors():
    k = R.make_collection(3, 0, 1024, seed=7)[0]
    assert not R.verify_recovered_factor(k["n"], k["e"], 7)["verified"]
    assert not R.verify_recovered_factor(k["n"], k["e"], k["n"])["verified"]
    assert R.verify_recovered_factor(k["n"], k["e"], k["q"])["verified"]


def test_validate_candidate_catches_issues():
    allk = R.make_collection(6, 0, 1024, seed=8)      # one collection => all primes distinct
    col, fresh = allk[:4], allk[5]
    reg = [k["n"] for k in col]
    ok = R.validate_candidate(fresh["p"], fresh["q"], 65537, 1024, reg)
    assert not ok["failed"]
    shared = R.validate_candidate(col[0]["p"], fresh["q"], 65537, 1024, reg)
    assert shared["shared_prime"] and "no_shared_prime_with_registry" in shared["failed"]
    dup = R.validate_candidate(col[0]["p"], col[0]["q"], 65537, 1024, reg)
    assert dup["duplicate_modulus"]
    same = R.validate_candidate(fresh["p"], fresh["p"], 65537, 1024, reg)
    assert "primes_distinct" in same["failed"]
    bad_e = R.validate_candidate(fresh["p"], fresh["q"], 4, 1024, reg)
    assert "exponent_valid" in bad_e["failed"]


def test_collection_rejects_impossible_parameters():
    with pytest.raises(ValueError):
        R.make_collection(4, 3, 1024)
