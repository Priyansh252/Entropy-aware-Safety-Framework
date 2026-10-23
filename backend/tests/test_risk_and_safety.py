import random
import pytest
from backend.core import adaptive_selector as AS, ecdsa_lab as EL, risk_engine as RE, rsa_lab as RL, safety_layer as SL
from backend.storage import db

BASE = {"operation": "ecdsa_sign", "randomness_source": "os_csprng", "generation_policy": "deterministic_rfc6979",
        "security_bits": 128, "required_security_bits": 128, "fallback_available": True,
        "validation": {"required": ["x"], "performed": ["x"], "failed": []}}
HARD = ["nonce_reuse_confirmed", "shared_prime_confirmed", "duplicate_modulus_confirmed"]


def test_default_weights_sum_to_100():
    from backend.config import DEFAULT_RISK_CONFIG as C
    assert sum(C["weights"].values()) == 100


def test_risk_score_bounds_fuzz():
    rng = random.Random(1)
    for _ in range(500):
        ctx = {"operation": "x", "randomness_source": rng.choice(["os_csprng", "unknown", "known_weak", "bogus", "seeded_prng_test"]),
               "generation_policy": rng.choice(["deterministic_rfc6979", "fixed_or_user_supplied", "zzz"]),
               "security_bits": rng.choice([None, 80, 128, 256]), "required_security_bits": rng.choice([None, 112, 128]),
               "entropy_assessment": rng.choice([None, {"relative_to_ideal": rng.uniform(-1, 2), "sample_size": 10}]),
               "nonce_reuse_confirmed": rng.random() < 0.2, "fallback_available": rng.random() < 0.5,
               "validation": {"required": ["a", "b"][:rng.randint(0, 2)], "performed": ["a"][:rng.randint(0, 1)], "failed": []}}
        r = RE.evaluate(ctx, None, rng.randint(0, 3), 3)
        assert 0 <= r["risk_score"] <= 100 and r["risk_category"] in ("Low", "Moderate", "High", "Critical")
        assert r["decision"] in RE.DECISIONS


def test_category_mapping_boundaries():
    cfg = RE.merged_config()
    assert [RE.category_for(s, cfg) for s in (0, 24.9, 25, 49.9, 50, 74.9, 75, 100)] == \
        ["Low", "Low", "Moderate", "Moderate", "High", "High", "Critical", "Critical"]


def test_clean_candidate_accepted():
    r = RE.evaluate(BASE)
    assert r["decision"] == "ACCEPT" and r["risk_category"] == "Low" and not r["hard_fail"]


@pytest.mark.parametrize("flag", HARD)
def test_confirmed_critical_conditions_never_accepted_even_if_score_is_zero(flag):
    cfg = {"weights": {k: 0 for k in RE.merged_config()["weights"]}, "accept_below": 1000}
    for regen in range(0, 5):
        for fb in (True, False):
            r = RE.evaluate({**BASE, flag: True, "fallback_available": fb}, cfg, regen, 3)
            assert r["decision"] != "ACCEPT" and r["risk_category"] == "Critical" and r["risk_score"] >= 90


def test_known_weak_source_and_weaker_than_required_are_never_accepted():
    assert RE.evaluate({**BASE, "randomness_source": "known_weak"})["decision"] != "ACCEPT"
    assert RE.evaluate({**BASE, "security_bits": 112})["decision"] != "ACCEPT"
    assert RE.evaluate({**BASE, "validation": {"required": ["x"], "performed": ["x"], "failed": ["modulus_size"]}})["decision"] != "ACCEPT"


def test_decision_sequence_regenerate_then_fallback_or_reject():
    ctx = {**BASE, "nonce_reuse_confirmed": True}
    assert RE.evaluate(ctx, None, 0, 3)["decision"] == "REGENERATE"
    assert RE.evaluate(ctx, None, 2, 3)["decision"] == "REGENERATE"
    assert RE.evaluate(ctx, None, 3, 3)["decision"] == "SAFE_FALLBACK"
    assert RE.evaluate({**ctx, "fallback_available": False}, None, 3, 3)["decision"] == "REJECT"
    assert RE.evaluate(ctx, None, 0, 0)["decision"] == "SAFE_FALLBACK"       # max_regen = 0 -> no regeneration


def test_soft_only_unsafe_candidate_skips_regeneration():
    ctx = {**BASE, "randomness_source": "seeded_prng_test", "generation_policy": "fixed_or_user_supplied", "entropy_assessment": {"relative_to_ideal": 0.5, "sample_size": 1000}}
    r = RE.evaluate(ctx)
    assert r["risk_score"] >= 50 and r["decision"] == "SAFE_FALLBACK" and not r["hard_fail"]
    assert RE.evaluate({**ctx, "fallback_available": False})["decision"] == "REJECT"


def test_evaluation_errors_fail_safe():
    r = RE.evaluate_safely(BASE, {"weights": {"entropy_quality": "x"}})
    assert r["decision"] == "REJECT" and r["risk_score"] == 100
    r = RE.evaluate_safely(None)
    assert r["decision"] == "REJECT"
    with pytest.raises(ValueError):
        RE.merged_config({"nope": 1})


def test_selector_never_weakens_security_and_respects_capabilities():
    for op in AS.OPERATIONS:
        for bits in (112, 128, 192):
            for perf in AS.PERF:
                for comp in ([], ["fips"], ["legacy_rsa"], ["modern"]):
                    sel = AS.select({"operation": op, "required_security_bits": bits, "performance_priority": perf, "compatibility": comp})["selected"]
                    if sel:
                        assert sel["security_bits"] >= bits and op in sel["operations"]
                        assert all(t in sel["tags"] for t in comp)
    assert AS.select({"operation": "signature"})["selected"]["id"] == "ecdsa_p256_det"
    assert AS.select({"operation": "signature", "compatibility": ["legacy_rsa"]})["selected"]["algorithm"] == "RSA"
    assert AS.select({"operation": "encryption", "required_security_bits": 192})["selected"] is None      # refuses, doesn't weaken
    assert AS.select({"operation": "encryption", "supported_algorithms": ["ECDSA"]})["selected"] is None  # ECDSA cannot encrypt
    assert AS.fallback_for({"operation": "signature", "compatibility": ["legacy_rsa"]}, "RSA") is None
    assert AS.fallback_for({"operation": "signature", "allow_fallback": False}, "RSA") is None
    with pytest.raises(ValueError):
        AS.select({"operation": "teleport"})


# ------------------------------------------------------------------ ECDSA guard
class ScriptedSource:
    declared_source = "unknown"
    injected_repeats = 0

    def __init__(self, nonces):
        self.nonces = list(nonces)

    def next(self):
        return self.nonces.pop(0) if self.nonces else EL.random_nonce()


def test_rejected_nonce_never_reaches_signing(monkeypatch):
    k1, k2 = EL.random_nonce(), EL.random_nonce()
    used = []
    real = EL.guarded_sign_with_nonce
    monkeypatch.setattr(EL, "guarded_sign_with_nonce", lambda key, m, k: (used.append(k), real(key, m, k))[1])
    key = EL.new_test_key()
    guard = SL.ECDSAGuard(key, ScriptedSource([k1, k1, k1, k2]), max_regen=5)
    a, b = guard.sign(b"m1"), guard.sign(b"m2")
    assert used == [k1, k2]                       # the two repeats of k1 were discarded, never signed
    assert a["status"] == b["status"] == "signed" and b["regenerations"] == 2
    assert a["verified"] and b["verified"] and len(set(guard.signed_r)) == 2


def test_stuck_source_falls_back_to_deterministic_and_attack_fails():
    key = EL.new_test_key()
    guard = SL.ECDSAGuard(key, EL.FaultyNonceSource("stuck"), max_regen=2)
    res = [guard.sign(f"msg{i}".encode()) for i in range(6)]
    assert res[0]["status"] == "signed" and all(r["status"] == "fallback_signed" for r in res[1:])
    assert all(r["verified"] for r in res)
    assert len(guard.signed_r) == 1               # only one raw-nonce signature ever produced
    recs = [(f"msg{i}".encode(), r["r"], r["s"]) for i, r in enumerate(res)]
    assert not EL.recover_from_signature_set(key.public_key(), recs)["recovered"]


def test_no_fallback_means_reject_and_no_signature():
    key = EL.new_test_key()
    for req in ({"allow_fallback": False}, {"compatibility": ["randomized_signing_only"]}):
        guard = SL.ECDSAGuard(key, EL.FaultyNonceSource("stuck"), max_regen=1, requirements=req)
        guard.sign(b"a")
        r = guard.sign(b"b")
        assert r["status"] == "rejected" and r["r"] is None and r["decision"] == "REJECT"
        assert len(r["trace"]) == 2                # 1 regeneration then terminal decision: limit enforced


def test_guard_never_yields_reused_r_under_heavy_faults():
    for seed in range(5):
        res = SL.run_ecdsa_session("guard", 40, "intermittent_repeat", 0.6, seed=seed, max_regen=3)
        assert res["vulnerable_signatures"] == 0 and not res["compromised"] and res["verified"] == res["signatures"]
    base = SL.run_ecdsa_session("baseline", 40, "intermittent_repeat", 0.6, seed=1)
    assert base["compromised"] and base["vulnerable_signatures"] > 0


def test_healthy_source_accepts_everything_without_rejections():
    res = SL.run_ecdsa_session("guard", 25, "healthy", 0.0, seed=1)
    assert res["rejected_candidates"] == 0 and res["regenerations"] == 0 and res["signatures"] == 25


def test_guard_fails_safe_on_internal_error(monkeypatch):
    monkeypatch.setattr(EL, "nonce_to_r", lambda k: (_ for _ in ()).throw(RuntimeError("boom")))
    key = EL.new_test_key()
    g = SL.ECDSAGuard(key, EL.FaultyNonceSource("healthy"), max_regen=1, requirements={"allow_fallback": False})
    assert g.sign(b"x")["status"] == "rejected" and g.signed_r == []


# ------------------------------------------------------------------ RSA guard
def _src(mode, reg_keys, bits=1024, seed=3, n=8):
    s = RL.RSACandidateSource(mode, 1.0, bits, random.Random(seed), max_candidates=n)
    s.issued_primes = [x for k in reg_keys for x in (k["p"], k["q"])]
    return s


def test_rsa_shared_prime_candidate_rejected_and_never_registered():
    reg = RL.make_collection(3, 0, 1024, seed=2)
    guard = SL.RSAGuard(_src("stuck", reg), 1024, 2, {"allow_fallback": False}, registry=[k["n"] for k in reg])
    r = guard.generate()
    assert r["status"] == "rejected" and r["_internal"] is None and r["decision"] == "REJECT"
    assert len(guard.registry) == 3 and len(r["trace"]) == 3          # max_regen=2 -> 3 attempts, then stop
    assert all(t["hard_fail"] for t in r["trace"])


def test_rsa_fallback_only_when_compatibility_allows():
    reg = RL.make_collection(3, 0, 1024, seed=2)
    ok = SL.RSAGuard(_src("stuck", reg), 1024, 1, {"allow_fallback": True}, registry=[k["n"] for k in reg]).generate()
    assert ok["status"] == "fallback" and "ecdsa" in ok["fallback_config"]
    legacy = SL.RSAGuard(_src("stuck", reg), 1024, 1, {"compatibility": ["legacy_rsa"]}, registry=[k["n"] for k in reg]).generate()
    assert legacy["status"] == "rejected"


def test_rsa_healthy_candidates_accepted_and_population_clean():
    res = SL.run_rsa_population("defended", 8, "intermittent_repeat", 0.5, seed=4, max_regen=4)
    assert res["vulnerable_final"] == 0 and res["keys_factored_by_batch_gcd"] == 0
    base = SL.run_rsa_population("baseline", 12, "intermittent_repeat", 0.6, seed=4)
    assert base["vulnerable_final"] > 0 and base["keys_factored_by_batch_gcd"] > 0


def test_rsa_malformed_candidate_fails_safe():
    class Bad:
        declared_source = "unknown"
        def next(self):
            return {"p": 4, "q": 4, "n": 16, "e": 65537}
    r = SL.RSAGuard(Bad(), 1024, 1, {"allow_fallback": False}).generate()
    assert r["status"] == "rejected"           # composite / equal primes / wrong size are all rejected


def test_audit_records_contain_no_secrets():
    key = EL.new_test_key()
    buf = db.AuditBuffer()
    SL.ECDSAGuard(key, EL.FaultyNonceSource("stuck"), 1, None, buf).sign(b"a")
    SL.ECDSAGuard(key, EL.FaultyNonceSource("stuck"), 1, None, buf).sign(b"b")
    text = str(buf.records)
    assert f"{EL.private_value(key):x}" not in text and buf.records and "nonce" not in " ".join(buf.records[0].keys())
    assert db.scrub({"d": 1, "nonce": 2, "private_key": 3, "ok": 4, "nested": {"q": 5, "x": 6}}) == {"ok": 4, "nested": {"x": 6}}


def test_rsa_guard_enforces_required_security_level_and_default_matches_key_size():
    src = lambda: RL.RSACandidateSource("healthy", 0.0, 1024, random.Random(1), max_candidates=3)
    ok = SL.RSAGuard(src(), 1024, 1, {"allow_fallback": False}).generate()
    assert ok["status"] == "accepted"                                    # educational 1024-bit meets its own ~80-bit level
    low = SL.RSAGuard(src(), 1024, 1, {"required_security_bits": 112, "allow_fallback": False}).generate()
    assert low["status"] == "rejected" and low["risk"]["hard_fail"]     # a weaker-than-required key is never accepted
