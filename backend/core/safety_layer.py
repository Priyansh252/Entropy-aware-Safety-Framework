"""Generation-time safety layer.

Candidates (ECDSA nonces / RSA key candidates) are produced by an *untrusted* source, validated with
operation-specific checks, scored by the risk engine and only then allowed to reach the protected
operation. A rejected candidate is never passed to signing / key use.

Scope notes (also in docs/):
 * The ECDSA reuse registry only sees signatures produced through this signer instance. A
   multi-signer or restarted deployment needs shared state - or, preferably, deterministic ECDSA.
 * The RSA shared-prime check is only as strong as the set of known moduli it is compared with.
"""
import random
import time
import uuid
from collections import Counter

from cryptography.hazmat.primitives.asymmetric import ec

from backend.core import adaptive_selector, ecdsa_lab as EL, risk_engine, rsa_lab as RL
from backend.storage import db


def _cid():
    return uuid.uuid4().hex[:10]


def fallback_available(req: dict, failed_algorithm: str) -> bool:
    if "randomized_signing_only" in req.get("compatibility", []) and failed_algorithm == "ECDSA":
        return False
    sel_req = {"operation": req.get("operation", "signature"),
               "required_security_bits": req.get("required_security_bits", 128),
               "performance_priority": req.get("performance_priority", "balanced"),
               "compatibility": [t for t in req.get("compatibility", []) if t != "randomized_signing_only"],
               "supported_algorithms": req.get("supported_algorithms")}
    if failed_algorithm == "ECDSA":
        sel_req["supported_algorithms"] = ["ECDSA"]  # same-key deterministic signing
    return adaptive_selector.fallback_for({**sel_req, "allow_fallback": req.get("allow_fallback", True)},
                                          failed_algorithm if failed_algorithm != "ECDSA" else "__none__") is not None


# ====================================================================== ECDSA
class ECDSAGuard:
    """Nonce-candidate guard: reuse registry + risk engine + regenerate / deterministic fallback."""

    def __init__(self, key, source, max_regen=3, requirements=None, audit=None, mode="interactive_demo",
                 risk_cfg=None):
        self.key, self.source, self.max_regen = key, source, max_regen
        self.req = {"operation": "signature", "required_security_bits": 128, "allow_fallback": True,
                    "compatibility": [], **(requirements or {})}
        self.audit, self.mode, self.risk_cfg = audit, mode, risk_cfg
        self.key_id = EL.public_fingerprint(key.public_key())
        self.seen_r = set()
        self.signed_r = []      # r of every raw-nonce signature actually produced (for tests/measurement)
        self.stats = Counter()

    def _ctx(self, reuse):
        fb = fallback_available(self.req, "ECDSA")
        return {"operation": "ecdsa_sign", "algorithm": "ECDSA",
                "configuration": "P-256 / SHA-256 / external nonce source + reuse registry",
                "randomness_source": self.source.declared_source,
                "generation_policy": "external_nonce_source",
                "security_bits": 128, "required_security_bits": self.req["required_security_bits"],
                "validation": {"required": ["nonce_reuse_registry"], "performed": ["nonce_reuse_registry"],
                               "failed": []},
                "nonce_reuse_confirmed": reuse, "fallback_available": fb}

    def _log(self, risk, cand, t0, outcome):
        self.stats["assessments"] += 1
        if self.audit:
            self.audit(db.audit_record_from_risk(
                risk, operation="ecdsa_sign", algorithm="ECDSA", configuration="reuse_guard", candidate_id=cand,
                exec_ms=(time.perf_counter() - t0) * 1000, mode=self.mode, validation_outcome=outcome))

    def sign(self, message: bytes) -> dict:
        t0 = time.perf_counter()
        regen, trace = 0, []
        while True:
            k = self.source.next()
            cid = _cid()
            self.stats["candidates"] += 1
            try:
                r = EL.nonce_to_r(k)
                reuse = r in self.seen_r
                risk = risk_engine.evaluate_safely(self._ctx(reuse), self.risk_cfg, regen, self.max_regen)
            except Exception:  # noqa: BLE001 - fail safe
                risk = risk_engine.evaluate_safely({"nonce_reuse_confirmed": True}, self.risk_cfg, self.max_regen, self.max_regen)
                reuse = True
            dec = risk["decision"]
            trace.append({"attempt": len(trace) + 1, "candidate_id": cid, "decision": dec,
                          "risk_score": risk["risk_score"], "hard_fail": risk["hard_fail"],
                          "reuse_detected": reuse})
            self._log(risk, cid, t0, "failed" if risk["hard_fail"] else "passed")
            if dec == "ACCEPT":
                rr, s = EL.guarded_sign_with_nonce(self.key, message, k)
                self.seen_r.add(rr)
                self.signed_r.append(rr)
                return self._result("signed", message, rr, s, trace, regen, risk, t0)
            if dec == "REGENERATE":
                regen += 1
                self.stats["regenerations"] += 1
                self.stats["rejected_candidates"] += 1
                continue
            self.stats["rejected_candidates"] += 1
            if dec == "SAFE_FALLBACK":
                rr, s = EL.library_sign(self.key, message, deterministic=True)
                self.stats["fallbacks"] += 1
                return self._result("fallback_signed", message, rr, s, trace, regen, risk, t0)
            self.stats["rejected_ops"] += 1
            return self._result("rejected", message, None, None, trace, regen, risk, t0)

    def _result(self, status, message, r, s, trace, regen, risk, t0):
        out = {"status": status, "decision": risk["decision"], "trace": trace, "regenerations": regen,
               "risk": risk, "exec_ms": (time.perf_counter() - t0) * 1000, "r": r, "s": s,
               "verified": None}
        if r is not None:
            out["verified"] = EL.verify(self.key.public_key(), message, r, s)
        return out


# ====================================================================== RSA
def rsa_security_bits(key_bits: int) -> int:
    """Approximate NIST SP 800-57 strength: RSA-1024 ~ 80-bit (educational size), RSA-2048 ~ 112-bit."""
    return 112 if key_bits >= 2048 else 80


class RSAGuard:
    """Per-candidate RSA validation + registry-based shared-prime check + regenerate / fallback."""

    def __init__(self, source, key_bits=1024, max_regen=3, requirements=None, audit=None,
                 mode="interactive_demo", risk_cfg=None, registry=None):
        self.source, self.key_bits, self.max_regen = source, key_bits, max_regen
        self.req = {"operation": "signature", "required_security_bits": rsa_security_bits(key_bits),
                    "allow_fallback": True, "compatibility": [], **(requirements or {})}
        self.audit, self.mode, self.risk_cfg = audit, mode, risk_cfg
        self.registry = list(registry or [])   # public moduli of keys already accepted
        self.stats = Counter()

    def generate(self) -> dict:
        t0 = time.perf_counter()
        regen, trace = 0, []
        while True:
            cand = self.source.next()
            cid = _cid()
            self.stats["candidates"] += 1
            try:
                v = RL.validate_candidate(cand["p"], cand["q"], cand["e"], self.key_bits, self.registry)
                ctx = {"operation": "rsa_keygen", "algorithm": "RSA", "configuration": f"RSA-{self.key_bits} (educational size)",
                       "randomness_source": self.source.declared_source, "generation_policy": "library_keygen",
                       "security_bits": rsa_security_bits(self.key_bits), "required_security_bits": self.req["required_security_bits"],
                       "validation": {"required": v["performed"], "performed": v["performed"], "failed": v["failed"]},
                       "shared_prime_confirmed": v["shared_prime"], "duplicate_modulus_confirmed": v["duplicate_modulus"],
                       "fallback_available": fallback_available(self.req, "RSA")}
                risk = risk_engine.evaluate_safely(ctx, self.risk_cfg, regen, self.max_regen)
            except Exception:  # noqa: BLE001
                v = {"failed": ["validation_error"]}
                risk = risk_engine.evaluate_safely({"nonce_reuse_confirmed": True}, self.risk_cfg, self.max_regen, self.max_regen)
            dec = risk["decision"]
            trace.append({"attempt": len(trace) + 1, "candidate_id": cid, "decision": dec,
                          "risk_score": risk["risk_score"], "hard_fail": risk["hard_fail"], "failed_checks": v["failed"]})
            self.stats["assessments"] += 1
            if self.audit:
                self.audit(db.audit_record_from_risk(
                    risk, operation="rsa_keygen", algorithm="RSA", configuration=f"RSA-{self.key_bits}",
                    candidate_id=cid, exec_ms=(time.perf_counter() - t0) * 1000, mode=self.mode,
                    validation_outcome="failed" if v["failed"] else "passed"))
            if dec == "ACCEPT":
                self.registry.append(cand["n"])
                return self._result("accepted", cand, trace, regen, risk, t0, cid)
            self.stats["rejected_candidates"] += 1
            if dec == "REGENERATE":
                regen += 1
                self.stats["regenerations"] += 1
                continue
            if dec == "SAFE_FALLBACK":
                self.stats["fallbacks"] += 1
                chosen = adaptive_selector.fallback_for(
                    {"operation": self.req.get("operation", "signature"),
                     "required_security_bits": self.req["required_security_bits"],
                     "compatibility": [t for t in self.req["compatibility"] if t != "legacy_rsa"],
                     "allow_fallback": True}, "RSA")
                ec.generate_private_key(ec.SECP256R1())   # key produced by the vetted library + OS CSPRNG
                res = self._result("fallback", None, trace, regen, risk, t0, cid)
                res["fallback_config"] = chosen["id"] if chosen else "ECDSA P-256 (deterministic)"
                return res
            self.stats["rejected_ops"] += 1
            return self._result("rejected", None, trace, regen, risk, t0, cid)

    def _result(self, status, cand, trace, regen, risk, t0, cid):
        return {"status": status, "decision": risk["decision"], "trace": trace, "regenerations": regen,
                "risk": risk, "exec_ms": (time.perf_counter() - t0) * 1000, "candidate_id": cid,
                "modulus_bits": cand["n"].bit_length() if cand else None,
                "_internal": cand}   # contains secret primes: never serialise this key


# ====================================================================== workflow runners
def run_ecdsa_session(arm, n_sigs, fault_mode, p_repeat, seed=None, max_regen=3, requirements=None,
                      audit=None, mode="experiment", risk_cfg=None):
    """arm: baseline | guard | deterministic. Returns measured outcome for one signing session."""
    key = EL.new_test_key()
    pub = key.public_key()
    source = EL.FaultyNonceSource(fault_mode, p_repeat, seed)
    guard = ECDSAGuard(key, source, max_regen, requirements, audit, mode, risk_cfg) if arm == "guard" else None
    records, times = [], []
    verified = rejected = fallbacks = 0
    for i in range(n_sigs):
        msg = f"session-message-{i}".encode()
        t0 = time.perf_counter()
        if arm == "baseline":
            r, s = EL.educational_sign_with_nonce(key, msg, source.next())   # no defence: raw faulty nonce
        elif arm == "deterministic":
            r, s = EL.library_sign(key, msg, deterministic=True)
        else:
            res = guard.sign(msg)
            if res["status"] == "rejected":
                rejected += 1
                times.append((time.perf_counter() - t0) * 1000)
                continue
            fallbacks += res["status"] == "fallback_signed"
            r, s = res["r"], res["s"]
        times.append((time.perf_counter() - t0) * 1000)
        verified += EL.verify(pub, msg, r, s)
        records.append((msg, r, s))
    rc = Counter(r for _, r, _ in records)
    vulnerable_sigs = sum(c - 1 for c in rc.values() if c > 1)    # signatures that re-used an earlier r
    rec = EL.recover_from_signature_set(pub, records)
    compromised = bool(rec["recovered"] and rec["d"] == EL.private_value(key))
    st = guard.stats if guard else Counter()
    return {"arm": arm, "signatures": len(records), "verified": int(verified), "rejected_ops": rejected,
            "fallbacks": int(fallbacks), "candidates": st.get("candidates", len(records)),
            "rejected_candidates": st.get("rejected_candidates", 0), "regenerations": st.get("regenerations", 0),
            "vulnerable_signatures": vulnerable_sigs, "injected_faults": source.injected_repeats,
            "compromised": compromised, "times_ms": times, "_guard": guard}


def run_rsa_population(arm, n_keys, fault_mode, p_reuse, key_bits=1024, seed=None, max_regen=3,
                       requirements=None, audit=None, mode="experiment", risk_cfg=None):
    """arm: baseline | defended. Returns measured outcome for one key population."""
    rng = random.Random(seed)
    budget = n_keys * (max_regen + 1) + 2
    if budget > 200:
        raise ValueError("n_keys * (max_regen + 1) must be <= 198")
    source = RL.RSACandidateSource(fault_mode, p_reuse, key_bits, rng, max_candidates=budget if arm == "defended" else n_keys + 1)
    accepted, times = [], []
    fb = rejected_ops = 0
    guard = RSAGuard(source, key_bits, max_regen, requirements, audit, mode, risk_cfg) if arm == "defended" else None
    for _ in range(n_keys):
        t0 = time.perf_counter()
        if arm == "baseline":
            accepted.append(source.next())
        else:
            res = guard.generate()
            if res["status"] == "accepted":
                accepted.append(res["_internal"])
            elif res["status"] == "fallback":
                fb += 1
            else:
                rejected_ops += 1
        times.append((time.perf_counter() - t0) * 1000)
    prime_count = Counter()
    for c in accepted:
        prime_count[c["p"]] += 1
        prime_count[c["q"]] += 1
    vulnerable_final = sum(1 for c in accepted if prime_count[c["p"]] > 1 or prime_count[c["q"]] > 1)
    findings = RL.analyze_moduli([c["n"] for c in accepted]) if len(accepted) >= 2 else []
    factored = sum(1 for f, c in zip(findings, accepted)
                   if f["factor"] and c["n"] % f["factor"] == 0 and f["factor"] in (c["p"], c["q"]))
    st = guard.stats if guard else Counter()
    return {"arm": arm, "operations": n_keys, "accepted_rsa_keys": len(accepted), "fallbacks": fb,
            "rejected_ops": rejected_ops, "candidates": st.get("candidates", len(accepted)),
            "rejected_candidates": st.get("rejected_candidates", 0), "regenerations": st.get("regenerations", 0),
            "injected_faults": source.injected, "vulnerable_final": vulnerable_final,
            "keys_factored_by_batch_gcd": factored, "times_ms": times}
