"""Reproducible experiment runner.

Protocol (fixed): every group takes (trials, seed, parameters) and returns raw rows + a summary.
Seeds make *synthetic* parts (fault injection decisions, synthetic samples, prime-pool sampling)
repeatable; cryptographic keys and secure nonces always come from the OS CSPRNG, so absolute
timings and some counts vary run to run. Fault models are SIMULATED and labelled as such.
"""
import csv
import json
import platform
import random
import statistics
import threading
import time
import uuid

import cryptography

from backend import config
from backend.core import adaptive_selector, ecdsa_lab as EL, entropy, risk_engine, rsa_lab as RL
from backend.core import safety_layer as SL
from backend.core.metrics import confusion, overhead_pct, rate, summarize
from backend.storage import db

GROUPS = {
    "entropy_samples": {"label": "Uniform vs biased vs repeated byte samples", "cap": 200, "kind": "measured (synthetic samples)"},
    "ecdsa_attack": {"label": "ECDSA: normal vs reused nonces (attack, detection)", "cap": 500, "kind": "measured"},
    "ecdsa_defense": {"label": "ECDSA: baseline vs defended signing under nonce faults", "cap": 200, "kind": "measured on a simulated fault model"},
    "rsa_batch_gcd": {"label": "RSA: normal vs shared-prime collections, batch-GCD accuracy", "cap": 100, "kind": "measured"},
    "rsa_defense": {"label": "RSA: baseline vs defended key generation under prime-reuse faults", "cap": 30, "kind": "measured on a simulated fault model"},
    "threshold_sensitivity": {"label": "Risk-score threshold & weight sensitivity / false rejection", "cap": 500, "kind": "simulated contexts (synthetic)"},
    "overhead": {"label": "Key-generation, validation and signing overhead", "cap": 300, "kind": "measured (this machine)"},
    "adaptive_policy": {"label": "Adaptive selection under security/performance/compatibility requirements", "cap": 1, "kind": "measured (policy enumeration)"},
}
DEFAULTS = {"trials": 30, "seed": 42, "fault_probability": 0.15, "fault_mode": "intermittent_repeat",
            "signatures_per_session": 20, "rsa_keys_per_population": 12, "collection_size": 12,
            "key_bits": 1024, "max_regen": 3, "sample_size": 4096}


def validate_params(p: dict) -> dict:
    out = dict(DEFAULTS)
    out.update({k: v for k, v in (p or {}).items() if k in DEFAULTS or k == "groups"})
    groups = out["groups"] if "groups" in (p or {}) else list(GROUPS)
    if not isinstance(groups, list) or not groups or any(g not in GROUPS for g in groups):
        raise ValueError(f"groups must be a non-empty subset of {list(GROUPS)}")

    def ival(name, lo, hi):
        try:
            v = int(out[name])
        except (TypeError, ValueError):
            raise ValueError(f"{name} must be an integer")
        if not lo <= v <= hi:
            raise ValueError(f"{name} must be between {lo} and {hi}")
        out[name] = v

    lo, hi = config.LIMITS["experiment_trials"]
    ival("trials", lo, hi)
    ival("seed", 0, 2**31 - 1)
    ival("signatures_per_session", *config.LIMITS["defense_signatures"])
    ival("rsa_keys_per_population", 3, 25)
    ival("collection_size", *config.LIMITS["rsa_collection_keys"])
    ival("max_regen", *config.LIMITS["max_regeneration"])
    ival("sample_size", *config.LIMITS["entropy_sample_size"])
    if out["sample_size"] > 65536:
        raise ValueError("sample_size for experiments must be <= 65536")
    if int(out["key_bits"]) not in (1024, 2048):
        raise ValueError("key_bits must be 1024 or 2048 (educational sizes)")
    out["key_bits"] = int(out["key_bits"])
    try:
        out["fault_probability"] = float(out["fault_probability"])
    except (TypeError, ValueError):
        raise ValueError("fault_probability must be a number")
    if not 0.0 <= out["fault_probability"] <= 0.9:
        raise ValueError("fault_probability must be between 0 and 0.9")
    if out["fault_mode"] not in ("intermittent_repeat", "stuck"):
        raise ValueError("fault_mode must be 'intermittent_repeat' or 'stuck'")
    if out["rsa_keys_per_population"] * (out["max_regen"] + 1) > 198:
        raise ValueError("rsa_keys_per_population * (max_regen + 1) must be <= 198")
    out["groups"] = groups
    return out


def effective_trials(group, p):
    return 1 if group == "adaptive_policy" else min(p["trials"], GROUPS[group]["cap"])


# ------------------------------------------------------------------ groups
def g_entropy(p, n, tick):
    rows, per = [], {k: [] for k in entropy.SAMPLE_KINDS}
    for t in range(n):
        for i, kind in enumerate(entropy.SAMPLE_KINDS):
            data, _ = entropy.generate_sample(kind, p["sample_size"], seed=p["seed"] + t * 100 + i)
            a = entropy.assess(data)
            low = bool({"low_entropy_vs_ideal", "very_small_alphabet"} & set(a["indicators"]))
            rep = "repeated_blocks" in a["indicators"]
            r = {"group": "entropy_samples", "trial": t, "kind": kind, "sample_size": a["sample_size"],
                 "shannon_bits": round(a["shannon_bits_per_byte"], 5), "relative_to_ideal": round(a["relative_to_ideal"], 5),
                 "unique_bytes": a["unique_byte_values"], "duplicate_blocks": a["duplicate_blocks"]["duplicate_blocks"],
                 "flag_low_entropy": int(low), "flag_repeated_blocks": int(rep)}
            rows.append(r)
            per[kind].append(r)
        tick()
    metrics = {k: {"shannon_bits": summarize(r["shannon_bits"] for r in v),
                   "low_entropy_flag_rate": rate(sum(r["flag_low_entropy"] for r in v), len(v)),
                   "repeated_block_flag_rate": rate(sum(r["flag_repeated_blocks"] for r in v), len(v))}
               for k, v in per.items()}
    return rows, {"metrics": metrics, "headline": {
        "uniform_mean_bits": metrics["uniform"]["shannon_bits"]["mean"],
        "nonce_reuse_mean_bits": metrics["nonce_reuse"]["shannon_bits"]["mean"],
        "nonce_reuse_low_entropy_flag_rate": metrics["nonce_reuse"]["low_entropy_flag_rate"]["rate"],
        "nonce_reuse_repeated_block_flag_rate": metrics["nonce_reuse"]["repeated_block_flag_rate"]["rate"]},
        "notes": ["Byte-level entropy does not detect repeated nonces (their bytes look uniform); a block-repeat/signature check does.",
                  "Samples are synthetic; 'uniform' here is seeded for repeatability and is not a security-grade source."]}


def g_ecdsa_attack(p, n, tick):
    rows = []
    for t in range(n):
        key = EL.new_test_key()
        pub = key.public_key()
        m1, m2 = f"msg-A-{t}".encode(), f"msg-B-{t}".encode()
        k = EL.random_nonce()
        scen = {
            "normal_random_nonces": (EL.library_sign(key, m1), EL.library_sign(key, m2)),
            "reused_nonce": (EL.educational_sign_with_nonce(key, m1, k), EL.educational_sign_with_nonce(key, m2, k)),
        }
        for name, (s1, s2) in scen.items():
            sigs = [{"id": "a", "key_id": "k", "r": s1[0], "s": s1[1]}, {"id": "b", "key_id": "k", "r": s2[0], "s": s2[1]}]
            detected = bool(EL.detect_nonce_reuse(sigs))
            res = EL.recover_private_key(pub, m1, s1, m2, s2)
            ok = bool(res["recovered"] and res["d"] == EL.private_value(key))
            rows.append({"group": "ecdsa_attack", "trial": t, "scenario": name, "reuse_truth": int(name == "reused_nonce"),
                         "signatures_verify": int(EL.verify(pub, m1, *s1) and EL.verify(pub, m2, *s2)),
                         "reuse_detected": int(detected), "key_recovered": int(ok)})
        tick()
    nr = [r for r in rows if r["scenario"] == "normal_random_nonces"]
    ru = [r for r in rows if r["scenario"] == "reused_nonce"]
    tp, fn = sum(r["reuse_detected"] for r in ru), sum(1 - r["reuse_detected"] for r in ru)
    fp, tn = sum(r["reuse_detected"] for r in nr), sum(1 - r["reuse_detected"] for r in nr)
    m = {"attack_success_normal": rate(sum(r["key_recovered"] for r in nr), len(nr)),
         "attack_success_reused": rate(sum(r["key_recovered"] for r in ru), len(ru)),
         "detection": confusion(tp, fp, tn, fn),
         "signature_verification_rate": rate(sum(r["signatures_verify"] for r in rows), len(rows))}
    return rows, {"metrics": m, "headline": {"attack_success_normal": m["attack_success_normal"]["rate"],
                                             "attack_success_reused": m["attack_success_reused"]["rate"]},
                  "notes": ["Detection here is signature-based (equal r), not entropy-based."]}


def _arm_summary(sessions):
    sigs = sum(s["signatures"] for s in sessions)
    times = [t for s in sessions for t in s["times_ms"]]
    cand = sum(s["candidates"] for s in sessions)
    rej = sum(s["rejected_candidates"] for s in sessions)
    inj = sum(s["injected_faults"] for s in sessions)
    return {"sessions": len(sessions), "signatures": sigs,
            "sessions_compromised": rate(sum(s["compromised"] for s in sessions), len(sessions)),
            "vulnerable_signatures_accepted": sum(s["vulnerable_signatures"] for s in sessions),
            "vulnerable_signature_rate": rate(sum(s["vulnerable_signatures"] for s in sessions), sigs),
            "signatures_verified": rate(sum(s["verified"] for s in sessions), sigs),
            "candidates_generated": cand, "candidates_rejected": rej, "regenerations": sum(s["regenerations"] for s in sessions),
            "fallbacks": sum(s["fallbacks"] for s in sessions), "rejected_operations": sum(s["rejected_ops"] for s in sessions),
            "injected_faults": inj,
            "false_rejection_rate": rate(max(0, rej - inj), max(0, cand - inj)),
            "time_ms_per_signature": summarize(times)}


def g_ecdsa_defense(p, n, tick):
    rows, by = [], {"baseline": [], "guard": [], "deterministic": []}
    for t in range(n):
        for arm in by:
            r = SL.run_ecdsa_session(arm, p["signatures_per_session"], p["fault_mode"], p["fault_probability"],
                                     seed=p["seed"] + t, max_regen=p["max_regen"],
                                     requirements={"allow_fallback": True}, audit=None)
            r.pop("_guard", None)
            by[arm].append(r)
            rows.append({"group": "ecdsa_defense", "trial": t, "arm": arm, **{k: v for k, v in r.items()
                         if k not in ("times_ms", "arm")}, "mean_ms_per_sig": round(statistics.fmean(r["times_ms"]), 4)})
        tick()
    m = {arm: _arm_summary(v) for arm, v in by.items()}
    b = m["baseline"]["time_ms_per_signature"]["mean"]
    for arm in ("guard", "deterministic"):
        m[arm]["overhead_vs_baseline_pct"] = overhead_pct(b, m[arm]["time_ms_per_signature"]["mean"])
    return rows, {"metrics": m, "headline": {
        "baseline_attack_success_rate": m["baseline"]["sessions_compromised"]["rate"],
        "defended_attack_success_rate": m["guard"]["sessions_compromised"]["rate"],
        "deterministic_attack_success_rate": m["deterministic"]["sessions_compromised"]["rate"]},
        "parameters": {"fault_mode": p["fault_mode"], "fault_probability": p["fault_probability"],
                       "signatures_per_session": p["signatures_per_session"]},
        "notes": ["Fault model is simulated: the source re-emits its previous nonce with the stated probability.",
                  "'Attack success' = an attacker holding all session signatures and the public key recovers the private key.",
                  "False rejection = rejected candidates that were not injected repeats / non-faulty candidates."]}


def g_rsa_batch(p, n, tick):
    rows, tp = [], dict(tp=0, fp=0, tn=0, fn=0)
    normal_flagged = vuln_flagged = rec_ok = rec_tot = consistent = 0
    t_batch, t_pair = [], []
    K = p["collection_size"]
    for t in range(n):
        for kind in ("normal", "vulnerable"):
            pairs = 0 if kind == "normal" else max(1, K // 4)
            col = RL.make_collection(K, pairs, p["key_bits"], seed=p["seed"] + t * 2 + (kind == "vulnerable"))
            ns = [k["n"] for k in col]
            t0 = time.perf_counter()
            fnd = RL.analyze_moduli(ns)
            t_batch.append((time.perf_counter() - t0) * 1000)
            t0 = time.perf_counter()
            ref = RL.pairwise_gcd_reference(ns)
            t_pair.append((time.perf_counter() - t0) * 1000)
            consistent += int(all((g > 1) == (r > 1) for g, r in zip(RL.batch_gcd(ns), ref)))
            flagged = 0
            for k, f in zip(col, fnd):
                is_flag = f["status"] != "ok"
                truth = k["vulnerable"]
                tp["tp"] += is_flag and truth
                tp["fp"] += is_flag and not truth
                tp["tn"] += (not is_flag) and not truth
                tp["fn"] += (not is_flag) and truth
                flagged += is_flag
                if f["factor"] and truth:
                    rec_tot += 1
                    v = RL.verify_recovered_factor(k["n"], k["e"], f["factor"])
                    rec_ok += int(v["verified"] and f["factor"] in (k["p"], k["q"]))
            if kind == "normal":
                normal_flagged += flagged > 0
            else:
                vuln_flagged += flagged > 0
            rows.append({"group": "rsa_batch_gcd", "trial": t, "collection": kind, "keys": K, "truly_vulnerable": sum(k["vulnerable"] for k in col),
                         "flagged": flagged, "batch_gcd_ms": round(t_batch[-1], 3), "pairwise_ms": round(t_pair[-1], 3)})
        tick()
    m = {"modulus_level": confusion(**tp), "collection_flagged_normal": rate(normal_flagged, n),
         "collection_flagged_vulnerable": rate(vuln_flagged, n), "factor_recovery_verified": rate(rec_ok, rec_tot),
         "batch_vs_pairwise_agreement": rate(consistent, 2 * n), "batch_gcd_ms": summarize(t_batch),
         "pairwise_ms": summarize(t_pair)}
    return rows, {"metrics": m, "headline": {"detection_rate": m["modulus_level"]["detection_rate"]["rate"],
                                             "false_positive_rate": m["modulus_level"]["false_positive_rate"]["rate"]},
                  "notes": ["Batch GCD is a population-level audit: it detects sharing only among the moduli supplied.",
                            f"Collections of {K} keys at {p['key_bits']} bits (educational size)."]}


def g_rsa_defense(p, n, tick):
    rows, by = [], {"baseline": [], "defended": []}
    n_keys = p["rsa_keys_per_population"]
    for t in range(n):
        for arm in by:
            r = SL.run_rsa_population(arm, n_keys, p["fault_mode"], p["fault_probability"], p["key_bits"],
                                      seed=p["seed"] + t, max_regen=p["max_regen"],
                                      requirements={"allow_fallback": True}, audit=None)
            by[arm].append(r)
            rows.append({"group": "rsa_defense", "trial": t, **{k: v for k, v in r.items() if k != "times_ms"},
                         "mean_ms_per_key": round(statistics.fmean(r["times_ms"]), 4)})
        tick()

    def summ(rs):
        keys = sum(r["accepted_rsa_keys"] for r in rs)
        cand, rej, inj = (sum(r[k] for r in rs) for k in ("candidates", "rejected_candidates", "injected_faults"))
        return {"populations": len(rs), "accepted_rsa_keys": keys,
                "vulnerable_final_keys": sum(r["vulnerable_final"] for r in rs),
                "vulnerable_final_rate": rate(sum(r["vulnerable_final"] for r in rs), keys),
                "keys_factored_by_batch_gcd": rate(sum(r["keys_factored_by_batch_gcd"] for r in rs), keys),
                "populations_with_any_vulnerable": rate(sum(r["vulnerable_final"] > 0 for r in rs), len(rs)),
                "candidates_generated": cand, "candidates_rejected": rej, "regenerations": sum(r["regenerations"] for r in rs),
                "fallbacks": sum(r["fallbacks"] for r in rs), "rejected_operations": sum(r["rejected_ops"] for r in rs),
                "injected_faults": inj, "time_ms_per_key": summarize(t for r in rs for t in r["times_ms"])}
    m = {a: summ(v) for a, v in by.items()}
    m["defended"]["overhead_vs_baseline_pct"] = overhead_pct(m["baseline"]["time_ms_per_key"]["mean"], m["defended"]["time_ms_per_key"]["mean"])
    return rows, {"metrics": m, "headline": {
        "baseline_attack_success_rate": m["baseline"]["keys_factored_by_batch_gcd"]["rate"],
        "defended_attack_success_rate": m["defended"]["keys_factored_by_batch_gcd"]["rate"],
        "baseline_vulnerable_final_rate": m["baseline"]["vulnerable_final_rate"]["rate"],
        "defended_vulnerable_final_rate": m["defended"]["vulnerable_final_rate"]["rate"]},
        "parameters": {"fault_mode": p["fault_mode"], "fault_probability": p["fault_probability"], "keys_per_population": n_keys},
        "notes": ["Primes come from a pool of library-generated primes; the faulty source re-uses earlier-issued primes (simulated).",
                  "Generation-time validation compares each candidate to the moduli already accepted; it is not a proof of safety against keys it has never seen.",
                  "A faulty candidate re-using a prime of an earlier *rejected* candidate shares nothing with any accepted key and may legitimately be accepted.",
                  "TIMING CAVEAT: primes are pre-generated, so the baseline time excludes key generation and the percentage overhead here is NOT meaningful. Use the 'overhead' group (validation vs real key generation)."]}


PROFILES = {
    "default": None,
    "entropy_heavy": {"entropy_quality": 50, "randomness_source": 15, "generation_policy": 15, "validation_coverage": 10, "security_margin": 10},
    "source_heavy": {"entropy_quality": 10, "randomness_source": 50, "generation_policy": 20, "validation_coverage": 10, "security_margin": 10},
    "flat": {"entropy_quality": 20, "randomness_source": 20, "generation_policy": 20, "validation_coverage": 20, "security_margin": 20},
}
THRESHOLDS = [25, 35, 50, 65, 80]


def g_threshold(p, n, tick):
    rng = random.Random(p["seed"])
    rows, ctxs = [], []
    n_ctx = n * 10
    for i in range(n_ctx):
        vulnerable = rng.random() < 0.4
        if vulnerable:
            kind = rng.choice(["biased", "repeated_values", "repeated_pattern"])
            data, _ = entropy.generate_sample(kind, 1024, seed=rng.randrange(2**31), bias=rng.uniform(0.1, 0.6))
            declared = "unknown" if rng.random() < 0.5 else "seeded_prng_test"
        else:
            kind = "uniform"
            data, _ = entropy.generate_sample("uniform", 1024, seed=rng.randrange(2**31))
            declared = "unknown" if rng.random() < 0.5 else "os_csprng"
        a = entropy.assess(data)
        ctx = {"operation": "ecdsa_sign", "randomness_source": declared, "generation_policy": "external_nonce_source",
               "entropy_assessment": {"relative_to_ideal": a["relative_to_ideal"], "sample_size": a["sample_size"]},
               "security_bits": 128, "required_security_bits": 128, "fallback_available": False,
               "validation": {"required": ["nonce_reuse_registry"], "performed": ["nonce_reuse_registry"], "failed": []}}
        ctxs.append((vulnerable, ctx))
        rows.append({"group": "threshold_sensitivity", "trial": i, "truth_vulnerable": int(vulnerable), "sample_kind": kind,
                     "declared_source": declared, "relative_to_ideal": round(a["relative_to_ideal"], 4)})
        if i % 10 == 9:
            tick()
    grid = []
    for pname, w in PROFILES.items():
        for thr in THRESHOLDS:
            c = dict(tp=0, fp=0, tn=0, fn=0)
            t0 = time.perf_counter()
            for vul, ctx in ctxs:
                r = risk_engine.evaluate(ctx, {"weights": w, "accept_below": thr} if w else {"accept_below": thr})
                flagged = r["decision"] != "ACCEPT"
                c["tp"] += flagged and vul
                c["fp"] += flagged and not vul
                c["tn"] += (not flagged) and not vul
                c["fn"] += (not flagged) and vul
            ms = (time.perf_counter() - t0) * 1000 / max(1, len(ctxs))
            cf = confusion(**c)
            grid.append({"profile": pname, "threshold": thr, "detection_rate": cf["detection_rate"]["rate"],
                         "false_rejection_rate": cf["false_positive_rate"]["rate"], "precision": cf["precision"],
                         "tp": c["tp"], "fp": c["fp"], "tn": c["tn"], "fn": c["fn"], "eval_ms_per_context": round(ms, 4)})
    return rows, {"metrics": {"grid": grid, "contexts": len(ctxs), "vulnerable_contexts": sum(v for v, _ in ctxs)},
                  "headline": {"default_threshold_50": next(g for g in grid if g["profile"] == "default" and g["threshold"] == 50)},
                  "notes": ["SIMULATED contexts constructed by this experiment; not field data.",
                            "Only soft factors are in play here (no confirmed hard-fail evidence): this measures how well the *score alone* separates weak from healthy sources.",
                            "Confirmed nonce reuse / shared primes are caught by hard-fail rules independent of any threshold."]}


def _time_ms(fn, reps=1):
    t0 = time.perf_counter()
    for _ in range(reps):
        fn()
    return (time.perf_counter() - t0) * 1000 / reps


def g_overhead(p, n, tick):
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    rows = []
    key = EL.new_test_key()
    msg = b"benchmark message"
    reg = [RL.make_collection(3, 0, p["key_bits"], seed=1)[i]["n"] for i in range(3)]
    sign_t = {"ecdsa_library_random": [], "ecdsa_library_deterministic": [], "ecdsa_raw_nonce_baseline": [], "ecdsa_guarded_signing": []}
    rsa_keygen, rsa_valid = [], []
    guard = SL.ECDSAGuard(key, EL.FaultyNonceSource("healthy"), 3, {"allow_fallback": True}, None, "experiment")
    for t in range(n):
        reps = 10
        a = _time_ms(lambda: EL.library_sign(key, msg), reps)
        b = _time_ms(lambda: EL.library_sign(key, msg, True), reps)
        c = _time_ms(lambda: EL.educational_sign_with_nonce(key, msg, EL.random_nonce()), reps)
        d = _time_ms(lambda: guard.sign(msg), reps)
        for k, v in zip(sign_t, (a, b, c, d)):
            sign_t[k].append(v)
        row = {"group": "overhead", "trial": t, **{k: round(v, 4) for k, v in zip(sign_t, (a, b, c, d))}}
        if t < min(n, 60):
            t0 = time.perf_counter()
            nums = _rsa.generate_private_key(65537, p["key_bits"]).private_numbers()
            kg = (time.perf_counter() - t0) * 1000
            t0 = time.perf_counter()
            v = RL.validate_candidate(nums.p, nums.q, 65537, p["key_bits"], reg)
            risk_engine.evaluate({"operation": "rsa_keygen", "randomness_source": "unknown", "generation_policy": "library_keygen",
                                  "security_bits": 112, "required_security_bits": 112, "fallback_available": True,
                                  "validation": {"required": v["performed"], "performed": v["performed"], "failed": v["failed"]}})
            va = (time.perf_counter() - t0) * 1000
            rsa_keygen.append(kg)
            rsa_valid.append(va)
            row.update({"rsa_keygen_ms": round(kg, 3), "rsa_validation_ms": round(va, 3)})
        rows.append(row)
        tick()
    base = summarize(sign_t["ecdsa_raw_nonce_baseline"])["mean"]
    m = {"signing_ms": {k: summarize(v) for k, v in sign_t.items()},
         "signing_overhead_vs_raw_pct": {k: overhead_pct(base, statistics.fmean(v)) for k, v in sign_t.items()},
         "rsa_keygen_ms": summarize(rsa_keygen), "rsa_validation_ms": summarize(rsa_valid),
         "rsa_validation_overhead_pct": overhead_pct(statistics.fmean(rsa_keygen), statistics.fmean(rsa_keygen) + statistics.fmean(rsa_valid)) if rsa_keygen else None,
         "throughput_signs_per_s": {k: (1000.0 / statistics.fmean(v)) if statistics.fmean(v) else None for k, v in sign_t.items()}}
    return rows, {"metrics": m, "headline": {"guarded_vs_raw_pct": m["signing_overhead_vs_raw_pct"]["ecdsa_guarded_signing"],
                                              "rsa_validation_overhead_pct": m["rsa_validation_overhead_pct"]},
                  "notes": ["Wall-clock timings on this machine; they include Python overhead and vary by hardware/load.",
                            "RSA key generation is timed for min(trials, 60) keys because it is the slowest step.",
                            "'raw nonce baseline' uses the educational chosen-nonce signer, which does its own modular arithmetic around OpenSSL."]}


def g_adaptive(p, n, tick):
    rows, chosen_counts, none_count, lowered = [], {}, 0, 0
    sup = [None, ["RSA"], ["ECDSA", "RSA"]]
    compats = [[], ["fips"], ["legacy_rsa"], ["fips", "widely_supported"], ["modern"]]
    for op in adaptive_selector.OPERATIONS:
        for bits in (112, 128, 192):
            for perf in adaptive_selector.PERF:
                for comp in compats:
                    for s in sup:
                        res = adaptive_selector.select({"operation": op, "required_security_bits": bits, "performance_priority": perf,
                                                        "compatibility": comp, "supported_algorithms": s})
                        sel = res["selected"]
                        if sel is None:
                            none_count += 1
                        else:
                            chosen_counts[sel["id"]] = chosen_counts.get(sel["id"], 0) + 1
                            lowered += sel["security_bits"] < bits
                        rows.append({"group": "adaptive_policy", "operation": op, "required_bits": bits, "performance": perf,
                                     "compatibility": "+".join(comp) or "-", "supported": "+".join(s) if s else "any",
                                     "selected": sel["id"] if sel else "NONE", "selected_bits": sel["security_bits"] if sel else ""})
    tick()
    total = len(rows)
    return rows, {"metrics": {"scenarios": total, "selected_counts": chosen_counts, "no_eligible_configuration": none_count,
                              "selections_below_required_security": lowered},
                  "headline": {"scenarios": total, "selections_below_required_security": lowered, "no_eligible": none_count},
                  "notes": ["Invariant checked over every scenario: the selected configuration never has less security than required.",
                            "'NONE' means no vetted configuration satisfies all constraints; the selector refuses instead of weakening them."]}


RUNNERS = {"entropy_samples": g_entropy, "ecdsa_attack": g_ecdsa_attack, "ecdsa_defense": g_ecdsa_defense,
           "rsa_batch_gcd": g_rsa_batch, "rsa_defense": g_rsa_defense, "threshold_sensitivity": g_threshold,
           "overhead": g_overhead, "adaptive_policy": g_adaptive}


# ------------------------------------------------------------------ orchestration
JOBS = {}
_jobs_lock = threading.Lock()


def _write_outputs(exp_id, rows, summary):
    d = config.export_dir() / exp_id
    d.mkdir(parents=True, exist_ok=True)
    fields = ["group", "trial"]
    for r in rows:
        for k in r:
            if k not in fields:
                fields.append(k)
    with open(d / "raw_results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    with open(d / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    return str(d / "raw_results.csv"), str(d / "summary.json")


def execute(exp_id, params, job=None):
    t_start = time.perf_counter()
    all_rows, groups_out = [], {}
    done = [0]
    total = sum(effective_trials(g, params) for g in params["groups"])

    def tick():
        done[0] += 1
        if job is not None:
            job["progress"] = min(1.0, done[0] / max(1, total))

    for g in params["groups"]:
        if job is not None:
            job["stage"] = GROUPS[g]["label"]
        n = effective_trials(g, params)
        t0 = time.perf_counter()
        rows, summ = RUNNERS[g](params, n, tick)
        summ.update({"label": GROUPS[g]["label"], "evidence_type": GROUPS[g]["kind"], "effective_trials": n,
                     "duration_s": round(time.perf_counter() - t0, 3), "raw_rows": len(rows)})
        groups_out[g] = summ
        all_rows.extend(rows)
    summary = {"experiment_id": exp_id, "params": params, "groups": groups_out,
               "environment": {"python": platform.python_version(), "cryptography": cryptography.__version__,
                               "platform": platform.platform()},
               "protocol": ("Fixed protocol: per group, N independent trials; seeds control synthetic choices only; "
                            "CIs are 95% Wilson (proportions) or normal-approximation (means). Educational key sizes; "
                            "results are measurements of this implementation on simulated fault models, "
                            "not evidence of production security.")}
    csv_path, json_path = _write_outputs(exp_id, all_rows, summary)
    return summary, csv_path, json_path, time.perf_counter() - t_start


def run_experiment_sync(params):
    p = validate_params(params)
    exp_id = "exp-" + uuid.uuid4().hex[:8]
    db.insert_experiment(exp_id, p["groups"], p)
    try:
        summary, csv_path, json_path, dur = execute(exp_id, p)
        db.update_experiment(exp_id, status="completed", summary=summary, csv_path=csv_path, json_path=json_path, duration_s=dur)
    except Exception as exc:  # noqa: BLE001
        db.update_experiment(exp_id, status="failed", error=f"{type(exc).__name__}: {exc}"[:300])
        raise
    return exp_id


def start_experiment(params):
    p = validate_params(params)
    with _jobs_lock:
        if any(j["status"] == "running" for j in JOBS.values()):
            raise RuntimeError("an experiment is already running")
        exp_id = "exp-" + uuid.uuid4().hex[:8]
        job = {"id": exp_id, "status": "running", "progress": 0.0, "stage": "starting", "error": None, "started": time.time()}
        JOBS[exp_id] = job
    db.insert_experiment(exp_id, p["groups"], p)

    def work():
        try:
            summary, csv_path, json_path, dur = execute(exp_id, p, job)
            db.update_experiment(exp_id, status="completed", summary=summary, csv_path=csv_path, json_path=json_path, duration_s=dur)
            job.update(status="completed", progress=1.0, stage="done")
        except Exception as exc:  # noqa: BLE001
            msg = f"{type(exc).__name__}: {exc}"[:300]
            db.update_experiment(exp_id, status="failed", error=msg)
            job.update(status="failed", error=msg)
    threading.Thread(target=work, daemon=True).start()
    return exp_id


def job_status(exp_id):
    return JOBS.get(exp_id)
