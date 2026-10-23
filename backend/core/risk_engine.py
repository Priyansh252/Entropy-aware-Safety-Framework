"""Context-aware, deterministic, rule-based risk engine + decision engine.

Score = sum(weight_i * subscore_i) over *soft* factors (weights sum to 100).
Hard-fail rules (confirmed nonce reuse, confirmed shared prime, ...) are evaluated separately: they
force the score to at least `hard_fail_floor` and the category to Critical, and the candidate can
never be ACCEPTed regardless of the soft score.

Soft-factor priors are documented policy judgements, NOT experimentally derived constants.
"""
import copy
import uuid

from backend.config import DEFAULT_RISK_CONFIG

DECISIONS = ("ACCEPT", "REGENERATE", "REJECT", "SAFE_FALLBACK")


def merged_config(override=None) -> dict:
    cfg = copy.deepcopy(DEFAULT_RISK_CONFIG)
    for key, val in (override or {}).items():
        if key not in cfg:
            raise ValueError(f"unknown risk config key: {key}")
        if isinstance(cfg[key], dict):
            if not isinstance(val, dict):
                raise ValueError(f"{key} must be an object")
            cfg[key].update(val)
        else:
            cfg[key] = val
    w = cfg["weights"]
    if any((not isinstance(v, (int, float))) or v < 0 for v in w.values()):
        raise ValueError("weights must be non-negative numbers")
    return cfg


def category_for(score: float, cfg: dict) -> str:
    b = cfg["category_bounds"]
    if score < b["low"]:
        return "Low"
    if score < b["moderate"]:
        return "Moderate"
    if score < b["high"]:
        return "High"
    return "Critical"


def _clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def _soft_factors(ctx, cfg):
    w = cfg["weights"]
    out = []

    # 1. entropy quality (statistical indicator only)
    ent = ctx.get("entropy_assessment")
    if ent and ent.get("relative_to_ideal") is not None:
        ratio = ent["relative_to_ideal"]
        ok, bad = cfg["entropy_ratio_ok"], cfg["entropy_ratio_bad"]
        sub = _clamp((ok - ratio) / (ok - bad))
        expl = (f"Sample entropy is {ratio:.3f}x the ideal-uniform expectation for {ent.get('sample_size')} bytes. "
                "Statistical indicator only; it cannot prove security.")
    else:
        sub = cfg["unassessed_entropy_subscore"]
        expl = "No entropy assessment supplied; a neutral-uncertain penalty is applied."
    out.append(("entropy_quality", sub, expl))

    # 2. randomness source (declared)
    src = ctx.get("randomness_source", "unknown")
    sub = cfg["source_prior"].get(src, cfg["source_prior"]["unknown"])
    out.append(("randomness_source", sub, f"Declared randomness source '{src}' (policy prior {sub:.2f}; unknown values are treated as 'unknown')."))

    # 3. generation / nonce policy
    pol = ctx.get("generation_policy", "custom_or_unknown")
    sub = cfg["policy_prior"].get(pol, cfg["policy_prior"]["custom_or_unknown"])
    out.append(("generation_policy", sub, f"Generation/nonce policy '{pol}' (policy prior {sub:.2f})."))

    # 4. validation coverage
    val = ctx.get("validation") or {}
    required, performed = set(val.get("required", [])), set(val.get("performed", []))
    if required:
        missing = sorted(required - performed)
        sub = len(missing) / len(required)
        expl = (f"{len(required) - len(missing)}/{len(required)} required validation checks performed"
                + (f"; missing: {', '.join(missing)}." if missing else "."))
    else:
        sub, expl = 1.0, "No operation-specific validation was defined for this operation."
    out.append(("validation_coverage", sub, expl))

    # 5. security margin
    bits, req = ctx.get("security_bits"), ctx.get("required_security_bits")
    if bits is None or req is None:
        sub, expl = 0.5, "Security level or requirement not provided."
    elif bits < req:
        sub, expl = 1.0, f"Configuration provides ~{bits}-bit security, below the required {req}."
    else:
        sub, expl = 0.0, f"Configuration provides ~{bits}-bit security, meeting the required {req}."
    out.append(("security_margin", sub, expl))
    return out


def _hard_rules(ctx):
    rules = []
    if ctx.get("nonce_reuse_confirmed"):
        rules.append(("confirmed_nonce_reuse", True, "A repeated ECDSA nonce (equal r under one key) was confirmed. Any signature would leak the private key."))
    if ctx.get("shared_prime_confirmed"):
        rules.append(("rsa_shared_prime", True, "The candidate modulus shares a nontrivial prime factor with a known modulus; gcd reveals the factorisation."))
    if ctx.get("duplicate_modulus_confirmed"):
        rules.append(("rsa_duplicate_modulus", True, "The candidate modulus duplicates an existing modulus."))
    failed = (ctx.get("validation") or {}).get("failed", [])
    other = [f for f in failed if f not in ("no_shared_prime_with_registry", "no_duplicate_modulus")]
    if other:
        rules.append(("invalid_parameters", True, "Required parameter checks failed: " + ", ".join(other) + "."))
    if ctx.get("randomness_source") == "known_weak":
        rules.append(("known_weak_randomness_source", False, "The randomness source is declared known-weak; regenerating from it cannot help."))
    bits, req = ctx.get("security_bits"), ctx.get("required_security_bits")
    if bits is not None and req is not None and bits < req:
        rules.append(("insufficient_security_level", False, f"Configuration (~{bits}-bit) is weaker than the required {req}-bit level; weaker configurations are never accepted."))
    return rules


def evaluate(ctx: dict, cfg_override=None, regen_count: int = 0, max_regen: int = 3) -> dict:
    cfg = merged_config(cfg_override)
    weights = cfg["weights"]
    factors, soft_total = [], 0.0
    for name, sub, expl in _soft_factors(ctx, cfg):
        pts = weights.get(name, 0) * sub
        soft_total += pts
        factors.append({"name": name, "kind": "soft", "weight": weights.get(name, 0),
                        "subscore": round(sub, 4), "points": round(pts, 2), "explanation": expl})
    hard = _hard_rules(ctx)
    for name, regenerable, expl in hard:
        factors.append({"name": name, "kind": "hard_fail", "weight": None, "subscore": 1.0,
                        "points": None, "explanation": expl, "regenerable": regenerable})
    soft_total = min(100.0, soft_total)
    score = max(soft_total, cfg["hard_fail_floor"]) if hard else soft_total
    category = "Critical" if hard else category_for(score, cfg)

    unsafe = bool(hard) or score >= cfg["accept_below"]
    candidate_specific = bool(hard) and all(r for _, r, _ in hard)
    fallback_ok = bool(ctx.get("fallback_available"))
    if not unsafe:
        decision, reason = "ACCEPT", "No hard-fail condition and score below the acceptance threshold."
    elif candidate_specific and regen_count < max_regen:
        decision, reason = "REGENERATE", "The candidate failed a candidate-specific check; discard it and generate a replacement."
    elif fallback_ok:
        decision, reason = "SAFE_FALLBACK", "Regeneration cannot resolve the issue or the budget is exhausted; switching to a vetted compatible configuration."
    else:
        decision, reason = "REJECT", "No safe candidate can be produced under the stated requirements; operation stopped."
    return {
        "assessment_id": uuid.uuid4().hex[:12],
        "risk_score": round(score, 2),
        "soft_score": round(soft_total, 2),
        "risk_category": category,
        "hard_fail": bool(hard),
        "factors": factors,
        "decision": decision,
        "recommended_action": reason,
        "regen_count": regen_count,
        "max_regen": max_regen,
        "validation_evidence": {
            "performed": (ctx.get("validation") or {}).get("performed", []),
            "failed": (ctx.get("validation") or {}).get("failed", []),
            "nonce_reuse_confirmed": bool(ctx.get("nonce_reuse_confirmed")),
            "shared_prime_confirmed": bool(ctx.get("shared_prime_confirmed")),
            "duplicate_modulus_confirmed": bool(ctx.get("duplicate_modulus_confirmed")),
        },
        "thresholds": {"accept_below": cfg["accept_below"], "category_bounds": cfg["category_bounds"],
                       "hard_fail_floor": cfg["hard_fail_floor"]},
    }


def evaluate_safely(ctx, cfg_override=None, regen_count=0, max_regen=3) -> dict:
    """Fail-safe wrapper: any internal error becomes REJECT, never ACCEPT."""
    try:
        return evaluate(ctx, cfg_override, regen_count, max_regen)
    except Exception as exc:  # noqa: BLE001
        return {"assessment_id": uuid.uuid4().hex[:12], "risk_score": 100.0, "soft_score": 100.0,
                "risk_category": "Critical", "hard_fail": True,
                "factors": [{"name": "evaluation_error", "kind": "hard_fail", "weight": None, "subscore": 1.0,
                             "points": None, "explanation": f"Risk evaluation failed ({type(exc).__name__}); failing safe."}],
                "decision": "REJECT", "recommended_action": "Evaluation error: rejecting (fail-safe).",
                "regen_count": regen_count, "max_regen": max_regen, "validation_evidence": {}, "thresholds": {}}
