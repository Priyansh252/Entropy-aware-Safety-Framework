"""REST API. All responses: {"ok": true, "data": ...} or {"ok": false, "error": {"code","message"}}."""
import platform
import threading
import time
import uuid

from flask import Blueprint, jsonify, request, send_file

from backend import config
from backend.core import adaptive_selector, ecdsa_lab as EL, entropy, experiments as X, risk_engine, rsa_lab as RL
from backend.core import safety_layer as SL
from backend.core.metrics import overhead_pct, summarize
from backend.storage import db

bp = Blueprint("api", __name__, url_prefix="/api")


class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def ok(data, status=200):
    return jsonify({"ok": True, "data": data}), status


def body():
    b = request.get_json(silent=True)
    if b is None:
        return {}
    if not isinstance(b, dict):
        raise ApiError(400, "bad_request", "JSON body must be an object")
    return b


def int_field(b, name, default, lo, hi):
    v = b.get(name, default)
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise ApiError(400, "validation_error", f"'{name}' must be an integer")
    if not lo <= v <= hi:
        raise ApiError(400, "validation_error", f"'{name}' must be between {lo} and {hi}")
    return v


def float_field(b, name, default, lo, hi):
    v = b.get(name, default)
    try:
        v = float(v)
    except (TypeError, ValueError):
        raise ApiError(400, "validation_error", f"'{name}' must be a number")
    if not lo <= v <= hi:
        raise ApiError(400, "validation_error", f"'{name}' must be between {lo} and {hi}")
    return v


def msg_field(b, name, default=None):
    v = b.get(name, default)
    lo, hi = config.LIMITS["message_length"]
    if not isinstance(v, str) or not lo <= len(v) <= hi:
        raise ApiError(400, "validation_error", f"'{name}' must be a string of {lo}-{hi} characters")
    return v.encode("utf-8")


def choice(b, name, options, default):
    v = b.get(name, default)
    if v not in options:
        raise ApiError(400, "validation_error", f"'{name}' must be one of {list(options)}")
    return v


def requirements_from(b, rsa=False):
    r = b.get("requirements") or {}
    if not isinstance(r, dict):
        raise ApiError(400, "validation_error", "'requirements' must be an object")
    comp = r.get("compatibility", [])
    if not isinstance(comp, list) or any(c not in adaptive_selector.KNOWN_TAGS + ["randomized_signing_only"] for c in comp):
        raise ApiError(400, "validation_error", "unknown compatibility tag")
    out = {"operation": choice(r, "operation", adaptive_selector.OPERATIONS, "signature"),
           "required_security_bits": int_field(r, "required_security_bits", 128, 80, 256),
           "performance_priority": choice(r, "performance_priority", adaptive_selector.PERF, "balanced"),
           "compatibility": comp, "allow_fallback": bool(r.get("allow_fallback", True))}
    if rsa and "required_security_bits" not in r:
        out.pop("required_security_bits")      # RSAGuard then defaults to the strength of the key size in use
    return out


def flush(buf):
    try:
        buf.flush()
    except Exception:  # noqa: BLE001 - audit failure must not leak details
        pass


def _hexprev(n, head=20):
    h = f"{n:x}"
    return h[:head] + "…" + h[-6:]


# ---------------------------------------------------------------- health / dashboard
@bp.get("/health")
def health():
    db.init_db()
    return ok({"status": "ok", "time": db.now(), "python": platform.python_version(), "database": "sqlite", "version": "1.0.0"})


@bp.get("/dashboard")
def dashboard():
    stats = db.dashboard_stats()
    comp = {}
    for g in ("ecdsa_defense", "rsa_defense"):
        e = db.latest_completed_with_group(g)
        if e:
            h = e["summary"]["groups"][g]["headline"]
            comp[g] = {"experiment_id": e["id"], "created": e["created"],
                       "baseline": h.get("baseline_attack_success_rate"), "defended": h.get("defended_attack_success_rate"),
                       "trials": e["summary"]["groups"][g]["effective_trials"]}
    stats["attack_comparison"] = comp
    stats["running"] = [{"id": j["id"], "progress": j["progress"], "stage": j["stage"]}
                        for j in X.JOBS.values() if j["status"] == "running"]
    return ok(stats)


# ---------------------------------------------------------------- entropy
@bp.post("/entropy/assess")
def entropy_assess():
    b = body()
    size = int_field(b, "size", 4096, *config.LIMITS["entropy_sample_size"])
    if b.get("hex"):
        try:
            data = bytes.fromhex(str(b["hex"]).replace(" ", ""))
        except ValueError:
            raise ApiError(400, "validation_error", "'hex' must be a valid hex string")
        if not 2 <= len(data) <= 65536:
            raise ApiError(400, "validation_error", "custom sample must be 2-65536 bytes")
        meta = {"kind": "custom_hex", "seeded_synthetic": False}
    else:
        kind = choice(b, "kind", entropy.SAMPLE_KINDS, "uniform")
        seed = b.get("seed")
        if seed not in (None, ""):
            seed = int_field(b, "seed", 0, 0, 2**31 - 1)
        else:
            seed = None
        data, meta = entropy.generate_sample(kind, size, seed, float_field(b, "bias", 0.5, 0.0, 1.0))
    res = entropy.assess(data)
    res["meta"] = meta
    return ok(res)


@bp.post("/entropy/compare")
def entropy_compare():
    b = body()
    kinds = b.get("kinds") or entropy.SAMPLE_KINDS
    if not isinstance(kinds, list) or not kinds or any(k not in entropy.SAMPLE_KINDS for k in kinds):
        raise ApiError(400, "validation_error", f"'kinds' must be a subset of {entropy.SAMPLE_KINDS}")
    size = int_field(b, "size", 4096, 64, 262144)
    seed = int_field(b, "seed", 7, 0, 2**31 - 1)
    out = []
    for i, k in enumerate(kinds):
        data, meta = entropy.generate_sample(k, size, seed + i)
        a = entropy.assess(data)
        a["meta"] = meta
        out.append({"kind": k, **a})
    return ok({"samples": out})


# ---------------------------------------------------------------- ECDSA lab
def _sess(b):
    try:
        return EL.get_session(str(b.get("session_id", "")))
    except KeyError:
        raise ApiError(404, "not_found", "Unknown or expired lab session; create a new test key.")


@bp.post("/ecdsa/session")
def ecdsa_session():
    return ok(EL.session_view(EL.create_session()))


@bp.get("/ecdsa/session/<sid>")
def ecdsa_session_get(sid):
    try:
        return ok(EL.session_view(EL.get_session(sid)))
    except KeyError:
        raise ApiError(404, "not_found", "Unknown or expired lab session")


@bp.post("/ecdsa/sign")
def ecdsa_sign():
    b = body()
    s = _sess(b)
    m = msg_field(b, "message")
    mode = choice(b, "mode", ["secure", "deterministic"], "secure")
    r, sv = EL.library_sign(s.key, m, deterministic=(mode == "deterministic"))
    sig = EL.add_signature(s, m, r, sv, "library_deterministic_rfc6979" if mode == "deterministic" else "library_random_nonce")
    return ok({"signature": sig, "session": EL.session_view(s)})


@bp.post("/ecdsa/reuse")
def ecdsa_reuse():
    """EDUCATIONAL ATTACK MODE: deliberately signs two messages with the same nonce."""
    b = body()
    s = _sess(b)
    m1, m2 = msg_field(b, "message1", "pay Alice 10"), msg_field(b, "message2", "pay Mallory 9999")
    if m1 == m2:
        raise ApiError(400, "validation_error", "the two messages must differ")
    k = EL.random_nonce()
    sigs = []
    for m in (m1, m2):
        r, sv = EL.educational_sign_with_nonce(s.key, m, k)
        sigs.append(EL.add_signature(s, m, r, sv, "EDUCATIONAL_reused_nonce"))
    return ok({"warning": "Educational attack mode: the same nonce was deliberately used for both signatures.",
               "signatures": sigs, "session": EL.session_view(s)})


@bp.post("/ecdsa/detect")
def ecdsa_detect():
    s = _sess(body())
    groups = EL.detect_nonce_reuse(s.sigs)
    return ok({"reuse_detected": bool(groups), "groups": groups, "signatures_checked": len(s.sigs),
               "method": "Signature analysis: equal r under one public key implies equal kG, i.e. a repeated nonce. This is independent of any entropy measurement."})


@bp.post("/ecdsa/recover")
def ecdsa_recover():
    b = body()
    s = _sess(b)
    res = EL.do_recover(s, b.get("signature_id_1"), b.get("signature_id_2"))
    db.insert_attack_run("ECDSA nonce reuse key recovery", bool(res.get("recovered") and res.get("matches_original")),
                         {k: v for k, v in res.items() if k in ("recovered", "variant", "matches_original", "public_key_check", "forgery_verifies")})
    return ok({"recovery": res, "equations": {
        "k": "k = (z1 - z2) · (s1 - s2)^-1  mod n", "d": "d = (s1·k - z1) · r^-1  mod n"}})


@bp.post("/ecdsa/defended")
def ecdsa_defended():
    b = body()
    s = _sess(b)
    m1, m2 = msg_field(b, "message1", "pay Alice 10"), msg_field(b, "message2", "pay Mallory 9999")
    max_regen = int_field(b, "max_regen", 3, *config.LIMITS["max_regeneration"])
    req = requirements_from(b)
    guard = SL.ECDSAGuard(s.key, EL.FaultyNonceSource("stuck"), max_regen, req, None, "interactive_demo")
    guard.seen_r = {x["r"] for x in s.sigs}
    buf = db.AuditBuffer()
    guard.audit = buf
    results = []
    for m in (m1, m2):
        res = guard.sign(m)
        entry = {"message": m.decode(), "status": res["status"], "decision": res["decision"], "regenerations": res["regenerations"],
                 "trace": res["trace"], "risk": res["risk"], "verified": res["verified"], "exec_ms": res["exec_ms"]}
        if res["r"] is not None:
            entry["signature"] = EL.add_signature(s, m, res["r"], res["s"],
                                                  "defended_deterministic_fallback" if res["status"] == "fallback_signed" else "defended_checked_nonce")
        results.append(entry)
    flush(buf)
    groups = EL.detect_nonce_reuse(s.sigs[-2:] if len(s.sigs) >= 2 else s.sigs)
    last2 = [x for x in s.sigs if x["mode"].startswith("defended")]
    atk = {"recovered": False, "reason": "fewer than two defended signatures"}
    if len(last2) >= 2:
        atk = EL.recover_private_key(s.pub, last2[-2]["message"], (last2[-2]["r"], last2[-2]["s"]),
                                     last2[-1]["message"], (last2[-1]["r"], last2[-1]["s"]))
    return ok({"source_model": "SIMULATED stuck nonce source (always proposes the same nonce)", "results": results,
               "reuse_in_defended_signatures": bool(groups), "attack_attempt_recovered_key": bool(atk["recovered"]),
               "attack_reason": atk.get("reason"), "session": EL.session_view(s)})


@bp.post("/ecdsa/verify")
def ecdsa_verify():
    b = body()
    s = _sess(b)
    sid = b.get("signature_id")
    rec = next((x for x in s.sigs if x["id"] == sid), None)
    if rec is None:
        raise ApiError(404, "not_found", "signature not found in this session")
    return ok({"signature_id": sid, "valid": EL.verify(s.pub, rec["message"], rec["r"], rec["s"])})


# ---------------------------------------------------------------- RSA lab
_COLLECTIONS = {}
_clock = threading.Lock()


def _col(b):
    c = _COLLECTIONS.get(str(b.get("collection_id", "")))
    if c is None:
        raise ApiError(404, "not_found", "Unknown or expired collection; generate a new one.")
    return c


@bp.post("/rsa/collection")
def rsa_collection():
    b = body()
    n_keys = int_field(b, "n_keys", 8, *config.LIMITS["rsa_collection_keys"])
    pairs = int_field(b, "shared_pairs", 0, 0, n_keys // 2)
    bits = int_field(b, "key_bits", 1024, *config.LIMITS["rsa_key_bits"])
    if bits not in (1024, 2048):
        raise ApiError(400, "validation_error", "'key_bits' must be 1024 or 2048 (educational sizes)")
    keys = RL.make_collection(n_keys, pairs, bits)
    cid = uuid.uuid4().hex[:10]
    with _clock:
        if len(_COLLECTIONS) >= 20:
            _COLLECTIONS.pop(next(iter(_COLLECTIONS)))
        _COLLECTIONS[cid] = {"keys": keys, "bits": bits, "pairs": pairs, "scan": None}
    return ok({"collection_id": cid, "key_bits": bits, "educational_note": "Reduced key size for demonstration only; not a production recommendation.",
               "planted_shared_pairs": pairs, "keys": [{"index": k["index"], "modulus_preview": _hexprev(k["n"]), "modulus_bits": k["n"].bit_length(), "e": k["e"]} for k in keys]})


@bp.post("/rsa/scan")
def rsa_scan():
    b = body()
    c = _col(b)
    keys = c["keys"]
    ns = [k["n"] for k in keys]
    t0 = time.perf_counter()
    findings = RL.analyze_moduli(ns)
    ms = (time.perf_counter() - t0) * 1000
    edges = []
    for i in range(len(ns)):
        for j in range(i + 1, len(ns)):
            g = RL.math.gcd(ns[i], ns[j])
            if g > 1:
                edges.append({"a": i, "b": j, "shared_factor_bits": g.bit_length(), "factor_preview": _hexprev(g, 12)})
    tp = fp = tn = fn = 0
    out = []
    for k, f in zip(keys, findings):
        flagged = f["status"] != "ok"
        tp += flagged and k["vulnerable"]
        fp += flagged and not k["vulnerable"]
        tn += (not flagged) and not k["vulnerable"]
        fn += (not flagged) and k["vulnerable"]
        out.append({"index": k["index"], "status": f["status"], "factor_recoverable": f["factor"] is not None,
                    "factor_preview": _hexprev(f["factor"], 12) if f["factor"] else None,
                    "planted_vulnerable": k["vulnerable"], "correct": flagged == k["vulnerable"]})
    c["scan"] = findings
    from backend.core.metrics import confusion
    return ok({"findings": out, "edges": edges, "batch_gcd_ms": ms, "keys_scanned": len(keys),
               "flagged": sum(f["status"] != "ok" for f in findings), "confusion": confusion(tp, fp, tn, fn),
               "scope_note": "Batch GCD audits only the moduli supplied here (a population-level check); it does not prove an individual key safe against keys it was not compared with."})


@bp.post("/rsa/recover")
def rsa_recover():
    b = body()
    c = _col(b)
    findings = c["scan"] or RL.analyze_moduli([k["n"] for k in c["keys"]])
    results = []
    for k, f in zip(c["keys"], findings):
        if f["factor"]:
            v = RL.verify_recovered_factor(k["n"], k["e"], f["factor"])
            results.append({"index": k["index"], "recovered": bool(v["verified"]),
                            "matches_original": bool(v["verified"] and f["factor"] in (k["p"], k["q"])),
                            "p_fingerprint": v.get("p_fingerprint"), "reason": v.get("reason")})
    success = bool(results) and all(r["recovered"] and r["matches_original"] for r in results)
    db.insert_attack_run("RSA shared-prime factor recovery", success, {"keys_recovered": len(results)})
    return ok({"recovered_keys": results, "count": len(results),
               "verification": "Each recovered key was rebuilt from (n, e, p), used to sign, and verified with an independently built public key."})


@bp.post("/rsa/defended")
def rsa_defended():
    b = body()
    n = int_field(b, "n_keys", 10, 3, 25)
    max_regen = int_field(b, "max_regen", 3, *config.LIMITS["max_regeneration"])
    if n * (max_regen + 1) > 198:
        raise ApiError(400, "validation_error", "n_keys * (max_regen + 1) must be <= 198")
    p = float_field(b, "fault_probability", 0.25, 0.0, 0.9)
    mode = choice(b, "fault_mode", ["intermittent_repeat", "stuck"], "intermittent_repeat")
    bits = int_field(b, "key_bits", 1024, 1024, 2048)
    req = requirements_from(b, rsa=True)
    seed = int_field(b, "seed", 11, 0, 2**31 - 1)
    buf = db.AuditBuffer()
    base = SL.run_rsa_population("baseline", n, mode, p, bits, seed, max_regen, req, None, "interactive_demo")
    dfn = SL.run_rsa_population("defended", n, mode, p, bits, seed, max_regen, req, buf, "interactive_demo")
    flush(buf)
    db.insert_attack_run("RSA batch-GCD on undefended population", base["keys_factored_by_batch_gcd"] > 0, {"factored": base["keys_factored_by_batch_gcd"]})
    for r in (base, dfn):
        r["mean_ms_per_key"] = summarize(r.pop("times_ms"))["mean"]
    return ok({"baseline": base, "defended": dfn, "overhead_pct": overhead_pct(base["mean_ms_per_key"], dfn["mean_ms_per_key"]),
               "source_model": "SIMULATED prime source that re-uses earlier-issued primes", "key_bits": bits})


# ---------------------------------------------------------------- safety engine
@bp.get("/safety/config")
def safety_config():
    return ok({"risk_config": config.DEFAULT_RISK_CONFIG, "catalog": adaptive_selector.CATALOG, "operations": adaptive_selector.OPERATIONS,
               "compatibility_tags": adaptive_selector.KNOWN_TAGS + ["randomized_signing_only"],
               "note": "Weights, priors and thresholds are an initial transparent baseline, not experimentally proven optima."})


@bp.post("/safety/select")
def safety_select():
    b = body()
    r = requirements_from({"requirements": b.get("requirements", b)})
    r["supported_algorithms"] = b.get("supported_algorithms") if isinstance(b.get("supported_algorithms"), list) else None
    try:
        return ok(adaptive_selector.select(r))
    except ValueError as e:
        raise ApiError(400, "validation_error", str(e))


_CTX_KEYS = {"operation", "algorithm", "configuration", "randomness_source", "generation_policy", "security_bits", "required_security_bits",
             "validation", "nonce_reuse_confirmed", "shared_prime_confirmed", "duplicate_modulus_confirmed", "entropy_assessment", "fallback_available"}


@bp.post("/safety/evaluate")
def safety_evaluate():
    b = body()
    ctx = b.get("context")
    if not isinstance(ctx, dict) or not (set(ctx) <= _CTX_KEYS):
        raise ApiError(400, "validation_error", f"'context' must be an object with keys from {sorted(_CTX_KEYS)}")
    max_regen = int_field(b, "max_regen", 3, *config.LIMITS["max_regeneration"])
    regen = int_field(b, "regen_count", 0, 0, 10)
    try:
        risk = risk_engine.evaluate(ctx, b.get("risk_config"), regen, max_regen)
    except ValueError as e:
        raise ApiError(400, "validation_error", str(e))
    buf = db.AuditBuffer()
    buf(db.audit_record_from_risk(risk, operation=ctx.get("operation", "custom"), algorithm=ctx.get("algorithm", "n/a"),
                                  configuration=ctx.get("configuration", "custom context"), candidate_id="manual",
                                  exec_ms=0.0, mode="interactive_demo",
                                  validation_outcome="failed" if risk["hard_fail"] else "passed"))
    flush(buf)
    return ok(risk)


@bp.post("/safety/scenario")
def safety_scenario():
    """Runs a REAL guarded generation for one protected operation and returns the decision trace."""
    b = body()
    target = choice(b, "target", ["ecdsa_sign", "rsa_keygen"], "ecdsa_sign")
    condition = choice(b, "condition", ["healthy", "faulty"], "faulty")
    max_regen = int_field(b, "max_regen", 3, *config.LIMITS["max_regeneration"])
    req = requirements_from(b)
    buf = db.AuditBuffer()
    note = None
    selection = adaptive_selector.select({**req, "operation": req["operation"]})
    if target == "ecdsa_sign":
        key = EL.new_test_key()
        guard = SL.ECDSAGuard(key, EL.FaultyNonceSource("healthy" if condition == "healthy" else "stuck"), max_regen, req, buf, "interactive_demo")
        runs = [guard.sign(b"first message"), guard.sign(b"second message")]
        ops = [{"label": f"Signing operation {i + 1}", **{k: r[k] for k in ("status", "decision", "regenerations", "trace", "risk", "verified")}} for i, r in enumerate(runs)]
    else:
        bits = int_field(b, "key_bits", 1024, 1024, 2048)
        import random as _r
        ks = SL.rsa_security_bits(bits)
        guard_req = dict(req)
        if guard_req["required_security_bits"] > ks:
            note = (f"RSA-{bits} is an educational size (about {ks}-bit security). For this scenario the required level was capped at "
                    f"{ks}-bit so the shared-prime handling can be shown; the adaptive selection above still uses your requested "
                    f"{req['required_security_bits']}-bit level.")
            guard_req["required_security_bits"] = ks
        extra = max_regen + 2
        col = RL.make_collection(3 + extra, 0, bits, seed=5)           # one collection => all primes distinct
        registry_keys = col[:3]
        src = RL.RSACandidateSource("healthy" if condition == "healthy" else "stuck", 1.0, bits, _r.Random(9), max_candidates=extra)
        src._fresh = [x for k in col[3:] for x in (k["p"], k["q"])]
        if condition == "faulty":
            src.reuse_pool = [x for k in registry_keys for x in (k["p"], k["q"])]   # always re-uses a known key's prime
        guard = SL.RSAGuard(src, bits, max_regen, guard_req, buf, "interactive_demo", registry=[k["n"] for k in registry_keys])
        r = guard.generate()
        ops = [{"label": "Key generation", **{k: r[k] for k in ("status", "decision", "regenerations", "trace", "risk")}, "fallback_config": r.get("fallback_config")}]
    flush(buf)
    return ok({"target": target, "condition": condition, "selection": selection, "operations": ops, "requirements": req, "requirement_note": note,
               "source_model": "SIMULATED faulty source" if condition == "faulty" else "OS CSPRNG-backed healthy source"})


@bp.post("/safety/defense-demo")
def defense_demo():
    b = body()
    target = choice(b, "target", ["ecdsa", "rsa"], "ecdsa")
    p = float_field(b, "fault_probability", 0.2, 0.0, 0.9)
    mode = choice(b, "fault_mode", ["intermittent_repeat", "stuck"], "intermittent_repeat")
    max_regen = int_field(b, "max_regen", 3, *config.LIMITS["max_regeneration"])
    req = requirements_from(b, rsa=(target == "rsa"))
    buf = db.AuditBuffer()
    seed = int_field(b, "seed", 21, 0, 2**31 - 1)
    if target == "ecdsa":
        n = int_field(b, "n", 30, *config.LIMITS["defense_signatures"])
        arms = {a: SL.run_ecdsa_session(a, n, mode, p, seed, max_regen, req, buf if a == "guard" else None, "interactive_demo")
                for a in ("baseline", "guard", "deterministic")}
        for r in arms.values():
            r.pop("_guard", None)
    else:
        n = int_field(b, "n", 10, 3, 25)
        if n * (max_regen + 1) > 198:
            raise ApiError(400, "validation_error", "n * (max_regen + 1) must be <= 198")
        arms = {a: SL.run_rsa_population(a, n, mode, p, 1024, seed, max_regen, req, buf if a == "defended" else None, "interactive_demo")
                for a in ("baseline", "defended")}
    flush(buf)
    base_key = "baseline"
    for r in arms.values():
        r["mean_ms"] = summarize(r.pop("times_ms"))["mean"]
        r["overhead_pct_vs_baseline"] = overhead_pct(arms[base_key]["mean_ms"], r["mean_ms"]) if r["arm"] != base_key else 0.0
    compromised = arms["baseline"].get("compromised", arms["baseline"].get("keys_factored_by_batch_gcd", 0) > 0)
    db.insert_attack_run(f"{target.upper()} undefended workflow compromised", bool(compromised), {"target": target})
    return ok({"target": target, "arms": arms, "fault_mode": mode, "fault_probability": p,
               "source_model": "SIMULATED fault injection (seeded for repeatability)"})


# ---------------------------------------------------------------- experiments
@bp.get("/experiments/options")
def exp_options():
    return ok({"groups": [{"id": k, **{kk: vv for kk, vv in v.items()}} for k, v in X.GROUPS.items()],
               "defaults": X.DEFAULTS, "limits": config.LIMITS})


@bp.post("/experiments/run")
def exp_run():
    try:
        eid = X.start_experiment(body())
    except ValueError as e:
        raise ApiError(400, "validation_error", str(e))
    except RuntimeError as e:
        raise ApiError(409, "busy", str(e))
    return ok({"experiment_id": eid}, 202)


@bp.get("/experiments/status/<eid>")
def exp_status(eid):
    j = X.job_status(eid)
    if j:
        return ok({k: j[k] for k in ("id", "status", "progress", "stage", "error")})
    e = db.get_experiment(eid)
    if not e:
        raise ApiError(404, "not_found", "unknown experiment")
    return ok({"id": eid, "status": e["status"], "progress": 1.0 if e["status"] == "completed" else 0.0, "stage": e["status"], "error": e["error"]})


@bp.get("/experiments")
def exp_list():
    return ok({"experiments": db.list_experiments(50)})


@bp.get("/experiments/<eid>")
def exp_get(eid):
    e = db.get_experiment(eid)
    if not e:
        raise ApiError(404, "not_found", "unknown experiment")
    e.pop("csv_path", None)
    e.pop("json_path", None)
    return ok(e)


@bp.get("/experiments/<eid>/export")
def exp_export(eid):
    fmt = request.args.get("format", "json")
    e = db.get_experiment(eid)
    if not e or e["status"] != "completed":
        raise ApiError(404, "not_found", "completed experiment not found")
    if fmt not in ("csv", "json"):
        raise ApiError(400, "validation_error", "format must be csv or json")
    path = e["csv_path"] if fmt == "csv" else e["json_path"]
    return send_file(path, as_attachment=True, download_name=f"{eid}_{'raw_results.csv' if fmt == 'csv' else 'summary.json'}")


# ---------------------------------------------------------------- audit
@bp.get("/audit")
def audit():
    a = request.args
    try:
        limit = max(1, min(500, int(a.get("limit", 100))))
        offset = max(0, int(a.get("offset", 0)))
    except ValueError:
        raise ApiError(400, "validation_error", "limit/offset must be integers")
    return ok(db.query_audit(a.get("search", "")[:80], a.get("decision", ""), a.get("operation", ""), a.get("category", ""),
                             a.get("mode", ""), a.get("sort", "ts"), a.get("order", "desc"), limit, offset))
