import csv
import io
import json
import os
import sqlite3
import pytest
from backend.core import ecdsa_lab as EL, experiments as X
from backend.storage import db
from backend.tests.conftest import post


def test_health_and_unknown_routes(client):
    r = client.get("/api/health").get_json()
    assert r["ok"] and r["data"]["status"] == "ok"
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.get_json()["ok"] is False
    assert client.get("/api/ecdsa/sign").status_code in (404, 405) and client.get("/api/ecdsa/sign").get_json()["ok"] is False


def test_input_validation(client):
    assert post(client, "/api/entropy/assess", {"size": 3})[0] == 400
    assert post(client, "/api/entropy/assess", {"kind": "zzz"})[0] == 400
    assert post(client, "/api/entropy/assess", {"hex": "zz"})[0] == 400
    assert post(client, "/api/rsa/collection", {"n_keys": 500})[0] == 400
    assert post(client, "/api/rsa/collection", {"n_keys": 4, "shared_pairs": 3})[0] == 400
    assert post(client, "/api/rsa/collection", {"key_bits": 512})[0] == 400
    assert post(client, "/api/ecdsa/sign", {"session_id": "nope", "message": "x"})[0] == 404
    assert post(client, "/api/experiments/run", {"trials": 100000})[0] == 400
    assert post(client, "/api/experiments/run", {"groups": ["bogus"]})[0] == 400
    assert post(client, "/api/safety/evaluate", {"context": {"evil": 1}})[0] == 400
    assert post(client, "/api/safety/select", {"operation": "fly"})[0] == 400
    code, body = post(client, "/api/entropy/assess", {"size": 3})
    assert body["ok"] is False and "message" in body["error"] and "Traceback" not in json.dumps(body)


def test_entropy_endpoint_real_values(client):
    _, b = post(client, "/api/entropy/assess", {"kind": "constant", "size": 256})
    assert b["data"]["shannon_bits_per_byte"] == 0
    _, b = post(client, "/api/entropy/assess", {"hex": "00" * 64})
    assert b["data"]["unique_byte_values"] == 1


def test_ecdsa_flow_end_to_end_and_no_secret_leak(client):
    _, s = post(client, "/api/ecdsa/session")
    sid = s["data"]["session_id"]
    assert post(client, "/api/ecdsa/sign", {"session_id": sid, "message": "hello", "mode": "deterministic"})[1]["data"]["signature"]["verified"]
    assert post(client, "/api/ecdsa/detect", {"session_id": sid})[1]["data"]["reuse_detected"] is False
    c, r = post(client, "/api/ecdsa/reuse", {"session_id": sid})
    assert c == 200 and "warning" in r["data"]
    assert post(client, "/api/ecdsa/detect", {"session_id": sid})[1]["data"]["reuse_detected"] is True
    c, rec = post(client, "/api/ecdsa/recover", {"session_id": sid})
    assert rec["data"]["recovery"]["recovered"] and rec["data"]["recovery"]["matches_original"]
    d_hex = f"{EL.private_value(EL.get_session(sid).key):064x}"
    assert d_hex not in json.dumps(rec) and d_hex not in json.dumps(r)
    _, dv = post(client, "/api/ecdsa/defended", {"session_id": sid})
    assert dv["data"]["attack_attempt_recovered_key"] is False
    assert [x["decision"] for x in dv["data"]["results"]][1] == "SAFE_FALLBACK"
    sig_id = r["data"]["signatures"][0]["id"]
    assert post(client, "/api/ecdsa/verify", {"session_id": sid, "signature_id": sig_id})[1]["data"]["valid"]


def test_rsa_flow(client):
    _, c = post(client, "/api/rsa/collection", {"n_keys": 8, "shared_pairs": 2})
    cid = c["data"]["collection_id"]
    assert "p" not in json.dumps(c["data"]["keys"][0]).replace("preview", "").replace("modulus", "")  # no factors in listing
    _, s = post(client, "/api/rsa/scan", {"collection_id": cid})
    assert s["data"]["flagged"] == 4 and s["data"]["confusion"]["detection_rate"]["rate"] == 1.0
    _, rc = post(client, "/api/rsa/recover", {"collection_id": cid})
    assert rc["data"]["count"] == 4 and all(x["recovered"] and x["matches_original"] for x in rc["data"]["recovered_keys"])
    _, c0 = post(client, "/api/rsa/collection", {"n_keys": 6, "shared_pairs": 0})
    _, s0 = post(client, "/api/rsa/scan", {"collection_id": c0["data"]["collection_id"]})
    assert s0["data"]["flagged"] == 0


def test_safety_endpoints_and_audit_persistence(client):
    _, sc = post(client, "/api/safety/scenario", {"target": "ecdsa_sign", "condition": "faulty", "max_regen": 2})
    ops = sc["data"]["operations"]
    assert ops[0]["decision"] == "ACCEPT" and ops[1]["decision"] == "SAFE_FALLBACK" and ops[1]["status"] == "fallback_signed"
    _, sc = post(client, "/api/safety/scenario", {"target": "rsa_keygen", "condition": "faulty", "requirements": {"compatibility": ["legacy_rsa"], "operation": "signature"}})
    assert sc["data"]["operations"][0]["decision"] == "REJECT" and sc["data"]["operations"][0]["status"] == "rejected"
    _, ev = post(client, "/api/safety/evaluate", {"context": {"operation": "ecdsa_sign", "nonce_reuse_confirmed": True}})
    assert ev["data"]["hard_fail"] and ev["data"]["decision"] != "ACCEPT"
    a = client.get("/api/audit?limit=500&decision=REJECT").get_json()["data"]
    assert a["total"] >= 1 and all(r["decision"] == "REJECT" for r in a["rows"])
    a = client.get("/api/audit?search=rsa_keygen&sort=risk_score&order=asc").get_json()["data"]
    assert a["rows"] and all("rsa_keygen" in r["operation"] for r in a["rows"])
    rows = client.get("/api/audit?limit=500").get_json()["data"]["rows"]
    assert all(set(r) >= {"ts", "operation", "configuration", "risk_score", "decision", "validation_outcome", "exec_ms", "regen_count", "mode"} for r in rows)
    con = sqlite3.connect(os.environ["EAF_DB_PATH"])
    blob = " ".join(str(x) for row in con.execute("SELECT * FROM audit_log") for x in row).lower()
    assert "private" not in blob and "\"nonce\"" not in blob


def test_defense_demo_endpoint(client):
    _, d = post(client, "/api/safety/defense-demo", {"target": "ecdsa", "n": 30, "fault_probability": 0.4})
    arms = d["data"]["arms"]
    assert arms["baseline"]["compromised"] and not arms["guard"]["compromised"] and not arms["deterministic"]["compromised"]
    assert arms["guard"]["vulnerable_signatures"] == 0 and arms["baseline"]["vulnerable_signatures"] > 0
    _, d = post(client, "/api/safety/defense-demo", {"target": "rsa", "n": 8, "fault_probability": 0.5})
    assert d["data"]["arms"]["defended"]["vulnerable_final"] == 0


def test_dashboard_reflects_real_data(client):
    d = client.get("/api/dashboard").get_json()["data"]
    assert d["total_assessments"] > 0 and d["attacks_succeeded"] >= 1 and d["vulnerable_detected"] >= 1


# ---------------------------------------------------------------- experiments
SMALL = {"trials": 4, "groups": ["entropy_samples", "ecdsa_attack", "ecdsa_defense", "rsa_batch_gcd", "rsa_defense", "threshold_sensitivity", "overhead", "adaptive_policy"],
         "signatures_per_session": 10, "rsa_keys_per_population": 6, "collection_size": 8}


def test_param_validation():
    for bad in ({"trials": 0}, {"trials": 501}, {"fault_probability": 2}, {"key_bits": 512}, {"sample_size": 10}, {"fault_mode": "x"},
                {"rsa_keys_per_population": 25, "max_regen": 10}, {"groups": []}):
        with pytest.raises(ValueError):
            X.validate_params(bad)
    assert X.validate_params({})["trials"] == 30


def test_experiment_run_metrics_persistence_and_export(client):
    eid = X.run_experiment_sync(SMALL)
    e = db.get_experiment(eid)
    assert e["status"] == "completed" and os.path.exists(e["csv_path"]) and os.path.exists(e["json_path"])
    g = e["summary"]["groups"]
    assert g["ecdsa_attack"]["metrics"]["attack_success_reused"]["rate"] == 1.0
    assert g["ecdsa_attack"]["metrics"]["attack_success_normal"]["rate"] == 0.0
    assert g["ecdsa_attack"]["metrics"]["detection"]["detection_rate"]["rate"] == 1.0
    assert g["ecdsa_defense"]["metrics"]["guard"]["vulnerable_signatures_accepted"] == 0
    assert g["ecdsa_defense"]["metrics"]["baseline"]["vulnerable_signatures_accepted"] >= 0
    assert g["rsa_defense"]["metrics"]["defended"]["vulnerable_final_keys"] == 0
    assert g["rsa_batch_gcd"]["metrics"]["modulus_level"]["detection_rate"]["rate"] == 1.0
    assert g["rsa_batch_gcd"]["metrics"]["modulus_level"]["false_positive_rate"]["rate"] == 0.0
    assert g["adaptive_policy"]["metrics"]["selections_below_required_security"] == 0
    assert g["entropy_samples"]["metrics"]["nonce_reuse"]["repeated_block_flag_rate"]["rate"] == 1.0
    grid = g["threshold_sensitivity"]["metrics"]["grid"]
    assert len(grid) == 20 and all(0 <= x["detection_rate"] <= 1 and 0 <= x["false_rejection_rate"] <= 1 for x in grid)
    # lower threshold can only increase detection
    d = {x["threshold"]: x["detection_rate"] for x in grid if x["profile"] == "default"}
    assert d[25] >= d[50] >= d[80]
    # exports through the API
    r = client.get(f"/api/experiments/{eid}/export?format=csv")
    rows = list(csv.DictReader(io.StringIO(r.data.decode())))
    assert r.status_code == 200 and rows and "group" in rows[0] and {x["group"] for x in rows} >= {"ecdsa_attack", "rsa_defense"}
    j = client.get(f"/api/experiments/{eid}/export?format=json")
    assert j.status_code == 200 and json.loads(j.data)["experiment_id"] == eid
    assert client.get(f"/api/experiments/{eid}/export?format=xml").status_code == 400
    assert client.get("/api/experiments/exp-missing/export").status_code == 404
    assert any(x["id"] == eid for x in client.get("/api/experiments").get_json()["data"]["experiments"])


def test_synthetic_experiment_reproducible_with_seed():
    p = {"trials": 3, "groups": ["entropy_samples", "threshold_sensitivity"], "seed": 99}
    rows = []
    for _ in range(2):
        pp = X.validate_params(p)
        out = []
        X.g_entropy(pp, 3, lambda: None)
        r, _ = X.g_entropy(pp, 3, lambda: None)
        t, _ = X.g_threshold(pp, 3, lambda: None)
        rows.append((r, t))
    assert rows[0] == rows[1]


def test_async_run_status_and_single_job(client):
    c, b = post(client, "/api/experiments/run", {"trials": 2, "groups": ["entropy_samples", "ecdsa_attack"]})
    assert c == 202
    eid = b["data"]["experiment_id"]
    import time
    for _ in range(100):
        s = client.get(f"/api/experiments/status/{eid}").get_json()["data"]
        if s["status"] != "running":
            break
        time.sleep(0.1)
    assert s["status"] == "completed" and s["progress"] == 1.0


def test_rsa_defended_endpoints_actually_accept_keys(client):
    """Regression: a vacuous '0 vulnerable keys' must not come from rejecting everything."""
    _, d = post(client, "/api/rsa/defended", {"n_keys": 6, "fault_probability": 0.4})
    df = d["data"]["defended"]
    assert df["accepted_rsa_keys"] > 0 and df["fallbacks"] == 0 and df["vulnerable_final"] == 0
    assert d["data"]["baseline"]["accepted_rsa_keys"] == 6
    _, d = post(client, "/api/safety/defense-demo", {"target": "rsa", "n": 6, "fault_probability": 0.4})
    dd = d["data"]["arms"]["defended"]
    assert dd["accepted_rsa_keys"] > 0 and dd["fallbacks"] == 0 and dd["vulnerable_final"] == 0


def test_rsa_scenario_regenerates_then_decides_and_healthy_accepts(client):
    _, sc = post(client, "/api/safety/scenario", {"target": "rsa_keygen", "condition": "faulty", "max_regen": 2, "requirements": {"allow_fallback": False}})
    op = sc["data"]["operations"][0]
    assert [t["decision"] for t in op["trace"]] == ["REGENERATE", "REGENERATE", "REJECT"] and sc["data"]["requirement_note"]
    names = [f["name"] for f in op["risk"]["factors"] if f["kind"] == "hard_fail"]
    assert names == ["rsa_shared_prime"]               # no spurious invalid_parameters / security-level failures
    _, sc = post(client, "/api/safety/scenario", {"target": "rsa_keygen", "condition": "healthy"})
    op = sc["data"]["operations"][0]
    assert op["decision"] == "ACCEPT" and op["status"] == "accepted"
