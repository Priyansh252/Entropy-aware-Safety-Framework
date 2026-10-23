"""SQLite persistence: audit log, experiments, attack-demo runs.

Secrets are never stored: every payload passes through `scrub()` which drops any key that looks
like secret material (private values, nonces, primes, seeds of secret generators)."""
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from backend import config

_lock = threading.Lock()
_SECRET_KEYS = {"d", "k", "p", "q", "dp", "dq", "qinv", "nonce", "private_key", "private_value",
                "prime", "prime_p", "prime_q", "secret", "d_value", "k_value"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id TEXT, ts TEXT, operation TEXT, candidate_id TEXT,
  algorithm TEXT, configuration TEXT, risk_score REAL, risk_category TEXT, factors TEXT, decision TEXT,
  regen_count INTEGER, validation_outcome TEXT, vulnerability_detected INTEGER, exec_ms REAL,
  mode TEXT, evidence TEXT);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE TABLE IF NOT EXISTS experiments (
  id TEXT PRIMARY KEY, created TEXT, status TEXT, groups TEXT, params TEXT, summary TEXT,
  csv_path TEXT, json_path TEXT, duration_s REAL, error TEXT);
CREATE TABLE IF NOT EXISTS attack_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, kind TEXT, success INTEGER, details TEXT);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def scrub(obj):
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items()
                if str(k).lower() not in _SECRET_KEYS and "secret" not in str(k).lower()
                and "private" not in str(k).lower()}
    if isinstance(obj, (list, tuple)):
        return [scrub(x) for x in obj]
    if isinstance(obj, (bytes, bytearray)):
        return "<bytes omitted>"
    return obj


def _conn():
    c = sqlite3.connect(config.db_path(), timeout=30)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _lock, _conn() as c:
        c.executescript(SCHEMA)


def _rows(cur):
    return [dict(r) for r in cur.fetchall()]


def audit_record_from_risk(risk: dict, *, operation, algorithm, configuration, candidate_id,
                           exec_ms, mode, validation_outcome="n/a", extra=None) -> dict:
    return {
        "assessment_id": risk["assessment_id"], "ts": now(), "operation": operation,
        "candidate_id": candidate_id, "algorithm": algorithm, "configuration": configuration,
        "risk_score": risk["risk_score"], "risk_category": risk["risk_category"],
        "factors": [{"name": f["name"], "kind": f["kind"], "points": f["points"]} for f in risk["factors"]],
        "decision": risk["decision"], "regen_count": risk["regen_count"],
        "validation_outcome": validation_outcome, "vulnerability_detected": int(risk["hard_fail"]),
        "exec_ms": exec_ms, "mode": mode, "evidence": scrub({**risk.get("validation_evidence", {}), **(extra or {})}),
    }


def insert_audit_many(records):
    if not records:
        return
    rows = [(r["assessment_id"], r["ts"], r["operation"], r["candidate_id"], r["algorithm"],
             r["configuration"], r["risk_score"], r["risk_category"], json.dumps(scrub(r["factors"])),
             r["decision"], r["regen_count"], r["validation_outcome"], r["vulnerability_detected"],
             r["exec_ms"], r["mode"], json.dumps(scrub(r["evidence"]))) for r in records]
    with _lock, _conn() as c:
        c.executemany("""INSERT INTO audit_log (assessment_id, ts, operation, candidate_id, algorithm,
            configuration, risk_score, risk_category, factors, decision, regen_count, validation_outcome,
            vulnerability_detected, exec_ms, mode, evidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)


class AuditBuffer:
    """Collects audit records and writes them in one transaction (keeps experiments fast)."""
    def __init__(self):
        self.records = []

    def __call__(self, rec):
        self.records.append(rec)

    def flush(self):
        insert_audit_many(self.records)
        n = len(self.records)
        self.records = []
        return n


def query_audit(search="", decision="", operation="", category="", mode="", sort="ts", order="desc",
                limit=100, offset=0):
    cols = {"ts", "operation", "algorithm", "risk_score", "decision", "exec_ms", "risk_category", "mode"}
    sort = sort if sort in cols else "ts"
    order = "ASC" if str(order).lower() == "asc" else "DESC"
    where, args = [], []
    if search:
        where.append("(operation LIKE ? OR algorithm LIKE ? OR configuration LIKE ? OR candidate_id LIKE ? OR assessment_id LIKE ?)")
        args += [f"%{search}%"] * 5
    for col, val in (("decision", decision), ("operation", operation), ("risk_category", category), ("mode", mode)):
        if val:
            where.append(f"{col} = ?")
            args.append(val)
    w = ("WHERE " + " AND ".join(where)) if where else ""
    with _lock, _conn() as c:
        total = c.execute(f"SELECT COUNT(*) FROM audit_log {w}", args).fetchone()[0]
        rows = _rows(c.execute(f"SELECT * FROM audit_log {w} ORDER BY {sort} {order} LIMIT ? OFFSET ?",
                               args + [int(limit), int(offset)]))
    for r in rows:
        r["factors"] = json.loads(r["factors"] or "[]")
        r["evidence"] = json.loads(r["evidence"] or "{}")
    return {"total": total, "rows": rows}


def insert_attack_run(kind: str, success: bool, details: dict):
    with _lock, _conn() as c:
        c.execute("INSERT INTO attack_runs (ts, kind, success, details) VALUES (?,?,?,?)",
                  (now(), kind, int(success), json.dumps(scrub(details))))


def insert_experiment(exp_id, groups, params, status="running"):
    with _lock, _conn() as c:
        c.execute("INSERT INTO experiments (id, created, status, groups, params) VALUES (?,?,?,?,?)",
                  (exp_id, now(), status, json.dumps(groups), json.dumps(params)))


def update_experiment(exp_id, **fields):
    allowed = {"status", "summary", "csv_path", "json_path", "duration_s", "error"}
    sets, args = [], []
    for k, v in fields.items():
        if k not in allowed:
            raise ValueError(k)
        sets.append(f"{k} = ?")
        args.append(json.dumps(v) if k == "summary" else v)
    with _lock, _conn() as c:
        c.execute(f"UPDATE experiments SET {', '.join(sets)} WHERE id = ?", args + [exp_id])


def _exp_row(r, with_summary=True):
    r["groups"] = json.loads(r["groups"] or "[]")
    r["params"] = json.loads(r["params"] or "{}")
    r["summary"] = json.loads(r["summary"]) if (with_summary and r.get("summary")) else None
    return r


def get_experiment(exp_id):
    with _lock, _conn() as c:
        rows = _rows(c.execute("SELECT * FROM experiments WHERE id = ?", (exp_id,)))
    return _exp_row(rows[0]) if rows else None


def list_experiments(limit=50, with_summary=False):
    with _lock, _conn() as c:
        rows = _rows(c.execute("SELECT * FROM experiments ORDER BY created DESC LIMIT ?", (limit,)))
    return [_exp_row(r, with_summary) for r in rows]


def latest_completed_with_group(group):
    for e in list_experiments(50, True):
        if e["status"] == "completed" and e["summary"] and group in (e["summary"].get("groups") or {}):
            return e
    return None


def dashboard_stats():
    with _lock, _conn() as c:
        total = c.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        vuln = c.execute("SELECT COUNT(*) FROM audit_log WHERE vulnerability_detected=1").fetchone()[0]
        rejected = c.execute("SELECT COUNT(*) FROM audit_log WHERE decision != 'ACCEPT'").fetchone()[0]
        risk_dist = {r[0]: r[1] for r in c.execute("SELECT risk_category, COUNT(*) FROM audit_log GROUP BY risk_category")}
        dec_dist = {r[0]: r[1] for r in c.execute("SELECT decision, COUNT(*) FROM audit_log GROUP BY decision")}
        attacks_ok = c.execute("SELECT COUNT(*) FROM attack_runs WHERE success=1").fetchone()[0]
        attacks_all = c.execute("SELECT COUNT(*) FROM attack_runs").fetchone()[0]
        running = c.execute("SELECT COUNT(*) FROM experiments WHERE status='running'").fetchone()[0]
        done = c.execute("SELECT COUNT(*) FROM experiments WHERE status='completed'").fetchone()[0]
        a = [dict(ts=r[0], kind="audit", title=f"{r[1]} → {r[2]}", detail=f"risk {r[3]}") for r in
             c.execute("SELECT ts, operation, decision, risk_score FROM audit_log ORDER BY id DESC LIMIT 8")]
        b = [dict(ts=r[0], kind="attack", title=f"{r[1]} demonstration", detail="succeeded" if r[2] else "did not succeed") for r in
             c.execute("SELECT ts, kind, success FROM attack_runs ORDER BY id DESC LIMIT 8")]
        d = [dict(ts=r[0], kind="experiment", title=f"Experiment {r[1]}", detail=r[2]) for r in
             c.execute("SELECT created, id, status FROM experiments ORDER BY created DESC LIMIT 8")]
    recent = sorted(a + b + d, key=lambda x: x["ts"], reverse=True)[:10]
    return {"total_assessments": total, "vulnerable_detected": vuln, "candidates_rejected": rejected,
            "attacks_succeeded": attacks_ok, "attack_runs": attacks_all, "experiments_running": running,
            "experiments_completed": done, "risk_distribution": risk_dist, "decision_distribution": dec_dist,
            "recent_activity": recent}
