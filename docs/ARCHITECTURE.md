# Architecture

```
React/Vite dashboard  --REST/JSON-->  Flask API (routes/api.py)
                                         |-- core/entropy.py          entropy assessment, synthetic samples
                                         |-- core/ecdsa_lab.py        ECDSA lab: chosen-nonce signer, detection, recovery, sessions
                                         |-- core/rsa_lab.py          RSA lab: batch GCD, recovery, candidate validation
                                         |-- core/risk_engine.py      deterministic scoring + decision engine
                                         |-- core/adaptive_selector.py policy-based configuration selection
                                         |-- core/safety_layer.py     ECDSAGuard / RSAGuard + workflow runners
                                         |-- core/experiments.py      reproducible experiment runner
                                         |-- core/metrics.py          Wilson CIs, summaries, confusion metrics
                                         '-- storage/db.py            SQLite: audit_log, experiments, attack_runs
```

Pipeline: randomness source -> entropy assessment -> candidate generation -> safety validation -> risk and decision engine -> ACCEPT / REGENERATE / SAFE_FALLBACK / REJECT -> cryptographic operation -> audit log and experiment logging.

Design rules
* UI, API, cryptographic operations, decision logic and experiments are separate modules.
* Vetted `cryptography` library for key generation, kG, verification, deterministic (RFC 6979) and random-nonce signing, RSA key construction/verification. The only hand-written crypto arithmetic is the educational chosen-nonce signer `s = k^-1 (z + r d) mod n` (a library cannot be told which nonce to use), and every signature it produces is verified by OpenSSL.
* Vulnerable material only exists in `educational_*` code paths and simulated fault sources, reached only from labelled endpoints and experiments.
* Fail safe: any internal error in scoring or validation yields REJECT.
* Secrets (private keys, nonces, primes) never leave the lab session memory; the API returns truncated/fingerprinted views, and `storage.db.scrub()` strips secret-looking keys before anything is persisted.

## REST API (all JSON: `{"ok":true,"data":...}` / `{"ok":false,"error":{"code","message"}}`)
| Method & path | Purpose |
|---|---|
| GET /api/health, /api/dashboard | status; metrics derived from the database |
| POST /api/entropy/assess, /compare | entropy of a synthetic or pasted sample; multi-sample comparison |
| POST /api/ecdsa/session, sign, reuse, detect, recover, defended, verify; GET /ecdsa/session/<id> | ECDSA lab |
| POST /api/rsa/collection, scan, recover, defended | RSA lab |
| GET /api/safety/config; POST /safety/select, evaluate, scenario, defense-demo | risk model, adaptive selection, risk evaluation, guarded generation, with/without-defense demo |
| GET /api/experiments/options; POST /experiments/run; GET /experiments/status/<id>, /experiments, /experiments/<id>, /experiments/<id>/export?format=csv\|json | experiments |
| GET /api/audit?search&decision&operation&category&mode&sort&order&limit&offset | audit log |

Limits (config.py): sample size 16..1,048,576 bytes; RSA collections 3..30 keys at 1024/2048 bits; experiment trials 1..500 (per-group caps); 256 KB request bodies; one experiment at a time (HTTP 409 otherwise).

## Directory tree
See `docs/PROJECT_TREE.txt`.
