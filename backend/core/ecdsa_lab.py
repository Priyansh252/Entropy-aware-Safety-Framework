"""ECDSA nonce-reuse laboratory (NIST P-256).

Everything that deliberately uses a repeated nonce is confined to functions whose names start with
`educational_` and is only reachable from explicitly labelled demo endpoints.

Design: key generation, public-key maths (kG), signature *verification* and the safe signing
paths use the vetted `cryptography` library (OpenSSL). Only the educational 'sign with a chosen
nonce' routine does the ECDSA arithmetic itself (s = k^-1 (z + r d) mod n), because no vetted
library lets a caller choose the nonce - which is exactly what the attack requires.
"""
import hashlib
import secrets
import threading
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (decode_dss_signature,
                                                             encode_dss_signature)

from backend.config import P256_ORDER as N

CURVE = ec.SECP256R1()
_HASH = hashes.SHA256()


def inv(a: int) -> int:
    return pow(a % N, -1, N)


def digest_int(message: bytes) -> int:
    """z = SHA-256(m) as an integer. P-256 order has 256 bits, so no truncation occurs."""
    return int.from_bytes(hashlib.sha256(message).digest(), "big")


def new_test_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(CURVE)


def private_value(key) -> int:
    return key.private_numbers().private_value


def public_fingerprint(pub) -> str:
    n = pub.public_numbers()
    return hashlib.sha256(n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")).hexdigest()[:16]


def secret_fingerprint(value: int) -> str:
    """Short hash used to *compare* secrets without displaying them."""
    return hashlib.sha256(value.to_bytes(32, "big")).hexdigest()[:16]


def nonce_to_r(k: int) -> int:
    """r = x(kG) mod n, computed by OpenSSL (public information once a signature exists)."""
    if not (1 <= k < N):
        raise ValueError("nonce out of range")
    return ec.derive_private_key(k, CURVE).public_key().public_numbers().x % N


def random_nonce() -> int:
    return secrets.randbelow(N - 1) + 1


def _sign_with_nonce(key, message: bytes, k: int):
    r = nonce_to_r(k)
    z = digest_int(message)
    s = (inv(k) * (z + r * private_value(key))) % N
    if r == 0 or s == 0:
        raise ValueError("degenerate signature; choose another nonce")
    return r, s


def educational_sign_with_nonce(key, message: bytes, k: int):
    """EDUCATIONAL ATTACK MODE ONLY: sign with a caller-chosen nonce."""
    return _sign_with_nonce(key, message, k)


def guarded_sign_with_nonce(key, message: bytes, k: int):
    """Used by the safety layer *after* a nonce candidate has been accepted."""
    return _sign_with_nonce(key, message, k)


def library_sign(key, message: bytes, deterministic: bool = False):
    """Vetted signing. deterministic=True -> RFC 6979 via the library."""
    algo = ec.ECDSA(_HASH, deterministic_signing=True) if deterministic else ec.ECDSA(_HASH)
    return decode_dss_signature(key.sign(message, algo))


def verify(pub, message: bytes, r: int, s: int) -> bool:
    try:
        pub.verify(encode_dss_signature(r, s), message, ec.ECDSA(_HASH))
        return True
    except (InvalidSignature, ValueError):
        return False


def detect_nonce_reuse(signatures):
    """Signature-based detection: two signatures under one key with equal r share kG, hence
    (barring a negligible 2^-256 coincidence) share the nonce up to sign.
    `signatures`: iterable of dicts {id, key_id, r, s}. Returns list of groups."""
    groups = {}
    for sig in signatures:
        groups.setdefault((sig["key_id"], sig["r"]), []).append(sig["id"])
    return [{"key_id": k, "r_hex": hex(r), "signature_ids": ids}
            for (k, r), ids in groups.items() if len(ids) > 1]


def recover_private_key(pub, m1: bytes, sig1, m2: bytes, sig2):
    """Recover d from two signatures with the same r (same nonce).
        s1 = k^-1 (z1 + r d), s2 = k^-1 (z2 + r d)  =>  k = (z1 - z2)/(s1 - s2),  d = (s1 k - z1)/r  (mod n)
    Some implementations emit s or n-s ('low-s' normalisation), which corresponds to k or -k,
    so both s2 and n-s2 are tried. A candidate is accepted only if d*G equals the public key.
    Returns dict with 'recovered' (bool) and, if successful, the private value 'd' (int)."""
    (r1, s1), (r2, s2) = sig1, sig2
    if r1 != r2:
        return {"recovered": False, "reason": "r values differ: no shared nonce between these signatures"}
    z1, z2 = digest_int(m1), digest_int(m2)
    if z1 == z2:
        return {"recovered": False, "reason": "messages hash to the same value: no information to solve for k"}
    pub_x = pub.public_numbers().x
    for variant, s2v in (("s2", s2), ("n-s2", (N - s2) % N)):
        den = (s1 - s2v) % N
        if den == 0:
            continue
        k = ((z1 - z2) * inv(den)) % N
        d = ((s1 * k - z1) * inv(r1)) % N
        if d and ec.derive_private_key(d, CURVE).public_key().public_numbers().x == pub_x:
            return {"recovered": True, "d": d, "variant": variant}
    return {"recovered": False, "reason": "no candidate matched the public key"}


def recover_from_signature_set(pub, records):
    """Attacker view: records = list of (message, r, s). Try every pair with equal r."""
    by_r = {}
    for m, r, s in records:
        by_r.setdefault(r, []).append((m, s))
    for r, lst in by_r.items():
        for i in range(len(lst)):
            for j in range(i + 1, len(lst)):
                res = recover_private_key(pub, lst[i][0], (r, lst[i][1]), lst[j][0], (r, lst[j][1]))
                if res["recovered"]:
                    return res
    return {"recovered": False, "reason": "no usable repeated-r pair"}


# ------------------------------------------------------------------ nonce sources (simulation)
class FaultyNonceSource:
    """SIMULATED nonce source for experiments.
    healthy: fresh uniform nonce each call (OS CSPRNG).
    intermittent_repeat: with probability p, re-emits the previously issued nonce (models RNG state
        restore / VM snapshot / broken entropy pool). The decision RNG may be seeded for
        reproducibility; nonce values themselves always come from the OS CSPRNG.
    stuck: always returns the same nonce.
    """
    MODES = ("healthy", "intermittent_repeat", "stuck")

    def __init__(self, mode="healthy", p_repeat=0.0, seed=None):
        import random
        if mode not in self.MODES:
            raise ValueError("unknown nonce source mode")
        self.mode, self.p, self.rng = mode, p_repeat, random.Random(seed)
        self.last = None
        self.issued = 0
        self.injected_repeats = 0

    @property
    def declared_source(self):
        return "os_csprng" if self.mode == "healthy" else "unknown"

    def next(self) -> int:
        self.issued += 1
        if self.mode == "healthy" or self.last is None:
            k = random_nonce()
        elif self.mode == "stuck":
            k = self.last
            self.injected_repeats += 1
        elif self.rng.random() < self.p:
            k = self.last
            self.injected_repeats += 1
        else:
            k = random_nonce()
        self.last = k
        return k


# ------------------------------------------------------------------ interactive lab sessions
_SESSIONS = {}
_LOCK = threading.Lock()
MAX_SESSIONS = 50


class Session:
    def __init__(self):
        self.id = uuid.uuid4().hex[:12]
        self.key = new_test_key()
        self.pub = self.key.public_key()
        self.sigs = []          # {id, key_id, message(bytes), r, s, mode, verified}
        self.recovered = None
        self.created = time.time()

    @property
    def key_id(self):
        return public_fingerprint(self.pub)


def create_session() -> Session:
    s = Session()
    with _LOCK:
        if len(_SESSIONS) >= MAX_SESSIONS:
            oldest = min(_SESSIONS.values(), key=lambda x: x.created)
            _SESSIONS.pop(oldest.id, None)
        _SESSIONS[s.id] = s
    return s


def get_session(sid: str) -> Session:
    with _LOCK:
        s = _SESSIONS.get(sid)
    if s is None:
        raise KeyError("unknown or expired lab session")
    return s


def add_signature(sess: Session, message: bytes, r: int, s: int, mode: str) -> dict:
    ok = verify(sess.pub, message, r, s)
    rec = {"id": f"sig-{len(sess.sigs) + 1}", "key_id": sess.key_id, "message": message,
           "r": r, "s": s, "mode": mode, "verified": ok}
    sess.sigs.append(rec)
    return public_sig(rec)


def public_sig(rec: dict) -> dict:
    """Test-environment-safe view: message, r, s, mode, verification. Never the nonce or key."""
    return {"id": rec["id"], "message": rec["message"].decode("utf-8", "replace"),
            "r": hex(rec["r"]), "s": hex(rec["s"]), "mode": rec["mode"], "verified": rec["verified"]}


def session_view(sess: Session) -> dict:
    n = sess.pub.public_numbers()
    return {"session_id": sess.id, "curve": "NIST P-256 (secp256r1)", "key_id": sess.key_id,
            "public_key": {"x": hex(n.x), "y": hex(n.y)},
            "signatures": [public_sig(x) for x in sess.sigs],
            "recovery": sess.recovered}


def do_recover(sess: Session, id1: str = None, id2: str = None) -> dict:
    """Recovery against the lab session's own test key (verified against its public key)."""
    lookup = {x["id"]: x for x in sess.sigs}
    if id1 and id2:
        pairs = [(lookup[id1], lookup[id2])]
    else:
        pairs = [(a, b) for i, a in enumerate(sess.sigs) for b in sess.sigs[i + 1:] if a["r"] == b["r"]]
    for a, b in pairs:
        res = recover_private_key(sess.pub, a["message"], (a["r"], a["s"]), b["message"], (b["r"], b["s"]))
        if res["recovered"]:
            d = res["d"]
            orig = private_value(sess.key)
            sess.recovered = {
                "recovered": True, "variant": res["variant"],
                "pair": [a["id"], b["id"]],
                "recovered_key_preview": f"{d:064x}"[:8] + "…" + f"{d:064x}"[-4:] + " (test key, truncated)",
                "recovered_fingerprint": secret_fingerprint(d),
                "original_fingerprint": secret_fingerprint(orig),
                "matches_original": d == orig,
                "public_key_check": ec.derive_private_key(d, CURVE).public_key().public_numbers()
                == sess.pub.public_numbers(),
            }
            # Prove the recovered key is functional: it forges a valid signature on a new message.
            forged_msg = b"forged-with-recovered-test-key"
            forged_key = ec.derive_private_key(d, CURVE)
            fr, fs = decode_dss_signature(forged_key.sign(forged_msg, ec.ECDSA(_HASH)))
            sess.recovered["forgery_verifies"] = verify(sess.pub, forged_msg, fr, fs)
            return sess.recovered
    sess.recovered = {"recovered": False,
                      "reason": "no pair of signatures with a shared nonce was found" if not (id1 and id2)
                      else "the selected pair does not share a nonce"}
    return sess.recovered
