"""RSA shared-prime laboratory: key construction (test keys only), batch GCD, factor recovery and
per-candidate validation.

Primes always come from the vetted library's key generator. A "vulnerable" modulus is built by
multiplying a prime taken from one library-generated key with a prime from another, i.e. exactly
the structure produced in the wild by low-entropy key generation. Only locally generated test
keys are ever analysed; nothing here scans third-party keys.
"""
import hashlib
import math
import random
import secrets
import threading

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

E = 65537
_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


# ------------------------------------------------------------------ primality (validation only)
def is_probable_prime(n: int, rounds: int = 12) -> bool:
    """Miller-Rabin. Used to *validate* candidate primes, never to generate keys."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


# ------------------------------------------------------------------ prime pool (vetted generator)
class PrimePool:
    """Cache of primes extracted from library-generated RSA keys of a given modulus size."""
    def __init__(self):
        self._primes = {}
        self._lock = threading.Lock()

    def ensure(self, key_bits: int, count: int):
        with self._lock:
            lst = self._primes.setdefault(key_bits, [])
            while len(lst) < count:
                nums = rsa.generate_private_key(E, key_bits).private_numbers()
                lst.extend([nums.p, nums.q])
            return list(lst)

    def sample(self, key_bits: int, count: int, rng: random.Random):
        pool = self.ensure(key_bits, max(count, 2 * 40))
        return rng.sample(pool, count)


POOL = PrimePool()


def fresh_prime_pair(key_bits: int):
    nums = rsa.generate_private_key(E, key_bits).private_numbers()
    return nums.p, nums.q


# ------------------------------------------------------------------ batch GCD
def _product_tree(xs):
    tree = [list(xs)]
    while len(tree[-1]) > 1:
        lvl = tree[-1]
        tree.append([lvl[i] * lvl[i + 1] if i + 1 < len(lvl) else lvl[i] for i in range(0, len(lvl), 2)])
    return tree


def batch_gcd(moduli):
    """Bernstein's product/remainder-tree batch GCD.
    Returns g_i = gcd(n_i, prod_{j != i} n_j) for each modulus (up to the usual caveat that a
    prime appearing in several moduli of the batch contributes with multiplicity)."""
    ns = list(moduli)
    if len(ns) < 2:
        return [1] * len(ns)
    tree = _product_tree(ns)
    rem = [tree[-1][0]]
    for level in reversed(tree[:-1]):
        rem = [rem[i // 2] % (x * x) for i, x in enumerate(level)]
    return [math.gcd(n, r // n) for n, r in zip(ns, rem)]


def pairwise_gcd_reference(moduli):
    """O(n^2) reference used for cross-checking batch_gcd in tests/experiments."""
    out = []
    for i, a in enumerate(moduli):
        g = 1
        for j, b in enumerate(moduli):
            if i != j:
                g = math.lcm(g, math.gcd(a, b)) if math.gcd(a, b) > 1 else g
        out.append(g)
    return out


def analyze_moduli(moduli):
    """Population-level audit. Returns per-modulus findings:
    status: ok | shared_prime | duplicate_modulus ; factor: a nontrivial prime factor if recoverable."""
    ns = list(moduli)
    gs = batch_gcd(ns)
    dup_count = {}
    for n in ns:
        dup_count[n] = dup_count.get(n, 0) + 1
    findings = []
    for i, (n, g) in enumerate(zip(ns, gs)):
        if dup_count[n] > 1:
            findings.append({"index": i, "status": "duplicate_modulus", "factor": None, "gcd": g})
            continue
        if g == 1:
            findings.append({"index": i, "status": "ok", "factor": None, "gcd": g})
            continue
        factor = g if 1 < g < n else None
        if factor is None:  # both primes appear elsewhere: resolve with one pairwise pass
            for j, m in enumerate(ns):
                if j != i:
                    h = math.gcd(n, m)
                    if 1 < h < n:
                        factor = h
                        break
        findings.append({"index": i, "status": "shared_prime", "factor": factor, "gcd": g})
    return findings


# ------------------------------------------------------------------ key construction / recovery
def build_private_key(n: int, e: int, p: int, q: int):
    if p * q != n:
        raise ValueError("p*q != n")
    d = pow(e, -1, math.lcm(p - 1, q - 1))
    nums = rsa.RSAPrivateNumbers(p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q),
                                 rsa.rsa_crt_iqmp(p, q), rsa.RSAPublicNumbers(e, n))
    return nums.private_key()


def verify_recovered_factor(n: int, e: int, p: int):
    """Rebuild the private key from public (n,e) and a recovered factor, then prove it works by
    signing and verifying with an *independently constructed* public key."""
    if not (1 < p < n) or n % p != 0:
        return {"verified": False, "reason": "not a factor of n"}
    q = n // p
    if not (is_probable_prime(p) and is_probable_prime(q)):
        return {"verified": False, "reason": "recovered factors are not both prime"}
    try:
        priv = build_private_key(n, e, p, q)
        msg = b"recovered-key-verification"
        pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
        sig = priv.sign(msg, pss, hashes.SHA256())
        rsa.RSAPublicNumbers(e, n).public_key().verify(sig, msg, pss, hashes.SHA256())
        return {"verified": True, "p_bits": p.bit_length(), "q_bits": q.bit_length(),
                "p_fingerprint": hashlib.sha256(p.to_bytes((p.bit_length() + 7) // 8, "big")).hexdigest()[:16]}
    except Exception as exc:  # noqa: BLE001 - report, never accept
        return {"verified": False, "reason": f"key reconstruction failed: {type(exc).__name__}"}


# ------------------------------------------------------------------ collections (test data)
def make_collection(n_keys: int, shared_pairs: int, key_bits: int = 1024, seed=None):
    """Create n_keys test moduli. `shared_pairs` of them are built to share a prime with another key
    (one 'victim' key per pair re-uses a prime of an earlier key). Ground truth is recorded.
    The seed only shuffles which pool primes are used (non-security-critical)."""
    if shared_pairs * 2 > n_keys:
        raise ValueError("shared_pairs too large for collection size")
    rng = random.Random(seed)
    need = 2 * n_keys
    primes = POOL.sample(key_bits, need, rng)
    keys = []
    it = iter(primes)
    for i in range(n_keys):
        keys.append({"index": i, "p": next(it), "q": next(it), "shares_with": []})
    for j in range(shared_pairs):
        a, b = keys[2 * j], keys[2 * j + 1]          # b re-uses a's p (replacing b.p)
        b["p"] = a["p"]
        a["shares_with"].append(b["index"])
        b["shares_with"].append(a["index"])
    for k in keys:
        k["n"], k["e"] = k["p"] * k["q"], E
        k["vulnerable"] = bool(k["shares_with"])
    order = list(range(n_keys))
    rng.shuffle(order)               # hide structure from naive index-based inspection
    remap = {old: new for new, old in enumerate(order)}
    shuffled = [None] * n_keys
    for old, k in enumerate(keys):
        k["shares_with"] = [remap[x] for x in k["shares_with"]]
        k["index"] = remap[old]
        shuffled[remap[old]] = k
    return shuffled


# ------------------------------------------------------------------ candidate validation (defence)
def validate_candidate(p: int, q: int, e: int, key_bits: int, registry_moduli):
    """Operation-specific RSA checks performed before a key may be used.
    The shared-factor check is only as good as `registry_moduli` (known public moduli)."""
    n = p * q
    checks = {}
    checks["modulus_size"] = n.bit_length() == key_bits
    checks["primes_distinct"] = p != q
    checks["primes_probable_prime"] = is_probable_prime(p) and is_probable_prime(q)
    checks["exponent_valid"] = e > 2 and e % 2 == 1 and math.gcd(e, p - 1) == 1 and math.gcd(e, q - 1) == 1
    checks["prime_gap_sufficient"] = abs(p - q) > (1 << max(1, key_bits // 2 - 100))
    dup = any(n == m for m in registry_moduli)
    shared = (not dup) and any(1 < math.gcd(n, m) < n for m in registry_moduli)
    checks["no_duplicate_modulus"] = not dup
    checks["no_shared_prime_with_registry"] = not shared
    performed = list(checks)
    failed = [k for k, v in checks.items() if not v]
    return {"checks": checks, "performed": performed, "failed": failed,
            "shared_prime": shared, "duplicate_modulus": dup}


class RSACandidateSource:
    """SIMULATED prime source for experiments (primes drawn from vetted-generator pool).
    healthy: two fresh primes per candidate.
    intermittent_reuse: with probability p the candidate re-uses a prime issued earlier (models a
        low-entropy boot-time generator that restarts with the same pool state).
    stuck: always re-uses an earlier prime once one exists."""
    MODES = ("healthy", "intermittent_reuse", "stuck")

    def __init__(self, mode, p_reuse, key_bits, rng, max_candidates=60, reuse_pool=None):
        mode = {"intermittent_repeat": "intermittent_reuse"}.get(mode, mode)   # shared UI vocabulary
        if mode not in self.MODES:
            raise ValueError("unknown prime source mode")
        self.mode, self.p, self.key_bits, self.rng = mode, p_reuse, key_bits, rng
        self._fresh = POOL.sample(key_bits, 2 * max_candidates, rng)
        self.issued_primes = []
        self.reuse_pool = reuse_pool      # optional: restrict re-used primes to this list (demo scenarios)
        self.count = 0
        self.injected = 0

    declared_source = "unknown"

    def _fresh_prime(self):
        if not self._fresh:
            raise RuntimeError("candidate budget exhausted")
        return self._fresh.pop()

    def next(self):
        self.count += 1
        pool = self.reuse_pool if self.reuse_pool is not None else self.issued_primes
        reuse = bool(pool) and (self.mode == "stuck" or
                                (self.mode == "intermittent_reuse" and self.rng.random() < self.p))
        if reuse:
            p = self.rng.choice(pool)
            q = self._fresh_prime()
            self.injected += 1
        else:
            p, q = self._fresh_prime(), self._fresh_prime()
        self.issued_primes.extend([p, q])
        return {"p": p, "q": q, "n": p * q, "e": E, "injected_fault": reuse}
