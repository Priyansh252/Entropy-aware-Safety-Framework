"""Policy-based selection of a vetted cryptographic configuration.

The selector only ever *filters* the catalogue by hard requirements (operation capability,
security level, compatibility tags, allowed algorithms) and then *ranks* what is left by the
performance preference. It never relaxes the required security level to improve performance or
to lower a risk score. security_bits values are approximate NIST SP 800-57 style equivalences.
"""

CATALOG = [
    {"id": "ecdsa_p256_det", "algorithm": "ECDSA", "detail": "P-256, SHA-256, RFC 6979 deterministic", "operations": ["signature"], "security_bits": 128, "perf_rank": 2, "tags": ["fips", "widely_supported", "deterministic_nonce"], "nonce_policy": "deterministic_rfc6979"},
    {"id": "ecdsa_p384_det", "algorithm": "ECDSA", "detail": "P-384, SHA-384, RFC 6979 deterministic", "operations": ["signature"], "security_bits": 192, "perf_rank": 3, "tags": ["fips", "widely_supported", "deterministic_nonce"], "nonce_policy": "deterministic_rfc6979"},
    {"id": "ed25519", "algorithm": "Ed25519", "detail": "EdDSA (deterministic by design)", "operations": ["signature"], "security_bits": 128, "perf_rank": 1, "tags": ["deterministic_nonce", "modern"], "nonce_policy": "deterministic_rfc6979"},
    {"id": "rsa_2048_pss", "algorithm": "RSA", "detail": "RSA-2048, PSS, SHA-256", "operations": ["signature"], "security_bits": 112, "perf_rank": 4, "tags": ["fips", "widely_supported", "legacy_rsa"], "nonce_policy": "library_keygen"},
    {"id": "rsa_3072_pss", "algorithm": "RSA", "detail": "RSA-3072, PSS, SHA-256", "operations": ["signature"], "security_bits": 128, "perf_rank": 5, "tags": ["fips", "widely_supported", "legacy_rsa"], "nonce_policy": "library_keygen"},
    {"id": "rsa_4096_pss", "algorithm": "RSA", "detail": "RSA-4096, PSS, SHA-384", "operations": ["signature"], "security_bits": 140, "perf_rank": 6, "tags": ["fips", "widely_supported", "legacy_rsa"], "nonce_policy": "library_keygen"},
    {"id": "rsa_2048_oaep", "algorithm": "RSA", "detail": "RSA-2048, OAEP", "operations": ["encryption"], "security_bits": 112, "perf_rank": 4, "tags": ["fips", "widely_supported", "legacy_rsa"], "nonce_policy": "library_keygen"},
    {"id": "rsa_3072_oaep", "algorithm": "RSA", "detail": "RSA-3072, OAEP", "operations": ["encryption"], "security_bits": 128, "perf_rank": 5, "tags": ["fips", "widely_supported", "legacy_rsa"], "nonce_policy": "library_keygen"},
    {"id": "ecdh_p256", "algorithm": "ECDH", "detail": "P-256 key agreement", "operations": ["key_agreement"], "security_bits": 128, "perf_rank": 2, "tags": ["fips", "widely_supported"], "nonce_policy": "library_keygen"},
    {"id": "ecdh_p384", "algorithm": "ECDH", "detail": "P-384 key agreement", "operations": ["key_agreement"], "security_bits": 192, "perf_rank": 3, "tags": ["fips", "widely_supported"], "nonce_policy": "library_keygen"},
    {"id": "x25519", "algorithm": "X25519", "detail": "Curve25519 key agreement", "operations": ["key_agreement"], "security_bits": 128, "perf_rank": 1, "tags": ["modern"], "nonce_policy": "library_keygen"},
]

OPERATIONS = ["signature", "encryption", "key_agreement"]
PERF = ["speed", "balanced", "security"]
KNOWN_TAGS = ["fips", "widely_supported", "legacy_rsa", "modern", "deterministic_nonce"]


def select(req: dict) -> dict:
    op = req.get("operation")
    if op not in OPERATIONS:
        raise ValueError(f"operation must be one of {OPERATIONS}")
    required = int(req.get("required_security_bits", 128))
    if not 80 <= required <= 256:
        raise ValueError("required_security_bits must be in 80..256")
    perf = req.get("performance_priority", "balanced")
    if perf not in PERF:
        raise ValueError(f"performance_priority must be one of {PERF}")
    compat = list(req.get("compatibility", []))
    allowed = req.get("supported_algorithms")
    excluded = set(req.get("excluded_algorithms", []))

    considered, eligible = [], []
    for c in CATALOG:
        reasons = []
        if op not in c["operations"]:
            reasons.append(f"{c['algorithm']} cannot perform '{op}'")
        if c["security_bits"] < required:
            reasons.append(f"~{c['security_bits']}-bit security is below required {required}")
        for t in compat:
            if t not in c["tags"]:
                reasons.append(f"lacks required compatibility tag '{t}'")
        if allowed and c["algorithm"] not in allowed:
            reasons.append("algorithm not in the supported list")
        if c["algorithm"] in excluded:
            reasons.append("algorithm excluded by caller")
        considered.append({"id": c["id"], "algorithm": c["algorithm"], "detail": c["detail"],
                           "security_bits": c["security_bits"], "eligible": not reasons, "rejected_because": reasons})
        if not reasons:
            eligible.append(c)

    def key(c):
        det_ecdsa_first = 0 if (op == "signature" and c["algorithm"] == "ECDSA") else 1
        if perf == "speed":
            metric = (c["perf_rank"], -c["security_bits"])
        elif perf == "security":
            metric = (-c["security_bits"], c["perf_rank"])
        else:
            metric = (c["security_bits"] - required, c["perf_rank"])
        return (det_ecdsa_first, metric)

    eligible.sort(key=key)
    chosen = eligible[0] if eligible else None
    if chosen:
        notes = [f"Selected {chosen['id']} ({chosen['detail']}), ~{chosen['security_bits']}-bit >= required {required}."]
        if chosen["algorithm"] == "ECDSA":
            notes.append("Deterministic ECDSA removes dependence on fresh signing-time randomness; it does not make weak key generation safe.")
        if any(c["algorithm"] == "ECDSA" for c in CATALOG) and op == "signature" and chosen["algorithm"] != "ECDSA":
            notes.append("Deterministic ECDSA was not eligible under the stated constraints.")
        assert chosen["security_bits"] >= required  # invariant: never weaker than required
    else:
        notes = ["No vetted configuration satisfies all constraints. The selector will not weaken the requirement; relax constraints explicitly or reject the operation."]
    return {"selected": chosen, "alternatives": [c["id"] for c in eligible[1:]],
            "considered": considered, "notes": notes, "request": {
                "operation": op, "required_security_bits": required, "performance_priority": perf,
                "compatibility": compat, "supported_algorithms": allowed, "excluded_algorithms": sorted(excluded)}}


def fallback_for(req: dict, failed_algorithm: str):
    """A vetted alternative that still satisfies the requirements, excluding the failed algorithm."""
    if req.get("allow_fallback", True) is False:
        return None
    r = dict(req)
    r["excluded_algorithms"] = list(req.get("excluded_algorithms", [])) + [failed_algorithm]
    return select(r)["selected"]
