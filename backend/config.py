"""Central configuration: paths, request limits and the default risk-model parameters.

All risk weights/thresholds live here (and can be overridden per request) so that they are
visible, documented and tunable. They are an *initial, transparent baseline*, not experimentally
proven optima; see docs/RISK_MODEL.md and the threshold-sensitivity experiment.
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    d = Path(os.environ.get("EAF_DATA_DIR", ROOT / "data"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def db_path() -> str:
    return os.environ.get("EAF_DB_PATH", str(data_dir() / "entropy_framework.db"))


def export_dir() -> Path:
    d = data_dir() / "experiments"
    d.mkdir(parents=True, exist_ok=True)
    return d


LIMITS = {
    "entropy_sample_size": (16, 1_048_576),
    "rsa_collection_keys": (3, 30),
    "rsa_key_bits": (1024, 2048),
    "experiment_trials": (1, 500),
    "defense_signatures": (4, 100),
    "max_regeneration": (0, 10),
    "message_length": (1, 500),
}

# ECDSA test curve: NIST P-256
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

DEFAULT_RISK_CONFIG = {
    # Soft-factor weights; they sum to 100 so the soft score is directly a 0-100 value.
    "weights": {
        "entropy_quality": 20,
        "randomness_source": 25,
        "generation_policy": 25,
        "validation_coverage": 15,
        "security_margin": 15,
    },
    # Category boundaries (score < bound -> category).
    "category_bounds": {"low": 25, "moderate": 50, "high": 75},
    # Score at/above which a candidate is not accepted on score alone.
    "accept_below": 50,
    # A confirmed critical condition forces the score to at least this value (=> Critical).
    "hard_fail_floor": 90,
    # Entropy sub-score ramp on (observed entropy / expected entropy of an ideal uniform sample
    # of the same size): <= bad -> full penalty, >= ok -> none.
    "entropy_ratio_ok": 0.97,
    "entropy_ratio_bad": 0.75,
    "unassessed_entropy_subscore": 0.5,
    # Priors (0 = best, 1 = worst). These are policy judgements, not measurements.
    "source_prior": {
        "os_csprng": 0.0,
        "hardware_rng_unverified": 0.3,
        "unknown": 0.6,
        "seeded_prng_test": 0.9,
        "known_weak": 1.0,
    },
    "policy_prior": {
        "deterministic_rfc6979": 0.0,
        "library_keygen": 0.0,
        "os_csprng_random": 0.1,
        "external_nonce_source": 0.5,
        "custom_or_unknown": 0.7,
        "fixed_or_user_supplied": 1.0,
    },
}
