# Risk-scoring model

score = min(100, sum_i weight_i * subscore_i) over soft factors; weights sum to 100.

| Factor | Weight | Subscore in [0,1] |
|---|---|---|
| entropy_quality | 20 | ramp on (observed / ideal-uniform entropy): 0 at >= 0.97, 1 at <= 0.75; 0.5 if no assessment |
| randomness_source | 25 | prior: os_csprng 0, hardware_rng_unverified 0.3, unknown 0.6, seeded_prng_test 0.9, known_weak 1 |
| generation_policy | 25 | prior: deterministic_rfc6979 / library_keygen 0, os_csprng_random 0.1, external_nonce_source 0.5, custom_or_unknown 0.7, fixed_or_user_supplied 1 |
| validation_coverage | 15 | share of required checks not performed |
| security_margin | 15 | 1 if configuration security < required, else 0 |

Categories: Low < 25, Moderate < 50, High < 75, Critical otherwise. Accept below 50.

Hard-fail rules (force score >= 90, category Critical, never ACCEPT regardless of weights/thresholds): confirmed nonce reuse; RSA shared prime; duplicate modulus; failed parameter checks; known-weak declared source; configuration weaker than required.

Decisions: ACCEPT if no hard-fail and score < accept threshold. If unsafe: REGENERATE when every triggered hard rule is candidate-specific and regeneration budget remains; else SAFE_FALLBACK if available; else REJECT. Soft-only failures describe the source/configuration, so they are not regenerated.

All weights, priors and thresholds are in `backend/config.py` and can be overridden per request. They are an **initial transparent baseline built from policy judgement, not experimentally derived optima**. The threshold-sensitivity experiment reports detection and false rejection for 4 weight profiles x 5 thresholds on *simulated* contexts; in the sample run the score alone separates weak from healthy sources only partially, which is why confirmed failures use hard rules.
