# Methodology

## Threat model
The attacker sees public keys, signatures and moduli, never secrets. The randomness source may be faulty (repeating or stuck). Out of scope: side channels, compromised hosts, and faults no check can observe.

## ECDSA nonce reuse
Signature: r = x(kG) mod n, s = k^-1 (z + r d) mod n, z = SHA-256(m) (256 bits, equal to the P-256 order size, so no truncation). Two messages with the same k:
s1 - s2 = k^-1 (z1 - z2)  =>  k = (z1 - z2)(s1 - s2)^-1  =>  d = (s1 k - z1) r^-1  (mod n).
A signer that normalises to low-s emits n - s, equivalent to -k; the implementation tries s2 and n - s2 and accepts a candidate only if d*G equals the public key. Messages must hash differently and r1 = r2. The recovered key is demonstrated to be functional by forging a signature that the original public key verifies.
Detection is by signature analysis (equal r under one key), independent of entropy measurement.

## RSA shared prime
n1 = p q1, n2 = p q2 => gcd(n1, n2) = p. Batch GCD (Bernstein): with P = prod n_i, g_i = gcd(n_i, (P mod n_i^2)/n_i) via a product tree and remainder tree. When a modulus shares both primes with different keys (g_i = n_i) one pairwise pass resolves a proper factor; identical moduli are reported as duplicates. A recovered factor is verified by rebuilding the private key (d = e^-1 mod lcm(p-1, q-1)), signing (RSA-PSS) and verifying with an independently constructed public key.

## Entropy assessment
Plug-in Shannon entropy per byte (also /8 and relative to the expected entropy of an ideal uniform sample of the same size, estimated by Monte Carlo/Miller-Madow), min-entropy, byte-frequency histogram, chi-square, longest run, repeated 32-byte blocks. It is an indicator for one finite sample, not a measurement of source entropy and not a security proof.

## Generation-time defense
* ECDSA guard: nonce candidate -> r = x(kG) -> compare with r values already signed by this signer -> risk engine -> ACCEPT (sign), REGENERATE (discard and redraw, bounded), SAFE_FALLBACK (deterministic RFC 6979 signing, only if requirements allow) or REJECT. Rejected nonces never reach the signing function (asserted in tests by instrumenting it).
* RSA guard: modulus size, distinct probable primes (Miller-Rabin), exponent coprimality, prime gap, duplicate modulus, gcd against accepted moduli -> same decision engine. Fallback to a non-RSA algorithm only if compatibility constraints permit.
* Batch GCD is a population audit; per-candidate validation is only as good as the known-moduli registry.

## Experimental protocol
Groups: entropy samples; ECDSA normal vs reused; ECDSA baseline vs guard vs deterministic; RSA batch-GCD accuracy; RSA baseline vs defended; threshold/weight sensitivity; overhead; adaptive policy. Each group runs N trials (capped per group; effective N is reported). Baseline and defended arms use the same seed and fault model. Seeds control synthetic choices only; keys, secure nonces and primes come from the OS. Outputs: raw CSV, summary JSON, SQLite metadata.

## Metrics (definitions)
* Attack success rate: fraction of sessions/populations in which an attacker holding all public outputs recovers a private key.
* Detection rate = TP/(TP+FN), positives = truly vulnerable. False-positive rate = FP/(FP+TN). False-rejection rate = safe candidates rejected / safe candidates.
* Vulnerable final-key rate: accepted keys sharing a prime with another accepted key / accepted keys (ground truth from the generator).
* Proportions: 95% Wilson interval. Times: mean, median, p95, normal-approximation 95% CI.
* Overhead % = (defended mean - baseline mean) / baseline mean. In `rsa_defense` the baseline excludes prime generation, so use the `overhead` group for overhead relative to real key generation.
