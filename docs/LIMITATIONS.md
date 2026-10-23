# Known limitations and security considerations
* Research prototype: not formally verified, not certified, not for production key management.
* RSA sizes of 1024/2048 bits are educational demonstrations, not recommendations.
* Fault models (repeating nonce source, prime-reuse source) are simulated; results measure this implementation under those models, not real-world prevalence.
* The ECDSA reuse registry covers one signer instance and is in memory; restarts or multiple signers need shared state, or deterministic ECDSA, which removes dependence on signing-time randomness but does not protect a weakly generated private key.
* RSA generation-time shared-prime detection only compares against moduli already known; batch GCD is a population-level audit.
* Entropy estimates are indicators for one finite sample; they do not prove or disprove source security.
* Lab sessions and RSA collections hold test secrets in server memory (bounded count); they are never written to SQLite or returned in full. The API listens on 127.0.0.1 only; there is no authentication because it is a local single-user tool.
* Timing numbers are wall-clock on the host machine, include Python overhead and vary between runs.
* Python's `random` module is used only for seeded synthetic data and fault injection decisions; keys, nonces and primes come from the OS CSPRNG via `cryptography`/`secrets`.
* RSA-1024 is labelled ~80-bit and RSA-2048 ~112-bit (approximate NIST SP 800-57 equivalences). Interactive RSA scenarios cap the required level at the key's own strength so educational keys can be demonstrated; this is shown to the user in the Safety engine page.
