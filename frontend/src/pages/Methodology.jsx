import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { DataTable, Notice, PageHead } from '../components/ui.jsx'

const S = ({ id, title, children }) => <section id={id}><h2>{title}</h2>{children}</section>
const SECTIONS = [['arch', 'Architecture'], ['motive', 'Motivation'], ['threat', 'Threat model'], ['ecdsa', 'ECDSA nonce reuse'], ['rsa', 'RSA shared primes'], ['entropy', 'Entropy limits'], ['risk', 'Risk scoring'], ['defense', 'Generation-time defense'], ['protocol', 'Experimental protocol'], ['limits', 'Metrics and limitations']]

export default function Methodology() {
  const [cfg, setCfg] = useState(null)
  useEffect(() => { api('/safety/config').then(setCfg).catch(() => {}) }, [])
  return (
    <>
      <PageHead title="Methodology and documentation">How the framework works, what it claims, and what it does not.</PageHead>
      <div className="doc">
        <nav aria-label="Sections">{SECTIONS.map(([k, l]) => <a key={k} href={`#${location.hash.split('?')[0]}`} onClick={(e) => { e.preventDefault(); document.getElementById(k)?.scrollIntoView({ behavior: 'smooth' }) }}>{l}</a>)}</nav>
        <div>
          <S id="arch" title="System architecture">
            <div className="eq" style={{ whiteSpace: 'normal' }}>Randomness source → entropy assessment → candidate generation → safety validation → risk and decision engine → accept / reject / regenerate / safe fallback → cryptographic operation → logging</div>
            <p>A React dashboard talks to a Flask REST API. Cryptographic modules (entropy, ECDSA lab, RSA lab) are separate from the safety layer (risk engine, adaptive selector, guards), the experiment runner and SQLite storage. Standard operations use the vetted <code>cryptography</code> library; only the chosen-nonce educational signer performs its own modular arithmetic.</p>
          </S>
          <S id="motive" title="Research motivation"><p>Weak or repeated randomness at generation time has compromised real ECDSA signatures and RSA keys. The aim is a reusable layer that checks candidates with mathematically justified, operation-specific tests before they are used, and measures how much that prevents.</p></S>
          <S id="threat" title="Threat model">
            <ul><li>The attacker sees public keys and published signatures or moduli, never secret material.</li><li>The randomness source may be faulty (repeats, stuck state). The signing and key-generation code is otherwise correct.</li><li>Out of scope: side channels, malware on the signer, and faults the checks cannot observe (for example a repeated prime never compared against any known modulus).</li><li>Vulnerable material is created only in labelled educational modes, for locally generated test keys.</li></ul>
          </S>
          <S id="ecdsa" title="ECDSA nonce-reuse mathematics">
            <p>A signature on hash z with nonce k and private key d is r = x(kG) mod n and s = k⁻¹(z + r·d) mod n. Two messages signed with the same k share r:</p>
            <div className="eq">s₁ − s₂ ≡ k⁻¹(z₁ − z₂) (mod n)</div><div className="eq">k ≡ (z₁ − z₂)(s₁ − s₂)⁻¹ (mod n)</div><div className="eq">d ≡ (s₁·k − z₁)·r⁻¹ (mod n)</div>
            <p>Some implementations emit n − s (low-s form), which corresponds to −k; the recovery tries both s₂ and n − s₂ and accepts a candidate only if d·G equals the public key. Detection is by signature analysis: equal r under one key. It is not an entropy measurement.</p>
          </S>
          <S id="rsa" title="RSA shared-prime mathematics">
            <p>If n₁ = p·q₁ and n₂ = p·q₂ with q₁ ≠ q₂, then gcd(n₁, n₂) = p, giving q₁ = n₁/p and the private exponent d = e⁻¹ mod lcm(p−1, q₁−1).</p>
            <div className="eq">gᵢ = gcd(nᵢ, (P mod nᵢ²) / nᵢ),  P = ∏ nⱼ</div>
            <p>Batch GCD computes this for every modulus with a product tree and remainder tree, far faster than all pairs. It audits only the moduli supplied: it is a population-level check, not a per-key proof of safety.</p>
          </S>
          <S id="entropy" title="Entropy assessment limits">
            <ul><li>Empirical Shannon entropy of one finite sample is not the entropy of the source.</li><li>High entropy does not prove security; low entropy in a sample does not by itself identify a recoverable key or nonce.</li><li>Byte-level entropy is blind to repeated whole values. Repeated nonces and shared primes are therefore detected by their own checks.</li><li>Samples are compared with the expected entropy of an ideal uniform sample of the same size, because small samples bias the estimate downward.</li></ul>
          </S>
          <S id="risk" title="Risk-scoring methodology">
            <p>Score = Σ weightᵢ × subscoreᵢ over soft factors (weights sum to 100). Hard-fail rules (confirmed nonce reuse, shared prime, duplicate modulus, invalid parameters, known-weak source, insufficient security level) force the score to at least the hard-fail floor and the category to Critical; they can never be accepted. Weights, priors and thresholds are an initial, transparent baseline, not experimentally proven optima; the threshold-sensitivity experiment shows their effect.</p>
            {cfg && <>
              <DataTable sortable={false} rows={Object.entries(cfg.risk_config.weights).map(([k, v]) => ({ id: k, k: k.replace(/_/g, ' '), v }))} columns={[{ key: 'k', label: 'Soft factor' }, { key: 'v', label: 'Weight', num: true }]} />
              <p className="small muted" style={{ marginTop: 8 }}>Category bounds: Low &lt; {cfg.risk_config.category_bounds.low}, Moderate &lt; {cfg.risk_config.category_bounds.moderate}, High &lt; {cfg.risk_config.category_bounds.high}, otherwise Critical. Accept below {cfg.risk_config.accept_below}. Hard-fail floor {cfg.risk_config.hard_fail_floor}.</p></>}
            <p>Decisions: ACCEPT; REGENERATE (candidate-specific failure and budget remaining); SAFE FALLBACK (vetted compatible configuration, only if requirements allow); REJECT. A soft-only failure is not regenerated, because it describes the source or configuration rather than one candidate.</p>
          </S>
          <S id="defense" title="Generation-time defense">
            <p>ECDSA: each nonce candidate's r is checked against signatures already produced; repeats are discarded before signing. After the regeneration limit the signer falls back to deterministic ECDSA (RFC 6979), which does not depend on fresh signing-time randomness but does not make a weak private key safe. The registry covers one signer instance, so multi-signer deployments should prefer deterministic signing.</p>
            <p>RSA: modulus size, distinct probable primes, public exponent, prime gap, duplicate modulus and a gcd check against known moduli. Fallback to a non-RSA algorithm happens only when compatibility allows; otherwise the operation is rejected.</p>
          </S>
          <S id="protocol" title="Experimental protocol">
            <ul><li>Each group runs N independent trials (capped per group; the effective count is reported).</li><li>Baseline (no safety layer) and defended arms see the same simulated fault model with the same seed.</li><li>Seeds fix synthetic choices only. Keys, secure nonces and primes come from OS randomness.</li><li>Raw rows are exported as CSV, summaries as JSON, and metadata is stored in SQLite.</li></ul>
          </S>
          <S id="limits" title="Metrics and limitations">
            <ul><li><b>Attack success</b>: an attacker with all public outputs of a session or population recovers a private key.</li><li><b>Detection rate</b> = TP/(TP+FN). <b>False-positive / false-rejection rate</b> = FP/(FP+TN), where negatives are safe candidates.</li><li>Proportions carry 95% Wilson intervals; timing means carry normal-approximation intervals.</li><li>Reduced RSA sizes are educational only. Fault models are simulated. Timings depend on the machine.</li></ul>
            <Notice tone="warn" title="No certification">This is a research prototype. It is not formally verified, certified or recommended for production key management.</Notice>
          </S>
        </div>
      </div>
    </>
  )
}
