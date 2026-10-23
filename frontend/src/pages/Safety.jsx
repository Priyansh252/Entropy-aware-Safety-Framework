import { useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { ShieldCheck, Play } from 'lucide-react'
import { api, post, f } from '../api.js'
import { Badge, Button, CategoryBadge, DataTable, DecisionBadge, ErrorNote, FactorTable, Field, Gauge, Kv, Notice, PageHead, Panel, Tabs, Trace, useAction } from '../components/ui.jsx'

const TAGS = [['fips', 'FIPS-style'], ['widely_supported', 'Widely supported'], ['legacy_rsa', 'Legacy RSA required'], ['modern', 'Modern curves'], ['randomized_signing_only', 'Randomized signing only']]

function Reqs({ r, set }) {
  const toggle = (t) => set({ ...r, compatibility: r.compatibility.includes(t) ? r.compatibility.filter((x) => x !== t) : [...r.compatibility, t] })
  return (<>
    <Field label="Operation"><select value={r.operation} onChange={(e) => set({ ...r, operation: e.target.value })}><option value="signature">Digital signature</option><option value="encryption">Encryption</option><option value="key_agreement">Key agreement</option></select></Field>
    <Field label="Required security level"><select value={r.required_security_bits} onChange={(e) => set({ ...r, required_security_bits: Number(e.target.value) })}><option value={112}>112-bit</option><option value={128}>128-bit</option><option value={192}>192-bit</option></select></Field>
    <Field label="Performance priority"><select value={r.performance_priority} onChange={(e) => set({ ...r, performance_priority: e.target.value })}><option value="speed">Speed</option><option value="balanced">Balanced</option><option value="security">Security margin</option></select></Field>
    <div className="stack" style={{ gap: 6 }}><span className="small muted" style={{ fontWeight: 550 }}>Compatibility constraints</span>
      {TAGS.map(([t, l]) => <label key={t} className="check"><input type="checkbox" checked={r.compatibility.includes(t)} onChange={() => toggle(t)} />{l}</label>)}
      <label className="check"><input type="checkbox" checked={r.allow_fallback} onChange={(e) => set({ ...r, allow_fallback: e.target.checked })} />Allow safe fallback</label></div>
  </>)
}

function Scenario() {
  const [target, setTarget] = useState('ecdsa_sign')
  const [cond, setCond] = useState('faulty')
  const [maxRegen, setMaxRegen] = useState(3)
  const [req, setReq] = useState({ operation: 'signature', required_security_bits: 128, performance_priority: 'balanced', compatibility: [], allow_fallback: true })
  const [opIdx, setOpIdx] = useState(1)
  const [att, setAtt] = useState(0)
  const run = useAction(async () => { const r = await post('/safety/scenario', { target, condition: cond, max_regen: Number(maxRegen), requirements: req }); const i = r.operations.length - 1; setOpIdx(i); setAtt(r.operations[i].trace.length - 1); return r })
  const d = run.data
  const op = d?.operations[opIdx]
  const a = op?.trace[att]
  const risk = op && att === op.trace.length - 1 ? op.risk : null
  return (
    <div className="grid g-side">
      <Panel title="Scenario">
        <div className="stack">
          <Field label="Protected operation"><select value={target} onChange={(e) => setTarget(e.target.value)}><option value="ecdsa_sign">ECDSA signing (nonce candidates)</option><option value="rsa_keygen">RSA key generation</option></select></Field>
          <Field label="Candidate source"><select value={cond} onChange={(e) => setCond(e.target.value)}><option value="healthy">Healthy source</option><option value="faulty">Faulty source (simulated)</option></select></Field>
          <Field label="Max regenerations"><input type="number" min="0" max="10" value={maxRegen} onChange={(e) => setMaxRegen(e.target.value)} /></Field>
          <Reqs r={req} set={setReq} />
          <Button variant="primary" icon={Play} loading={run.loading} onClick={run.run}>Run guarded operation</Button>
          <ErrorNote error={run.error} />
        </div>
      </Panel>
      <div className="stack">
        {!d ? <Panel><div className="empty"><h3>No decision trace yet</h3>Choose a scenario and run the guarded operation. Every attempt is scored and logged.</div></Panel> : (<>
          <Panel title="Adaptive configuration" aside={<Badge tone="neutral">{d.source_model}</Badge>}>
            {d.selection.selected ? <Kv items={[['Selected', <b>{d.selection.selected.detail}</b>], ['Approx. security', `${d.selection.selected.security_bits}-bit (required ${d.selection.request.required_security_bits})`], ['Notes', d.selection.notes.join(' ')]]} /> : <Notice tone="warn" title="No eligible configuration">{d.selection.notes[0]}</Notice>}
            <details style={{ marginTop: 8 }}><summary className="small muted" style={{ cursor: 'pointer' }}>Why other configurations were excluded</summary>
              <DataTable sortable={false} rows={d.selection.considered.map((c) => ({ ...c }))} columns={[{ key: 'id', label: 'Configuration' }, { key: 'eligible', label: 'Eligible', render: (c) => <Badge tone={c.eligible ? 'ok' : 'neutral'}>{c.eligible ? 'yes' : 'no'}</Badge> }, { key: 'rejected_because', label: 'Reason', render: (c) => c.rejected_because.join('; ') || '–' }]} /></details>
          </Panel>
          {d.requirement_note && <Notice tone="info" title="Note">{d.requirement_note}</Notice>}
          {d.operations.length > 1 && <Tabs tabs={d.operations.map((o, i) => [i, o.label])} value={opIdx} onChange={(i) => { setOpIdx(i); setAtt(d.operations[i].trace.length - 1) }} />}
          <Panel title="Decision trace" aside={<span className="row"><DecisionBadge d={op.decision} />{op.fallback_config && <Badge tone="info">{op.fallback_config}</Badge>}</span>}>
            <Trace attempts={op.trace} selected={att} onSelect={setAtt} />
            <p style={{ marginTop: 10 }}><b>Outcome:</b> {op.status.replace('_', ' ')}. {op.risk.recommended_action} {op.regenerations > 0 && `${op.regenerations} candidate(s) were discarded and never used.`}</p>
          </Panel>
          {risk && <div className="grid g2">
            <Panel title="Final risk assessment"><Gauge score={risk.risk_score} category={risk.risk_category} hardFail={risk.hard_fail} bounds={risk.thresholds.category_bounds} />
              <div style={{ marginTop: 12 }}><Kv items={[['Soft-factor score', risk.soft_score], ['Accept below', risk.thresholds.accept_below], ['Regenerations', `${risk.regen_count} of ${risk.max_regen}`],
                ['Validation performed', risk.validation_evidence.performed.join(', ') || '–'], ['Validation failed', risk.validation_evidence.failed.join(', ') || 'none'],
                ['Nonce reuse confirmed', String(risk.validation_evidence.nonce_reuse_confirmed)], ['Shared prime confirmed', String(risk.validation_evidence.shared_prime_confirmed)]]} /></div></Panel>
            <Panel title="Risk factors" flush><FactorTable factors={risk.factors} /></Panel></div>}
          {!risk && <Notice tone="info">Attempt {a.attempt} was scored {a.risk_score}{a.hard_fail ? ' and hit a hard-fail rule' : ''}; decision {a.decision.replace('_', ' ')}. Select the last attempt for the full factor breakdown.</Notice>}
        </>)}
      </div>
    </div>
  )
}

function Defense() {
  const [target, setTarget] = useState('ecdsa')
  const [n, setN] = useState(30)
  const [p, setP] = useState(0.2)
  const [mode, setMode] = useState('intermittent_repeat')
  const [maxRegen, setMaxRegen] = useState(3)
  const run = useAction(() => post('/safety/defense-demo', { target, n: Number(n), fault_probability: Number(p), fault_mode: mode, max_regen: Number(maxRegen) }))
  const d = run.data
  const base = d?.arms.baseline
  const def = d && (d.arms.guard || d.arms.defended)
  const ecdsa = d?.target === 'ecdsa'
  const row = (label, get) => ({ id: label, label, a: get(base), b: get(def) })
  const rows = d ? (ecdsa ? [
    row('Nonce candidates generated', (x) => x.candidates), row('Candidates rejected', (x) => x.rejected_candidates), row('Candidates regenerated', (x) => x.regenerations),
    row('Vulnerable (reused-nonce) signatures accepted', (x) => x.vulnerable_signatures), row('Final successful signatures', (x) => `${x.signatures} (${x.verified} verify)`), row('Fallback to deterministic ECDSA', (x) => x.fallbacks),
    row('Mean time per signature', (x) => f.ms(x.mean_ms)), row('Added overhead', (x) => (x.arm === 'baseline' ? '–' : `${x.overhead_pct_vs_baseline?.toFixed(0)}%`)), row('Attacker recovers private key', (x) => (x.compromised ? 'YES' : 'no')),
  ] : [
    row('Key candidates generated', (x) => x.candidates), row('Candidates rejected', (x) => x.rejected_candidates), row('Candidates regenerated', (x) => x.regenerations),
    row('Vulnerable keys accepted', (x) => x.vulnerable_final), row('Final successful RSA keys', (x) => x.accepted_rsa_keys), row('Safe fallbacks / rejected operations', (x) => `${x.fallbacks} / ${x.rejected_ops}`),
    row('Mean time per key', (x) => f.ms(x.mean_ms)), row('Added overhead (excl. prime generation, not meaningful as %)', (x) => (x.arm === 'baseline' ? '–' : 'see Experiments')), row('Keys factored by batch GCD', (x) => x.keys_factored_by_batch_gcd),
  ]) : []
  return (
    <div className="grid g-side">
      <Panel title="Demonstration">
        <div className="stack">
          <Field label="Workflow"><select value={target} onChange={(e) => { setTarget(e.target.value); setN(e.target.value === 'rsa' ? 10 : 30) }}><option value="ecdsa">ECDSA signing session</option><option value="rsa">RSA key population</option></select></Field>
          <Field label={target === 'rsa' ? 'Keys to generate' : 'Signatures'}><input type="number" min={target === 'rsa' ? 3 : 4} max={target === 'rsa' ? 25 : 100} value={n} onChange={(e) => setN(e.target.value)} /></Field>
          <Field label="Fault model (simulated)"><select value={mode} onChange={(e) => setMode(e.target.value)}><option value="intermittent_repeat">Intermittent repeats</option><option value="stuck">Stuck source</option></select></Field>
          <Field label="Fault probability"><input type="number" step="0.05" min="0" max="0.9" value={p} onChange={(e) => setP(e.target.value)} /></Field>
          <Field label="Max regenerations"><input type="number" min="0" max="10" value={maxRegen} onChange={(e) => setMaxRegen(e.target.value)} /></Field>
          <Button variant="primary" icon={ShieldCheck} loading={run.loading} onClick={run.run}>Run with and without defense</Button>
          <ErrorNote error={run.error} />
        </div>
      </Panel>
      <div className="stack">
        {!d ? <Panel><div className="empty"><h3>No demonstration run</h3>Both workflows consume the same simulated faulty source model.</div></Panel> : (<>
          <Panel title="Without defense vs with safety layer" aside={<Badge tone="neutral">{d.source_model}</Badge>} flush>
            <DataTable sortable={false} rows={rows} columns={[{ key: 'label', label: 'Measure' }, { key: 'a', label: 'No defense', num: true }, { key: 'b', label: 'Safety layer', num: true }]} />
          </Panel>
          <Panel title="Workflow">
            <p className="small muted">Generate candidates → assess available quality indicators → run operation-specific checks ({ecdsa ? 'nonce-reuse registry on r' : 'prime, modulus and shared-factor validation'}) → score risk → accept, reject, regenerate or fall back → perform the operation.</p>
            {ecdsa && d.arms.deterministic && <p className="small muted">Deterministic ECDSA (RFC 6979) arm: {d.arms.deterministic.compromised ? 'compromised' : 'no key recovery'}, {d.arms.deterministic.vulnerable_signatures} reused-nonce signatures, mean {f.ms(d.arms.deterministic.mean_ms)} per signature.</p>}
            {!ecdsa && <p className="small muted">This is generation-time prevention. The shared-prime check only sees moduli already accepted; batch GCD is a separate population-level audit.</p>}
          </Panel>
        </>)}
      </div>
    </div>
  )
}

export default function Safety() {
  const [tab, setTab] = useState('trace')
  return (
    <>
      <PageHead title="Safety engine">
        Candidates from an untrusted source are validated, scored and either accepted, regenerated, replaced by a safe fallback, or rejected. Confirmed critical conditions can never be accepted, whatever the score.
      </PageHead>
      <Tabs tabs={[['trace', 'Decision trace'], ['defense', 'Generation-time defense']]} value={tab} onChange={setTab} />
      {tab === 'trace' ? <Scenario /> : <Defense />}
    </>
  )
}
