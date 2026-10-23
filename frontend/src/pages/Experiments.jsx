import { useCallback, useEffect, useRef, useState } from 'react'
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Download, Play } from 'lucide-react'
import { api, post, f } from '../api.js'
import { Badge, Button, DataTable, Empty, ErrorNote, Field, Notice, PageHead, Panel, Progress, useAction, useToast } from '../components/ui.jsx'

const C = { base: '#c2352b', def: '#3b4cca', det: '#0f8b8d' }
const Grid = () => <CartesianGrid vertical={false} stroke="#e8ecf1" />

export default function Experiments() {
  const toast = useToast()
  const [opts, setOpts] = useState(null)
  const [cfg, setCfg] = useState(null)
  const [groups, setGroups] = useState([])
  const [hist, setHist] = useState([])
  const [cur, setCur] = useState(null)
  const [job, setJob] = useState(null)
  const [profile, setProfile] = useState('default')
  const [err, setErr] = useState(null)
  const timer = useRef(null)

  const loadHist = useCallback(async () => setHist((await api('/experiments')).experiments), [])
  const view = useCallback(async (id) => { try { setCur(await api(`/experiments/${id}`)) } catch (e) { setErr(e.message) } }, [])
  useEffect(() => {
    (async () => {
      try {
        const o = await api('/experiments/options'); setOpts(o); setCfg({ ...o.defaults }); setGroups(o.groups.map((g) => g.id))
        const h = (await api('/experiments')).experiments; setHist(h)
        const last = h.find((e) => e.status === 'completed'); if (last) view(last.id)
        const run = h.find((e) => e.status === 'running'); if (run) setJob({ id: run.id, progress: 0, stage: 'running', status: 'running' })
      } catch (e) { setErr(e.message) }
    })()
    return () => clearTimeout(timer.current)
  }, [view])
  useEffect(() => {
    if (!job || job.status !== 'running') return
    const tick = async () => {
      try {
        const s = await api(`/experiments/status/${job.id}`)
        setJob(s)
        if (s.status === 'running') timer.current = setTimeout(tick, 700)
        else { await loadHist(); if (s.status === 'completed') { await view(job.id); toast('Experiment completed') } else setErr(s.error || 'Experiment failed') }
      } catch (e) { setErr(e.message) }
    }
    timer.current = setTimeout(tick, 400)
    return () => clearTimeout(timer.current)
  }, [job?.id, job?.status])

  const run = useAction(async () => {
    setErr(null)
    const r = await post('/experiments/run', { ...cfg, groups })
    setJob({ id: r.experiment_id, status: 'running', progress: 0, stage: 'starting' })
  })
  if (!opts || !cfg) return <><PageHead title="Experiments and benchmarks">Loading…</PageHead><ErrorNote error={err} /></>
  const set = (k, num = true) => (e) => setCfg({ ...cfg, [k]: num ? e.target.value : e.target.value })
  const running = job?.status === 'running'
  const g = cur?.summary?.groups || {}
  const small = cur && cur.params.trials < 30

  const atk = []
  if (g.ecdsa_defense) { const m = g.ecdsa_defense.metrics; atk.push({ name: 'ECDSA sessions', 'No defense': m.baseline.sessions_compromised.rate * 100, 'Reuse guard': m.guard.sessions_compromised.rate * 100, 'Deterministic ECDSA': m.deterministic.sessions_compromised.rate * 100 }) }
  if (g.rsa_defense) { const m = g.rsa_defense.metrics; atk.push({ name: 'RSA keys (batch GCD)', 'No defense': m.baseline.keys_factored_by_batch_gcd.rate * 100, 'Reuse guard': m.defended.keys_factored_by_batch_gcd.rate * 100 }) }
  const vul = []
  if (g.ecdsa_defense) { const m = g.ecdsa_defense.metrics; vul.push({ name: 'ECDSA', 'Vulnerable accepted (no defense)': m.baseline.vulnerable_signatures_accepted, 'Vulnerable accepted (defended)': m.guard.vulnerable_signatures_accepted, 'Candidates rejected': m.guard.candidates_rejected }) }
  if (g.rsa_defense) { const m = g.rsa_defense.metrics; vul.push({ name: 'RSA', 'Vulnerable accepted (no defense)': m.baseline.vulnerable_final_keys, 'Vulnerable accepted (defended)': m.defended.vulnerable_final_keys, 'Candidates rejected': m.defended.candidates_rejected }) }
  const tim = []
  if (g.overhead) { const m = g.overhead.metrics.signing_ms; const nm = { ecdsa_library_random: 'random nonce', ecdsa_library_deterministic: 'deterministic', ecdsa_raw_nonce_baseline: 'raw nonce (baseline)', ecdsa_guarded_signing: 'guarded' }; Object.entries(m).forEach(([k, v]) => tim.push({ name: nm[k] || k, ms: +v.mean.toFixed(4) })) }
  const rtim = g.overhead ? [{ name: 'RSA key generation', ms: g.overhead.metrics.rsa_keygen_ms.mean }, { name: 'Validation + risk scoring', ms: g.overhead.metrics.rsa_validation_ms.mean }] : []
  const grid = g.threshold_sensitivity?.metrics.grid.filter((x) => x.profile === profile).map((x) => ({ t: x.threshold, 'Detection rate': +(x.detection_rate * 100).toFixed(1), 'False rejection rate': +(x.false_rejection_rate * 100).toFixed(1) }))

  return (
    <>
      <PageHead title="Experiments and benchmarks">
        Fixed-protocol, repeatable trials. Seeds control synthetic choices only; keys and secure nonces always come from OS randomness. All charts below are computed from the stored results of the selected run.
      </PageHead>
      <div className="grid g-side">
        <Panel title="Configuration">
          <div className="stack">
            <div className="stack" style={{ gap: 5 }}><span className="small muted" style={{ fontWeight: 550 }}>Experiment groups</span>
              {opts.groups.map((o) => <label key={o.id} className="check" title={o.kind}><input type="checkbox" checked={groups.includes(o.id)} onChange={() => setGroups(groups.includes(o.id) ? groups.filter((x) => x !== o.id) : [...groups, o.id])} />{o.label}</label>)}</div>
            <Field label="Trials" hint={`1 – ${opts.limits.experiment_trials[1]}; capped per group`}><input type="number" min="1" max="500" value={cfg.trials} onChange={set('trials')} /></Field>
            <Field label="Seed"><input type="number" min="0" value={cfg.seed} onChange={set('seed')} /></Field>
            <Field label="Fault probability" hint="simulated"><input type="number" step="0.05" min="0" max="0.9" value={cfg.fault_probability} onChange={set('fault_probability')} /></Field>
            <Field label="Fault model"><select value={cfg.fault_mode} onChange={set('fault_mode', false)}><option value="intermittent_repeat">Intermittent repeats</option><option value="stuck">Stuck source</option></select></Field>
            <div className="grid g2" style={{ gap: 10 }}>
              <Field label="Signatures / session"><input type="number" min="4" max="100" value={cfg.signatures_per_session} onChange={set('signatures_per_session')} /></Field>
              <Field label="RSA keys / population"><input type="number" min="3" max="25" value={cfg.rsa_keys_per_population} onChange={set('rsa_keys_per_population')} /></Field>
              <Field label="Collection size"><input type="number" min="3" max="30" value={cfg.collection_size} onChange={set('collection_size')} /></Field>
              <Field label="Max regenerations"><input type="number" min="0" max="10" value={cfg.max_regen} onChange={set('max_regen')} /></Field>
            </div>
            <Button variant="primary" icon={Play} loading={run.loading} disabled={running || !groups.length} onClick={run.run}>Run experiment</Button>
            {running && <div className="stack" style={{ gap: 4 }}><Progress value={job.progress || 0} /><span className="small muted">{Math.round((job.progress || 0) * 100)}% · {job.stage}</span></div>}
            <ErrorNote error={run.error || err} />
          </div>
        </Panel>
        <div className="stack">
          {!cur ? <Panel><Empty title="No completed experiment">Configure and run an experiment. Results, charts and exports appear here.</Empty></Panel> : (<>
            <Panel title={`Results: ${cur.id}`} aside={<span className="row"><a className="btn sm" href={`/api/experiments/${cur.id}/export?format=csv`}><Download size={14} />CSV</a><a className="btn sm" href={`/api/experiments/${cur.id}/export?format=json`}><Download size={14} />JSON</a></span>}>
              <p className="muted small">{cur.params.trials} trials requested, {Object.values(g).map((x) => x.effective_trials).join(' / ')} effective per group · {cur.duration_s?.toFixed(1)} s · seed {cur.params.seed} · fault model {cur.params.fault_mode} @ {cur.params.fault_probability}</p>
              {small && <Notice tone="warn" title="Small sample">Fewer than 30 trials is a demonstration, not a conclusive comparison; check the confidence intervals.</Notice>}
            </Panel>
            {atk.length > 0 && <Panel title="Attack success: baseline vs defended" aside={<Badge tone="neutral">measured, simulated faults</Badge>}>
              <ResponsiveContainer width="100%" height={230}><BarChart data={atk}><Grid /><XAxis dataKey="name" /><YAxis unit="%" domain={[0, 100]} /><Tooltip formatter={(v) => `${(+v).toFixed(1)}%`} /><Legend />
                <Bar dataKey="No defense" fill={C.base} radius={[3, 3, 0, 0]} /><Bar dataKey="Reuse guard" fill={C.def} radius={[3, 3, 0, 0]} /><Bar dataKey="Deterministic ECDSA" fill={C.det} radius={[3, 3, 0, 0]} /></BarChart></ResponsiveContainer>
              <p className="small muted">{g.ecdsa_defense && <>ECDSA no defense: {f.ci(g.ecdsa_defense.metrics.baseline.sessions_compromised)}; guard: {f.ci(g.ecdsa_defense.metrics.guard.sessions_compromised)}. </>}{g.rsa_defense && <>RSA no defense: {f.ci(g.rsa_defense.metrics.baseline.keys_factored_by_batch_gcd)}; defended: {f.ci(g.rsa_defense.metrics.defended.keys_factored_by_batch_gcd)}.</>}</p></Panel>}
            {vul.length > 0 && <Panel title="Vulnerable candidates: accepted vs rejected">
              <ResponsiveContainer width="100%" height={230}><BarChart data={vul}><Grid /><XAxis dataKey="name" /><YAxis allowDecimals={false} /><Tooltip /><Legend />
                <Bar dataKey="Vulnerable accepted (no defense)" fill={C.base} /><Bar dataKey="Vulnerable accepted (defended)" fill={C.def} /><Bar dataKey="Candidates rejected" fill="#e3c05f" /></BarChart></ResponsiveContainer></Panel>}
            {tim.length > 0 && <div className="grid g2">
              <Panel title="Signing time (mean, ms)"><ResponsiveContainer width="100%" height={220}><BarChart data={tim}><Grid /><XAxis dataKey="name" fontSize={10} interval={0} angle={-18} textAnchor="end" height={52} /><YAxis /><Tooltip /><Bar dataKey="ms" fill={C.def} radius={[3, 3, 0, 0]} /></BarChart></ResponsiveContainer>
                <p className="small muted">Guarded signing vs raw-nonce baseline: {f.num(g.overhead.metrics.signing_overhead_vs_raw_pct.ecdsa_guarded_signing, 0)}% (microsecond scale; machine dependent).</p></Panel>
              <Panel title="RSA generation vs validation (mean, ms)"><ResponsiveContainer width="100%" height={220}><BarChart data={rtim}><Grid /><XAxis dataKey="name" fontSize={11} /><YAxis /><Tooltip /><Bar dataKey="ms" fill={C.det} radius={[3, 3, 0, 0]} /></BarChart></ResponsiveContainer>
                <p className="small muted">Validation adds {f.num(g.overhead.metrics.rsa_validation_overhead_pct, 0)}% to {cur.params.key_bits}-bit key generation time.</p></Panel></div>}
            {grid && <Panel title="Threshold sensitivity: detection and false rejection" aside={<select aria-label="Weight profile" value={profile} onChange={(e) => setProfile(e.target.value)} style={{ width: 'auto' }}>{['default', 'entropy_heavy', 'source_heavy', 'flat'].map((p) => <option key={p}>{p}</option>)}</select>}>
              <ResponsiveContainer width="100%" height={230}><LineChart data={grid}><Grid /><XAxis dataKey="t" label={{ value: 'accept-below threshold', position: 'insideBottom', offset: -2, fontSize: 11 }} /><YAxis unit="%" domain={[0, 100]} /><Tooltip /><Legend verticalAlign="top" />
                <Line dataKey="Detection rate" stroke={C.def} strokeWidth={2} /><Line dataKey="False rejection rate" stroke={C.base} strokeWidth={2} /></LineChart></ResponsiveContainer>
              <p className="small muted">{g.threshold_sensitivity.notes.join(' ')}</p></Panel>}
            <div className="grid g2">
              {g.rsa_batch_gcd && <Panel title="Batch-GCD accuracy"><dl className="kv"><dt>Detection rate</dt><dd>{f.ci(g.rsa_batch_gcd.metrics.modulus_level.detection_rate)}</dd><dt>False-positive rate</dt><dd>{f.ci(g.rsa_batch_gcd.metrics.modulus_level.false_positive_rate)}</dd>
                <dt>Verified recoveries</dt><dd>{f.ci(g.rsa_batch_gcd.metrics.factor_recovery_verified)}</dd><dt>Agrees with pairwise GCD</dt><dd>{f.ci(g.rsa_batch_gcd.metrics.batch_vs_pairwise_agreement)}</dd></dl></Panel>}
              {g.ecdsa_attack && <Panel title="ECDSA attack and detection"><dl className="kv"><dt>Recovery, normal nonces</dt><dd>{f.ci(g.ecdsa_attack.metrics.attack_success_normal)}</dd><dt>Recovery, reused nonce</dt><dd>{f.ci(g.ecdsa_attack.metrics.attack_success_reused)}</dd>
                <dt>Reuse detection rate</dt><dd>{f.ci(g.ecdsa_attack.metrics.detection.detection_rate)}</dd><dt>False-positive rate</dt><dd>{f.ci(g.ecdsa_attack.metrics.detection.false_positive_rate)}</dd></dl></Panel>}
              {g.adaptive_policy && <Panel title="Adaptive policy outcomes"><dl className="kv"><dt>Scenarios enumerated</dt><dd>{g.adaptive_policy.metrics.scenarios}</dd><dt>Selections below required security</dt><dd><b>{g.adaptive_policy.metrics.selections_below_required_security}</b></dd><dt>No eligible configuration (refused)</dt><dd>{g.adaptive_policy.metrics.no_eligible_configuration}</dd>
                <dt>Chosen</dt><dd>{Object.entries(g.adaptive_policy.metrics.selected_counts).map(([k, v]) => `${k}: ${v}`).join(', ')}</dd></dl></Panel>}
              {g.entropy_samples && <Panel title="Entropy samples"><dl className="kv">{Object.entries(g.entropy_samples.metrics).map(([k, v]) => <><dt key={k}>{k.replace(/_/g, ' ')}</dt><dd key={k + 'd'}>{f.num(v.shannon_bits.mean, 3)} bits/byte; low-entropy flag {f.pct(v.low_entropy_flag_rate.rate, 0)}; repeated-block flag {f.pct(v.repeated_block_flag_rate.rate, 0)}</dd></>)}</dl></Panel>}
            </div>
          </>)}
          <Panel title="Experiment history" flush>
            <DataTable rows={hist} defaultSort={{ key: 'created', dir: 'desc' }} empty="No experiments yet." selected={cur?.id} onRowClick={(r) => r.status === 'completed' && view(r.id)} columns={[
              { key: 'id', label: 'ID' }, { key: 'created', label: 'Started', render: (r) => <span className="small">{f.time(r.created)}</span> },
              { key: 'status', label: 'Status', render: (r) => <Badge tone={r.status === 'completed' ? 'ok' : r.status === 'failed' ? 'bad' : 'info'}>{r.status}</Badge> },
              { key: 'trials', label: 'Trials', num: true, render: (r) => r.params.trials }, { key: 'groups', label: 'Groups', sortable: false, render: (r) => r.groups.length },
              { key: 'duration_s', label: 'Duration', num: true, render: (r) => (r.duration_s ? `${r.duration_s.toFixed(1)} s` : '–') }]} />
          </Panel>
        </div>
      </div>
    </>
  )
}
