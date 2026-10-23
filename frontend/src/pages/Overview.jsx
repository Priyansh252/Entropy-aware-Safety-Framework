import { useEffect, useState, useCallback } from 'react'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Play, KeyRound, Network, RefreshCw } from 'lucide-react'
import { api, post, f } from '../api.js'
import { Button, Empty, ErrorNote, Ledger, Notice, PageHead, Panel, useAction, useToast } from '../components/ui.jsx'

const CAT_COLORS = { Low: '#7cc4a0', Moderate: '#e3c05f', High: '#e08f4d', Critical: '#c2352b' }

export default function Overview({ go, backendOk }) {
  const [d, setD] = useState(null)
  const [err, setErr] = useState(null)
  const toast = useToast()
  const load = useCallback(async () => {
    try { setD(await api('/dashboard')); setErr(null) } catch (e) { setErr(e.message) }
  }, [])
  useEffect(() => { load(); const t = setInterval(load, 4000); return () => clearInterval(t) }, [load])

  const demo = useAction(async (target) => { const r = await post('/safety/defense-demo', { target }); toast(`${target.toUpperCase()} defense demonstration complete`); await load(); return r })
  const quick = useAction(async () => {
    await post('/experiments/run', { trials: 10, groups: ['entropy_samples', 'ecdsa_attack', 'ecdsa_defense', 'rsa_defense'], signatures_per_session: 15, rsa_keys_per_population: 8 })
    toast('Quick experiment started'); go('experiments')
  })

  if (err && !d) return <><PageHead title="Overview">Framework status and recent activity.</PageHead><ErrorNote error={err} /></>
  if (!d) return <PageHead title="Overview">Loading…</PageHead>
  const empty = d.total_assessments === 0 && d.attack_runs === 0 && d.experiments_completed === 0
  const risk = ['Low', 'Moderate', 'High', 'Critical'].map((k) => ({ name: k, count: d.risk_distribution[k] || 0 }))
  const dec = ['ACCEPT', 'REGENERATE', 'SAFE_FALLBACK', 'REJECT'].map((k) => ({ name: k.replace('_', ' '), count: d.decision_distribution[k] || 0 }))
  const cmp = Object.entries(d.attack_comparison).map(([k, v]) => ({
    name: k === 'ecdsa_defense' ? 'ECDSA sessions' : 'RSA keys', 'No defense': +(v.baseline * 100).toFixed(1), 'With safety layer': +(v.defended * 100).toFixed(1) }))

  return (
    <>
      <PageHead title="Overview">
        Live state of the framework, computed from the audit database and completed experiments. Nothing on this page is pre-filled.
      </PageHead>
      <Ledger items={[
        { label: 'Framework status', value: backendOk ? 'Operational' : 'Offline', color: backendOk ? 'var(--ok)' : 'var(--bad)' },
        { label: 'Assessments recorded', value: d.total_assessments },
        { label: 'Vulnerable candidates detected', value: d.vulnerable_detected },
        { label: 'Candidates not accepted', value: d.candidates_rejected },
        { label: 'Attack demos that succeeded', value: `${d.attacks_succeeded}/${d.attack_runs}` },
        { label: 'Experiments', value: d.experiments_running ? `${d.experiments_running} running` : `${d.experiments_completed} completed` },
      ]} />
      <Panel title="Quick launch">
        <div className="row">
          <Button variant="primary" icon={Play} loading={quick.loading} onClick={quick.run}>Run quick experiment (10 trials)</Button>
          <Button icon={KeyRound} loading={demo.loading} onClick={() => demo.run('ecdsa')}>ECDSA defense demo</Button>
          <Button icon={Network} loading={demo.loading} onClick={() => demo.run('rsa')}>RSA defense demo</Button>
          <Button size="sm" icon={RefreshCw} onClick={load}>Refresh</Button>
        </div>
        <div style={{ marginTop: 10 }}><ErrorNote error={quick.error || demo.error} /></div>
      </Panel>
      {empty ? (
        <Panel><Empty title="No results yet" action={<><Button variant="primary" onClick={() => demo.run('ecdsa')} loading={demo.loading}>Run the ECDSA defense demo</Button><Button onClick={() => go('ecdsa')}>Open ECDSA laboratory</Button></>}>
          Run a demonstration or an experiment. Charts and counters fill in from measured backend data.</Empty></Panel>
      ) : (
        <div className="grid g2">
          <Panel title="Risk categories assigned">
            <ResponsiveContainer width="100%" height={220}><BarChart data={risk}><CartesianGrid vertical={false} stroke="#e8ecf1" /><XAxis dataKey="name" /><YAxis allowDecimals={false} /><Tooltip />
              <Bar dataKey="count" name="Assessments" fill="#3b4cca" radius={[3, 3, 0, 0]} shape={(p) => <rect {...p} fill={CAT_COLORS[p.name]} rx={3} />} /></BarChart></ResponsiveContainer>
          </Panel>
          <Panel title="Decisions taken">
            <ResponsiveContainer width="100%" height={220}><BarChart data={dec}><CartesianGrid vertical={false} stroke="#e8ecf1" /><XAxis dataKey="name" /><YAxis allowDecimals={false} /><Tooltip />
              <Bar dataKey="count" name="Decisions" fill="#3b4cca" radius={[3, 3, 0, 0]} /></BarChart></ResponsiveContainer>
          </Panel>
          <Panel title="Attack success: no defense vs safety layer" aside={<span className="faint small">from latest completed experiments</span>}>
            {cmp.length ? (
              <ResponsiveContainer width="100%" height={220}><BarChart data={cmp}><CartesianGrid vertical={false} stroke="#e8ecf1" /><XAxis dataKey="name" /><YAxis unit="%" domain={[0, 100]} /><Tooltip /><Legend />
                <Bar dataKey="No defense" fill="#c2352b" radius={[3, 3, 0, 0]} /><Bar dataKey="With safety layer" fill="#3b4cca" radius={[3, 3, 0, 0]} /></BarChart></ResponsiveContainer>
            ) : <Empty title="No comparison yet">Run an experiment that includes the ECDSA or RSA defense groups.</Empty>}
          </Panel>
          <Panel title="Recent activity" flush>
            {d.recent_activity.length ? <div className="stack" style={{ gap: 0 }}>{d.recent_activity.map((a, i) => (
              <div key={i} className="row spread" style={{ padding: '8px 16px', borderBottom: '1px solid var(--line-2)' }}>
                <span><b>{a.title}</b> <span className="muted">{a.detail}</span></span><span className="faint small">{f.time(a.ts)}</span></div>))}</div> : <Empty title="Nothing yet" />}
          </Panel>
        </div>
      )}
      <Notice tone="info" title="Scope">Results describe this implementation on educational key sizes and simulated fault models. They are not evidence of production-grade security.</Notice>
    </>
  )
}
