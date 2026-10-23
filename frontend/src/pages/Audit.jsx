import { useCallback, useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { api, f } from '../api.js'
import { Badge, Button, CategoryBadge, DataTable, DecisionBadge, Empty, ErrorNote, Kv, PageHead, Panel } from '../components/ui.jsx'

const PAGE = 50
export default function Audit() {
  const [q, setQ] = useState({ search: '', decision: '', operation: '', category: '', mode: '' })
  const [off, setOff] = useState(0)
  const [d, setD] = useState(null)
  const [err, setErr] = useState(null)
  const [open, setOpen] = useState(null)
  const load = useCallback(async () => {
    const p = new URLSearchParams({ ...q, limit: PAGE, offset: off, sort: 'ts', order: 'desc' })
    try { setD(await api(`/audit?${p}`)); setErr(null) } catch (e) { setErr(e.message) }
  }, [q, off])
  useEffect(() => { const t = setTimeout(load, 200); return () => clearTimeout(t) }, [load])
  const set = (k) => (e) => { setOff(0); setQ({ ...q, [k]: e.target.value }) }
  const sel = (k, opts, label) => <select aria-label={label} value={q[k]} onChange={set(k)} style={{ width: 'auto' }}><option value="">{label}</option>{opts.map((o) => <option key={o} value={o}>{o}</option>)}</select>
  const rows = d?.rows.map((r) => ({ ...r, id: r.id })) || []
  return (
    <>
      <PageHead title="Audit log">Every assessment with its decision. Secret keys, nonces and raw secret random material are never stored; entries hold test identifiers and sanitized metadata only.</PageHead>
      <Panel title={`Records${d ? ` (${d.total})` : ''}`} aside={<Button size="sm" icon={RefreshCw} onClick={load}>Refresh</Button>}>
        <div className="row" style={{ marginBottom: 12 }}>
          <input type="text" aria-label="Search" placeholder="Search operation, configuration, ID…" value={q.search} onChange={set('search')} style={{ maxWidth: 300 }} />
          {sel('decision', ['ACCEPT', 'REGENERATE', 'SAFE_FALLBACK', 'REJECT'], 'All decisions')}
          {sel('operation', ['ecdsa_sign', 'rsa_keygen'], 'All operations')}
          {sel('category', ['Low', 'Moderate', 'High', 'Critical'], 'All risk levels')}
          {sel('mode', ['interactive_demo', 'experiment'], 'All modes')}
        </div>
        <ErrorNote error={err} />
        {d && !d.total ? <Empty title="No records match">Run a demonstration on the Safety engine page to create audit entries.</Empty> : (
          <DataTable rows={rows} selected={open?.id} onRowClick={(r) => setOpen(open?.id === r.id ? null : r)} columns={[
            { key: 'ts', label: 'Time', render: (r) => <span className="small">{f.time(r.ts)}</span> }, { key: 'operation', label: 'Operation' }, { key: 'configuration', label: 'Configuration' },
            { key: 'risk_score', label: 'Risk', num: true }, { key: 'risk_category', label: 'Level', render: (r) => <CategoryBadge c={r.risk_category} /> }, { key: 'decision', label: 'Decision', render: (r) => <DecisionBadge d={r.decision} /> },
            { key: 'validation_outcome', label: 'Validation', render: (r) => <Badge tone={r.validation_outcome === 'passed' ? 'ok' : r.validation_outcome === 'failed' ? 'bad' : 'neutral'}>{r.validation_outcome}</Badge> },
            { key: 'exec_ms', label: 'Duration', num: true, render: (r) => f.ms(r.exec_ms) }, { key: 'mode', label: 'Mode' }]} />)}
        {open && <div style={{ marginTop: 12, padding: 14, background: '#f8f9fb', border: '1px solid var(--line-2)', borderRadius: 5 }}>
          <Kv items={[['Assessment', <code>{open.assessment_id}</code>], ['Candidate', <code>{open.candidate_id}</code>], ['Regenerations', open.regen_count],
            ['Factors', open.factors.map((x) => `${x.name}${x.points != null ? ` (${x.points})` : ''}`).join(', ')], ['Evidence', JSON.stringify(open.evidence)]]} /></div>}
        {d && d.total > PAGE && <div className="row spread" style={{ marginTop: 12 }}><span className="muted small">{off + 1}–{Math.min(off + PAGE, d.total)} of {d.total}</span>
          <span className="row"><Button size="sm" disabled={off === 0} onClick={() => setOff(Math.max(0, off - PAGE))}>Previous</Button><Button size="sm" disabled={off + PAGE >= d.total} onClick={() => setOff(off + PAGE)}>Next</Button></span></div>}
      </Panel>
    </>
  )
}
