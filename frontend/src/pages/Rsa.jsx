import { useState } from 'react'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Boxes, ScanSearch, Unlock, ShieldCheck } from 'lucide-react'
import { post, f } from '../api.js'
import { Badge, Button, DataTable, ErrorNote, Field, Ledger, Notice, PageHead, Panel, useAction, useToast } from '../components/ui.jsx'

function Graph({ n, edges, status }) {
  const R = 120, C = 150
  const pts = Array.from({ length: n }, (_, i) => [C + R * Math.cos((2 * Math.PI * i) / n - Math.PI / 2), C + R * Math.sin((2 * Math.PI * i) / n - Math.PI / 2)])
  return (
    <svg viewBox="0 0 300 300" width="100%" style={{ maxHeight: 320 }} role="img" aria-label="Modulus relationship graph">
      {edges.map((e, i) => <line key={i} x1={pts[e.a][0]} y1={pts[e.a][1]} x2={pts[e.b][0]} y2={pts[e.b][1]} stroke="#c2352b" strokeWidth="2"><title>{`keys ${e.a} and ${e.b} share a ${e.shared_factor_bits}-bit prime`}</title></line>)}
      {pts.map(([x, y], i) => { const bad = status?.[i] && status[i] !== 'ok'; return (
        <g key={i}><circle cx={x} cy={y} r="13" fill={bad ? '#fbe7e5' : '#fff'} stroke={bad ? '#c2352b' : '#7b8798'} strokeWidth="1.6" />
          <text x={x} y={y + 4} textAnchor="middle" fontSize="11" fill="#172033">{i}</text></g>) })}
    </svg>
  )
}

export default function Rsa() {
  const toast = useToast()
  const [n, setN] = useState(10)
  const [pairs, setPairs] = useState(2)
  const [bits, setBits] = useState(1024)
  const [col, setCol] = useState(null)
  const [scan, setScan] = useState(null)
  const [rec, setRec] = useState(null)
  const [cmp, setCmp] = useState(null)
  const [fault, setFault] = useState(0.25)
  const gen = useAction(async (p) => { const r = await post('/rsa/collection', { n_keys: Number(n), shared_pairs: p, key_bits: Number(bits) }); setCol(r); setScan(null); setRec(null); toast(p ? 'Collection with shared primes generated' : 'Normal collection generated'); return r })
  const sc = useAction(async () => { const r = await post('/rsa/scan', { collection_id: col.collection_id }); setScan(r); return r })
  const rc = useAction(async () => { const r = await post('/rsa/recover', { collection_id: col.collection_id }); setRec(r); toast(`${r.count} test keys rebuilt and verified`); return r })
  const df = useAction(async () => { const r = await post('/rsa/defended', { n_keys: 10, fault_probability: Number(fault), key_bits: Number(bits) }); setCmp(r); return r })
  const err = gen.error || sc.error || rc.error || df.error
  const status = scan ? Object.fromEntries(scan.findings.map((x) => [x.index, x.status])) : null
  const recIdx = rec ? Object.fromEntries(rec.recovered_keys.map((x) => [x.index, x])) : {}
  const rows = col ? col.keys.map((k) => { const s = scan?.findings[k.index]; return { id: k.index, ...k, status: s?.status, factor: s?.factor_preview, planted: s?.planted_vulnerable, rec: recIdx[k.index] } }) : []
  const cdata = cmp ? [['Candidates generated', 'candidates'], ['Candidates rejected', 'rejected_candidates'], ['Vulnerable keys accepted', 'vulnerable_final'], ['Keys factored by batch GCD', 'keys_factored_by_batch_gcd']].map(([name, k]) => ({ name, 'No defense': cmp.baseline[k], 'With safety layer': cmp.defended[k] })) : []

  return (
    <>
      <PageHead title="RSA shared-prime laboratory">
        Educational key sizes, locally generated test keys only. If two moduli share a prime, gcd(n₁, n₂) reveals it and both keys can be factored. Nothing here scans third-party keys.
      </PageHead>
      <div className="grid g-side">
        <Panel title="Controls">
          <div className="stack">
            <Field label="Keys in collection" hint="3 – 30"><input type="number" min="3" max="30" value={n} onChange={(e) => setN(e.target.value)} /></Field>
            <Field label="Key pairs sharing a prime" hint={`0 – ${Math.floor(n / 2)}`}><input type="number" min="0" max={Math.floor(n / 2)} value={pairs} onChange={(e) => setPairs(Math.min(Number(e.target.value), Math.floor(n / 2)))} /></Field>
            <Field label="Modulus size"><select value={bits} onChange={(e) => setBits(Number(e.target.value))}><option value={1024}>1024 bits (educational)</option><option value={2048}>2048 bits (slower)</option></select></Field>
            <Button icon={Boxes} loading={gen.loading} onClick={() => gen.run(0)}>Generate normal collection</Button>
            <Button variant="danger" icon={Boxes} loading={gen.loading} disabled={pairs < 1} onClick={() => gen.run(Number(pairs))}>Generate with shared primes</Button>
            <Button variant="primary" icon={ScanSearch} disabled={!col} loading={sc.loading} onClick={sc.run}>Run batch-GCD scan</Button>
            <Button icon={Unlock} disabled={!scan || !scan.flagged} loading={rc.loading} onClick={rc.run}>Recover and verify factors</Button>
            <hr style={{ border: 0, borderTop: '1px solid var(--line-2)', width: '100%' }} />
            <Field label="Prime-reuse fault rate" hint="simulated"><input type="number" step="0.05" min="0" max="0.9" value={fault} onChange={(e) => setFault(e.target.value)} /></Field>
            <Button icon={ShieldCheck} loading={df.loading} onClick={df.run}>Defended key generation comparison</Button>
            <ErrorNote error={err} />
          </div>
        </Panel>
        <div className="stack">
          {!col ? <Panel><div className="empty"><h3>No collection yet</h3>Generate a normal collection, or one with shared primes, to begin.</div></Panel> : (<>
            <Ledger items={[{ label: 'Keys', value: col.keys.length }, { label: 'Modulus size', value: `${col.key_bits} bits` }, { label: 'Planted sharing pairs', value: col.planted_shared_pairs },
              ...(scan ? [{ label: 'Flagged by batch GCD', value: scan.flagged, color: scan.flagged ? 'var(--bad)' : 'var(--ok)' }, { label: 'Detection rate', value: f.pct(scan.confusion.detection_rate.rate, 0) }, { label: 'False positives', value: scan.confusion.fp }] : [])]} />
            <div className="grid g2">
              <Panel title="Modulus relationships" aside={scan && <span className="faint small">red edge = shared prime</span>}>
                <Graph n={col.keys.length} edges={scan?.edges || []} status={status} />
                {!scan && <p className="faint small">Run the scan to reveal relationships.</p>}
              </Panel>
              <Panel title="Scan outcome">
                {scan ? (<div className="stack">
                  <Notice tone={scan.flagged ? 'bad' : 'ok'}>{scan.flagged ? `${scan.flagged} of ${scan.keys_scanned} moduli share a prime factor with another key in this collection.` : 'No shared primes found in this collection.'}</Notice>
                  <p className="small muted">Batch GCD ran in {f.ms(scan.batch_gcd_ms)}. Detection vs planted ground truth: TP {scan.confusion.tp}, FP {scan.confusion.fp}, TN {scan.confusion.tn}, FN {scan.confusion.fn}.</p>
                  <p className="small muted">{scan.scope_note}</p></div>) : <p className="muted">Scan not run yet.</p>}
              </Panel>
            </div>
            <Panel title="Keys" flush>
              <DataTable rows={rows} columns={[{ key: 'id', label: 'Key' }, { key: 'modulus_preview', label: 'Modulus', mono: true }, { key: 'modulus_bits', label: 'Bits', num: true },
                { key: 'status', label: 'Scan', render: (r) => r.status ? <Badge tone={r.status === 'ok' ? 'ok' : 'bad'}>{r.status === 'ok' ? 'no shared factor' : r.status.replace('_', ' ')}</Badge> : '–' },
                { key: 'factor', label: 'Shared factor', mono: true, render: (r) => r.factor || '–' },
                { key: 'rec', label: 'Recovered & verified', sortable: false, render: (r) => r.rec ? <Badge tone={r.rec.recovered && r.rec.matches_original ? 'bad' : 'warn'}>{r.rec.recovered && r.rec.matches_original ? 'private key rebuilt' : 'failed'}</Badge> : '–' }]} />
            </Panel>
            {rec && <Notice tone="info" title="Verification">{rec.verification}</Notice>}
          </>)}
          {cmp && (
            <Panel title="Defended vs undefended generation" aside={<Badge tone="info">simulated prime-reuse faults</Badge>}>
              <ResponsiveContainer width="100%" height={230}><BarChart data={cdata}><CartesianGrid vertical={false} stroke="#e8ecf1" /><XAxis dataKey="name" fontSize={11} interval={0} /><YAxis allowDecimals={false} /><Tooltip /><Legend />
                <Bar dataKey="No defense" fill="#c2352b" radius={[3, 3, 0, 0]} /><Bar dataKey="With safety layer" fill="#3b4cca" radius={[3, 3, 0, 0]} /></BarChart></ResponsiveContainer>
              <p className="small muted">Regenerations: {cmp.defended.regenerations}; fallbacks: {cmp.defended.fallbacks}; validation and decision time per key {f.ms(cmp.defended.mean_ms_per_key)} vs {f.ms(cmp.baseline.mean_ms_per_key)} undefended. Both draw pre-generated primes, so this excludes prime generation; see Experiments for overhead relative to real key generation. Generation-time validation compares each candidate with moduli already accepted; batch GCD above audits a population after the fact. They are complementary, not interchangeable.</p>
            </Panel>)}
        </div>
      </div>
    </>
  )
}
