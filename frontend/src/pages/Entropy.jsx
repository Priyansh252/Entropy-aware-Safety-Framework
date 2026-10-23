import { useState } from 'react'
import { Bar, BarChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { post, f } from '../api.js'
import { Badge, Button, DataTable, ErrorNote, Field, Kv, Ledger, Notice, PageHead, Panel, useAction } from '../components/ui.jsx'

const KINDS = [['uniform', 'Uniform bytes'], ['biased', 'Biased distribution'], ['repeated_pattern', 'Repeated pattern'], ['repeated_values', 'Small set of repeated values'], ['constant', 'Constant byte'], ['nonce_reuse', 'Repeated 32-byte nonces']]
const IND = { very_small_alphabet: 'bad', long_constant_run: 'bad', repeated_blocks: 'warn', low_entropy_vs_ideal: 'bad', below_ideal_entropy: 'warn' }

export default function Entropy() {
  const [kind, setKind] = useState('uniform')
  const [size, setSize] = useState(4096)
  const [seed, setSeed] = useState('')
  const [bias, setBias] = useState(0.5)
  const [hex, setHex] = useState('')
  const one = useAction((body) => post('/entropy/assess', body))
  const cmp = useAction(() => post('/entropy/compare', { size: Math.min(size, 262144), seed: seed === '' ? 7 : Number(seed) }))
  const r = one.data
  const hist = r ? r.frequency.map((c, i) => ({ byte: i, count: c })) : []
  const analyze = () => one.run(hex.trim() ? { hex: hex.trim() } : { kind, size: Number(size), seed: seed === '' ? undefined : Number(seed), bias: Number(bias) })

  return (
    <>
      <PageHead title="Entropy analyzer">
        Measures the empirical byte-distribution entropy of a sample. This is a statistical indicator about one finite sample, not a security proof and not a nonce-reuse detector.
      </PageHead>
      <div className="grid g-side">
        <Panel title="Sample">
          <div className="stack">
            <Field label="Sample type"><select value={kind} onChange={(e) => setKind(e.target.value)} disabled={!!hex.trim()}>{KINDS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></Field>
            <Field label="Size (bytes)" hint="16 – 1,048,576"><input type="number" min="16" max="1048576" value={size} onChange={(e) => setSize(e.target.value)} /></Field>
            {kind === 'biased' && <Field label="Bias" hint="share of bytes drawn from 16 values"><input type="number" step="0.05" min="0" max="1" value={bias} onChange={(e) => setBias(e.target.value)} /></Field>}
            <Field label="Seed" hint="optional; makes synthetic samples repeatable"><input type="text" value={seed} onChange={(e) => setSeed(e.target.value.replace(/\D/g, ''))} placeholder="empty = OS randomness for uniform" /></Field>
            <Field label="Or paste bytes as hex" hint="overrides the type above"><textarea rows={3} value={hex} onChange={(e) => setHex(e.target.value)} placeholder="e.g. 3fa9 0c…" /></Field>
            <div className="row"><Button variant="primary" onClick={analyze} loading={one.loading}>Analyze sample</Button><Button onClick={cmp.run} loading={cmp.loading}>Compare all types</Button></div>
            <ErrorNote error={one.error || cmp.error} />
          </div>
        </Panel>
        <div className="stack">
          {!r ? <Panel><div className="empty"><h3>No sample analyzed</h3>Choose a sample type and select Analyze sample.</div></Panel> : (<>
            <Ledger items={[
              { label: 'Sample size', value: r.sample_size.toLocaleString() },
              { label: 'Shannon entropy (bits/byte)', value: f.num(r.shannon_bits_per_byte, 3) },
              { label: 'Normalized (÷ 8)', value: f.num(r.normalized_entropy, 3) },
              { label: 'Relative to ideal uniform', value: f.num(r.relative_to_ideal, 3) },
              { label: 'Distinct byte values', value: r.unique_byte_values },
            ]} />
            <Panel title="Byte-frequency distribution" aside={<span className="faint small">{r.meta.seeded_synthetic ? 'seeded synthetic sample' : 'OS or user-supplied data'}</span>}>
              <ResponsiveContainer width="100%" height={220}><BarChart data={hist} barCategoryGap={0}><CartesianGrid vertical={false} stroke="#e8ecf1" />
                <XAxis dataKey="byte" interval={31} /><YAxis allowDecimals={false} /><Tooltip labelFormatter={(v) => `byte 0x${Number(v).toString(16).padStart(2, '0')}`} />
                <ReferenceLine y={r.sample_size / 256} stroke="#a96a0b" strokeDasharray="4 3" label={{ value: 'uniform expectation', fontSize: 11, fill: '#a96a0b', position: 'insideTopRight' }} />
                <Bar dataKey="count" fill="#3b4cca" isAnimationActive={false} /></BarChart></ResponsiveContainer>
            </Panel>
            <div className="grid g2">
              <Panel title="Interpretation">
                <p>{r.interpretation}</p>
                <div className="row" style={{ marginBottom: 8 }}>{r.indicators.length ? r.indicators.map((i) => <Badge key={i} tone={IND[i]}>{i.replace(/_/g, ' ')}</Badge>) : <Badge tone="ok">no indicators raised</Badge>}</div>
                <Kv items={[['Ideal uniform entropy (this size)', `${f.num(r.expected_uniform_entropy, 3)} bits/byte`], ['Min-entropy', `${f.num(r.min_entropy_bits_per_byte, 3)} bits/byte`],
                  ['Longest run', r.longest_run], ['Repeated 32-byte blocks', `${r.duplicate_blocks.duplicate_blocks} of ${r.duplicate_blocks.blocks}`], ['Chi-square (255 d.f.)', f.num(r.chi_square, 1)]]} />
              </Panel>
              <Panel title="Statistical assessment ≠ cryptographic validation">
                <ul style={{ margin: 0, paddingLeft: 18 }}>{r.limitations.map((l) => <li key={l} className="small">{l}</li>)}</ul>
              </Panel>
            </div>
          </>)}
        </div>
      </div>
      {cmp.data && (
        <Panel title="Sample comparison" aside={<span className="faint small">{cmp.data.samples[0].sample_size} bytes each</span>}>
          <div className="grid g2">
            <ResponsiveContainer width="100%" height={240}><BarChart data={cmp.data.samples.map((s) => ({ name: s.kind.replace('_', ' '), bits: +s.shannon_bits_per_byte.toFixed(3) }))}><CartesianGrid vertical={false} stroke="#e8ecf1" />
              <XAxis dataKey="name" interval={0} fontSize={11} /><YAxis domain={[0, 8]} /><Tooltip /><ReferenceLine y={8} stroke="#7b8798" strokeDasharray="3 3" /><Bar dataKey="bits" name="bits/byte" fill="#3b4cca" radius={[3, 3, 0, 0]} /></BarChart></ResponsiveContainer>
            <DataTable rows={cmp.data.samples.map((s) => ({ id: s.kind, kind: s.kind.replace('_', ' '), h: s.shannon_bits_per_byte, rel: s.relative_to_ideal, dup: s.duplicate_blocks.duplicate_blocks, ind: s.indicators.join(', ') || '–' }))}
              columns={[{ key: 'kind', label: 'Type' }, { key: 'h', label: 'Bits/byte', num: true, render: (r) => f.num(r.h, 3) }, { key: 'rel', label: 'vs ideal', num: true, render: (r) => f.num(r.rel, 3) }, { key: 'dup', label: 'Repeated blocks', num: true }, { key: 'ind', label: 'Indicators' }]} />
          </div>
          <div style={{ marginTop: 12 }}><Notice tone="warn" title="Note">The repeated-nonce sample keeps a near-ideal byte entropy while half its 32-byte blocks are duplicates. Byte entropy alone would not catch it; the repeated-block check and signature analysis do.</Notice></div>
        </Panel>
      )}
    </>
  )
}
