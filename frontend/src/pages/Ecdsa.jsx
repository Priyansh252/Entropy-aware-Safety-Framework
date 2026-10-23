import { useState } from 'react'
import { KeyRound, PenLine, Repeat, Search, Unlock, ShieldCheck, BadgeCheck, Zap } from 'lucide-react'
import { post, f } from '../api.js'
import { Badge, Button, DataTable, DecisionBadge, ErrorNote, Field, Hex, Kv, Notice, PageHead, Panel, Trace, useAction, useToast } from '../components/ui.jsx'

const modeTone = (m) => (m.startsWith('EDUCATIONAL') ? 'bad' : m.startsWith('defended') ? 'info' : 'ok')

export default function Ecdsa() {
  const toast = useToast()
  const [sess, setSess] = useState(null)
  const [msg, setMsg] = useState('hello world')
  const [mode, setMode] = useState('secure')
  const [m1, setM1] = useState('pay Alice 10 EUR')
  const [m2, setM2] = useState('pay Mallory 9999 EUR')
  const [verifyId, setVerifyId] = useState('')
  const [detect, setDetect] = useState(null)
  const [recovery, setRecovery] = useState(null)
  const [defended, setDefended] = useState(null)
  const [verified, setVerified] = useState(null)
  const [reused, setReused] = useState(false)
  const [sel, setSel] = useState({})

  const sid = sess?.session_id
  const act = (fn, ok) => useAction(async (...a) => { const r = await fn(...a); if (ok) toast(ok); return r })
  const newKey = act(async () => { const s = await post('/ecdsa/session'); setSess(s); setDetect(null); setRecovery(null); setDefended(null); setVerified(null); setReused(false); return s }, 'Test key generated')
  const sign = act(async () => { const r = await post('/ecdsa/sign', { session_id: sid, message: msg, mode }); setSess(r.session); return r }, 'Message signed')
  const reuse = act(async () => { const r = await post('/ecdsa/reuse', { session_id: sid, message1: m1, message2: m2 }); setSess(r.session); setReused(true); return r }, 'Two messages signed with one nonce (educational mode)')
  const det = act(async () => { const r = await post('/ecdsa/detect', { session_id: sid }); setDetect(r); return r })
  const rec = act(async () => { const r = await post('/ecdsa/recover', { session_id: sid }); setRecovery(r.recovery); return r })
  const def = act(async () => { const r = await post('/ecdsa/defended', { session_id: sid, message1: m1, message2: m2 }); setSess(r.session); setDefended(r); return r }, 'Defended signing complete')
  const ver = act(async () => { const r = await post('/ecdsa/verify', { session_id: sid, signature_id: verifyId }); setVerified(r); return r })
  const full = act(async () => {
    const s = await post('/ecdsa/session'); setSess(s); setDefended(null); setVerified(null)
    const r = await post('/ecdsa/reuse', { session_id: s.session_id, message1: m1, message2: m2 }); setSess(r.session); setReused(true)
    setDetect(await post('/ecdsa/detect', { session_id: s.session_id }))
    setRecovery((await post('/ecdsa/recover', { session_id: s.session_id })).recovery)
    const d = await post('/ecdsa/defended', { session_id: s.session_id, message1: 'defended: ' + m1, message2: 'defended: ' + m2 }); setSess(d.session); setDefended(d)
    return d
  }, 'Full demonstration finished')
  const first = [newKey, sign, reuse, det, rec, def, ver, full].find((a) => a.error)
  const sigs = sess?.signatures || []
  const flow = [
    ['Generate test key', !!sess], ['Sign two messages, reused nonce', reused], ['Detect reuse', !!detect?.reuse_detected],
    ['Recover private key', !!recovery?.recovered], ['Verify recovery', !!(recovery?.matches_original && recovery?.forgery_verifies)], ['Compare with defended signing', !!defended],
  ]
  const ds = defended?.results

  return (
    <>
      <PageHead title="ECDSA nonce-reuse laboratory">
        NIST P-256 test keys only. Two signatures made with the same nonce let anyone solve for the private key. The vulnerable nonce is produced only by the clearly labelled educational control below.
      </PageHead>
      <div className="steps" aria-label="Attack workflow">{flow.map(([l, done], i) => (
        <div key={l} className={`step ${done ? 'done' : ''}`}><span className="no">{i + 1}</span><span>{l}</span></div>))}</div>
      <div className="grid g-side">
        <div className="stack">
          <Panel title="Controls">
            <div className="stack">
              <div className="row"><Button variant="primary" icon={KeyRound} loading={newKey.loading} onClick={newKey.run}>Generate test key</Button>
                <Button icon={Zap} loading={full.loading} onClick={full.run} title="Runs all steps in order">Run full demonstration</Button></div>
              <hr style={{ border: 0, borderTop: '1px solid var(--line-2)', width: '100%' }} />
              <b>Secure test signing</b>
              <Field label="Message"><input type="text" value={msg} maxLength={500} onChange={(e) => setMsg(e.target.value)} /></Field>
              <Field label="Signing mode"><select value={mode} onChange={(e) => setMode(e.target.value)}><option value="secure">Library, fresh random nonce</option><option value="deterministic">Library, deterministic (RFC 6979)</option></select></Field>
              <Button icon={PenLine} disabled={!sid || !msg} loading={sign.loading} onClick={sign.run}>Sign message</Button>
              <hr style={{ border: 0, borderTop: '1px solid var(--line-2)', width: '100%' }} />
              <Badge tone="bad">Educational attack mode</Badge>
              <Field label="Message 1"><input type="text" value={m1} maxLength={500} onChange={(e) => setM1(e.target.value)} /></Field>
              <Field label="Message 2" hint="must differ"><input type="text" value={m2} maxLength={500} onChange={(e) => setM2(e.target.value)} /></Field>
              <Button variant="danger" icon={Repeat} disabled={!sid || !m1 || !m2 || m1 === m2} loading={reuse.loading} onClick={reuse.run}>Sign both with a reused nonce</Button>
              <div className="row">
                <Button icon={Search} disabled={!sid} loading={det.loading} onClick={det.run}>Detect reuse</Button>
                <Button icon={Unlock} disabled={!sid} loading={rec.loading} onClick={rec.run}>Recover private key</Button>
              </div>
              <Button variant="primary" icon={ShieldCheck} disabled={!sid || m1 === m2} loading={def.loading} onClick={def.run}>Run defended signing</Button>
              <div className="row"><select aria-label="Signature to verify" value={verifyId} onChange={(e) => setVerifyId(e.target.value)} style={{ flex: 1 }}><option value="">Select signature…</option>{sigs.map((s) => <option key={s.id} value={s.id}>{s.id}: {s.message.slice(0, 22)}</option>)}</select>
                <Button icon={BadgeCheck} disabled={!verifyId} loading={ver.loading} onClick={ver.run}>Verify</Button></div>
              {verified && <Notice tone={verified.valid ? 'ok' : 'bad'}>Signature {verified.signature_id} is {verified.valid ? 'valid' : 'invalid'} under the public key.</Notice>}
              <ErrorNote error={first?.error} />
            </div>
          </Panel>
        </div>
        <div className="stack">
          {!sess ? <Panel><div className="empty"><h3>No test key yet</h3>Generate a test key, or run the full demonstration to see every step.</div></Panel> : (<>
            <Panel title="Test key and signatures" aside={<span className="faint small">session {sess.session_id}</span>}>
              <Kv items={[['Curve', sess.curve], ['Public key x', <Hex v={sess.public_key.x} n={34} />], ['Key fingerprint', <code>{sess.key_id}</code>]]} />
              <div style={{ marginTop: 12 }}>
                <DataTable defaultSort={null} rows={sigs.map((s) => ({ ...s }))} empty="No signatures yet." columns={[
                  { key: 'id', label: 'ID' }, { key: 'mode', label: 'Mode', render: (s) => <Badge tone={modeTone(s.mode)}>{s.mode.replace(/_/g, ' ')}</Badge> },
                  { key: 'message', label: 'Message' }, { key: 'r', label: 'r', render: (s) => <Hex v={s.r} n={12} /> }, { key: 's', label: 's', render: (s) => <Hex v={s.s} n={12} /> },
                  { key: 'verified', label: 'Verifies', render: (s) => <Badge tone={s.verified ? 'ok' : 'bad'}>{s.verified ? 'valid' : 'invalid'}</Badge> }]} />
              </div>
            </Panel>
            {detect && <Panel title="Nonce-reuse detection">
              {detect.reuse_detected ? <Notice tone="bad" title="Reuse detected">Signatures {detect.groups[0].signature_ids.join(' and ')} share r = <Hex v={detect.groups[0].r_hex} n={16} />, so they used the same nonce.</Notice> : <Notice tone="ok">No repeated r among {detect.signatures_checked} signatures.</Notice>}
              <p className="muted small" style={{ marginTop: 8 }}>{detect.method}</p></Panel>}
            {recovery && <Panel title="Private-key recovery" aside={<Badge tone={recovery.recovered ? 'bad' : 'ok'}>{recovery.recovered ? 'key recovered' : 'not recovered'}</Badge>}>
              {recovery.recovered ? (<>
                <Kv items={[['Recovered key (test, truncated)', <code>{recovery.recovered_key_preview}</code>], ['Recovered fingerprint', <code>{recovery.recovered_fingerprint}</code>], ['Original fingerprint', <code>{recovery.original_fingerprint}</code>],
                  ['Matches original', <Badge tone="ok">{String(recovery.matches_original)}</Badge>], ['d·G equals public key', <Badge tone="ok">{String(recovery.public_key_check)}</Badge>], ['Forged signature verifies', <Badge tone="bad">{String(recovery.forgery_verifies)}</Badge>]]} />
                <div className="eq">k = (z₁ − z₂)(s₁ − s₂)⁻¹ mod n<br />d = (s₁k − z₁) r⁻¹ mod n</div>
                <p className="muted small">With the same nonce, s₁ − s₂ = k⁻¹(z₁ − z₂), so k falls out of two public values, and then d follows from either signature. The recovered key signed a new message that the original public key accepts.</p>
              </>) : <Notice tone="ok">{recovery.reason}</Notice>}
            </Panel>}
            {defended && <Panel title="Defended signing" aside={<Badge tone="info">simulated stuck nonce source</Badge>}>
              <div className="stack">{ds.map((r, i) => (
                <div key={i}><div className="row spread"><b>{r.message}</b><span className="row"><DecisionBadge d={r.decision} /><Badge tone={r.verified ? 'ok' : 'bad'}>{r.verified ? 'signature valid' : 'no signature'}</Badge></span></div>
                  <Trace attempts={r.trace} selected={-1} onSelect={(a) => setSel({ ...sel, [i]: a })} />
                  <p className="muted small">{r.risk.recommended_action}</p></div>))}
                <Notice tone={defended.attack_attempt_recovered_key ? 'bad' : 'ok'} title="Attack attempt">{defended.attack_attempt_recovered_key ? 'The key was recovered.' : `Key recovery failed: ${defended.attack_reason}`}</Notice>
                <p className="muted small">The source keeps proposing the same nonce. The guard discards repeats before signing, regenerates up to the limit, then falls back to deterministic ECDSA (RFC 6979), which does not depend on fresh signing-time randomness. Deterministic signing does not fix a weakly generated private key.</p>
              </div></Panel>}
          </>)}
        </div>
      </div>
    </>
  )
}
