import { createContext, useContext, useMemo, useState, useCallback } from 'react'
import { Loader2, AlertTriangle, CheckCircle2, Info, ChevronUp, ChevronDown, XCircle } from 'lucide-react'

export const cx = (...a) => a.filter(Boolean).join(' ')

export function useAction(fn) {
  const [s, set] = useState({ loading: false, error: null, data: null })
  const run = useCallback(async (...args) => {
    set((x) => ({ ...x, loading: true, error: null }))
    try { const data = await fn(...args); set({ loading: false, error: null, data }); return data }
    catch (e) { set((x) => ({ ...x, loading: false, error: e.message })); return null }
  }, [fn])
  return { ...s, run, reset: () => set({ loading: false, error: null, data: null }) }
}

const ToastCtx = createContext(() => {})
export const useToast = () => useContext(ToastCtx)
export function ToastProvider({ children }) {
  const [items, setItems] = useState([])
  const push = useCallback((msg, tone) => {
    const id = Math.random()
    setItems((x) => [...x, { id, msg, tone }])
    setTimeout(() => setItems((x) => x.filter((i) => i.id !== id)), 4000)
  }, [])
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((i) => <div key={i.id} className={cx('toast', i.tone)}>{i.msg}</div>)}
      </div>
    </ToastCtx.Provider>
  )
}

export const Panel = ({ title, aside, children, flush, className }) => (
  <section className={cx('panel', className)}>
    {(title || aside) && <header><h2>{title}</h2><div className="row">{aside}</div></header>}
    <div className={cx('body', flush && 'flush')}>{children}</div>
  </section>
)

export const Button = ({ children, onClick, loading, variant, disabled, icon: Icon, size, title, type = 'button' }) => (
  <button type={type} title={title} className={cx('btn', variant, size)} onClick={onClick} disabled={disabled || loading}>
    {loading ? <Loader2 size={15} className="spin" /> : Icon ? <Icon size={15} /> : null}{children}
  </button>
)

export const Badge = ({ tone, children }) => <span className={cx('badge', tone)}>{children}</span>

export const Field = ({ label, hint, children }) => (
  <label className="f"><span>{label}{hint && <span className="hint"> {hint}</span>}</span>{children}</label>
)

const NI = { info: Info, warn: AlertTriangle, bad: XCircle, ok: CheckCircle2 }
export function Notice({ tone = 'info', title, children }) {
  const I = NI[tone]
  return <div className={cx('notice', tone)} role={tone === 'bad' ? 'alert' : undefined}><I size={16} /><div>{title && <b>{title}. </b>}{children}</div></div>
}
export const ErrorNote = ({ error }) => (error ? <Notice tone="bad" title="Something went wrong">{error}</Notice> : null)

export const Empty = ({ title, children, action }) => (
  <div className="empty"><h3>{title}</h3><div>{children}</div>{action && <div className="row">{action}</div>}</div>
)

export const Ledger = ({ items }) => (
  <div className="ledger">{items.map((i) => (
    <div key={i.label}><div className="v" style={i.color ? { color: i.color } : null}>{i.value}</div><div className="l">{i.label}</div></div>
  ))}</div>
)

export function Tabs({ tabs, value, onChange }) {
  return <div className="tabs" role="tablist">{tabs.map(([k, l]) => (
    <button key={k} role="tab" aria-selected={value === k} className={value === k ? 'on' : ''} onClick={() => onChange(k)}>{l}</button>
  ))}</div>
}

export const decisionTone = { ACCEPT: 'ok', REGENERATE: 'warn', SAFE_FALLBACK: 'info', REJECT: 'bad' }
export const categoryTone = { Low: 'ok', Moderate: 'warn', High: 'bad', Critical: 'crit' }
export const DecisionBadge = ({ d }) => <Badge tone={decisionTone[d]}>{d?.replace('_', ' ')}</Badge>
export const CategoryBadge = ({ c }) => <Badge tone={categoryTone[c]}>{c}</Badge>

export function DataTable({ columns, rows, empty = 'No rows', onRowClick, selected, defaultSort, sortable = true }) {
  const [sort, setSort] = useState(defaultSort || null)
  const sorted = useMemo(() => {
    if (!sort) return rows
    const { key, dir } = sort
    return [...rows].sort((a, b) => {
      const x = a[key], y = b[key]
      if (x == null) return 1
      if (y == null) return -1
      return (x > y ? 1 : x < y ? -1 : 0) * (dir === 'asc' ? 1 : -1)
    })
  }, [rows, sort])
  if (!rows.length) return <div className="empty small">{empty}</div>
  return (
    <div className="scroll-x"><table className="t">
      <thead><tr>{columns.map((c) => {
        const can = sortable && c.sortable !== false
        const on = sort?.key === c.key
        return <th key={c.key} className={cx(can && 'sortable', c.num && 'num')}
          onClick={can ? () => setSort({ key: c.key, dir: on && sort.dir === 'desc' ? 'asc' : 'desc' }) : undefined}
          aria-sort={on ? (sort.dir === 'asc' ? 'ascending' : 'descending') : undefined}>
          {c.label}{on && (sort.dir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}</th>
      })}</tr></thead>
      <tbody>{sorted.map((r, i) => (
        <tr key={r.id ?? i} className={cx(onRowClick && 'click', selected === (r.id ?? i) && 'sel')} onClick={onRowClick ? () => onRowClick(r) : undefined}>
          {columns.map((c) => <td key={c.key} className={cx(c.num && 'num', c.mono && 'mono')}>{c.render ? c.render(r) : r[c.key]}</td>)}
        </tr>))}</tbody>
    </table></div>
  )
}

export function Gauge({ score, category, hardFail, bounds = { low: 25, moderate: 50, high: 75 } }) {
  return (
    <div>
      <div className="row spread" style={{ marginBottom: 2 }}>
        <span className="muted small">Risk score {hardFail && '(forced by a hard-fail rule)'}</span><CategoryBadge c={category} />
      </div>
      <div className="gauge" role="img" aria-label={`Risk score ${score} of 100, ${category}`}>
        <div className="mark" style={{ left: `${Math.min(99, Math.max(1, score))}%` }}>{score}</div>
        <div className="bar"><div className="seg s1" /><div className="seg s2" /><div className="seg s3" /><div className="seg s4" /></div>
        <div className="scale"><span>0</span><span>{bounds.low}</span><span>{bounds.moderate}</span><span>{bounds.high}</span><span>100</span></div>
      </div>
    </div>
  )
}

export function Trace({ attempts, selected, onSelect }) {
  return (
    <div className="rail" role="list">{attempts.map((a, i) => (
      <div key={i} style={{ display: 'flex' }} role="listitem">
        {i > 0 && <div className="link" />}
        <button className={cx('node', selected === i && 'on')} onClick={() => onSelect(i)} style={{ font: 'inherit' }}>
          <div className="n-title">Attempt {a.attempt}</div>
          <DecisionBadge d={a.decision} />
          <div className="n-score">score {a.risk_score}{a.hard_fail ? ' · hard-fail' : ''}</div>
        </button>
      </div>))}
    </div>
  )
}

export function FactorTable({ factors }) {
  return (
    <DataTable sortable={false} rows={factors.map((x, i) => ({ ...x, id: i }))} columns={[
      { key: 'name', label: 'Factor', render: (r) => <span><b>{r.name.replace(/_/g, ' ')}</b> {r.kind === 'hard_fail' && <Badge tone="crit">hard fail</Badge>}</span> },
      { key: 'points', label: 'Points', num: true, render: (r) => r.points == null ? '–' : (
        <div className="bar-cell" style={{ justifyContent: 'flex-end' }}><i style={{ width: `${(r.points / (r.weight || 1)) * 46}px` }} />{r.points}/{r.weight}</div>) },
      { key: 'explanation', label: 'Why' },
    ]} />
  )
}

export function Kv({ items }) {
  return <dl className="kv">{items.filter(Boolean).map(([k, v]) => <><dt key={k}>{k}</dt><dd key={k + 'v'}>{v}</dd></>)}</dl>
}
export const Hex = ({ v, n = 18 }) => <code title={v}>{v && v.length > n + 6 ? `${v.slice(0, n)}…${v.slice(-4)}` : v}</code>
export const Progress = ({ value }) => <div className="progress" role="progressbar" aria-valuenow={Math.round(value * 100)}><i style={{ width: `${value * 100}%` }} /></div>
export const PageHead = ({ title, children }) => <div className="page-head"><h1>{title}</h1><p>{children}</p></div>
