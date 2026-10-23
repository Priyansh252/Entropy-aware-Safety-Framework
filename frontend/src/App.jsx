import { useEffect, useState } from 'react'
import { LayoutDashboard, Waves, KeyRound, Network, ShieldCheck, FlaskConical, ScrollText, BookOpen, PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import { api } from './api.js'
import { ToastProvider } from './components/ui.jsx'
import Overview from './pages/Overview.jsx'
import Entropy from './pages/Entropy.jsx'
import Ecdsa from './pages/Ecdsa.jsx'
import Rsa from './pages/Rsa.jsx'
import Safety from './pages/Safety.jsx'
import Experiments from './pages/Experiments.jsx'
import Audit from './pages/Audit.jsx'
import Methodology from './pages/Methodology.jsx'

const PAGES = [
  ['overview', 'Overview', LayoutDashboard, Overview],
  ['entropy', 'Entropy analyzer', Waves, Entropy],
  ['ecdsa', 'ECDSA laboratory', KeyRound, Ecdsa],
  ['rsa', 'RSA laboratory', Network, Rsa],
  ['safety', 'Safety engine', ShieldCheck, Safety],
  ['experiments', 'Experiments', FlaskConical, Experiments],
  ['audit', 'Audit log', ScrollText, Audit],
  ['method', 'Methodology', BookOpen, Methodology],
]

const Logo = () => (
  <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true">
    <rect width="32" height="32" rx="7" fill="#27355a" />
    <rect x="7" y="15" width="4" height="10" fill="#7f9cff" /><rect x="14" y="8" width="4" height="17" fill="#7f9cff" /><rect x="21" y="12" width="4" height="13" fill="#7f9cff" />
    <rect x="5" y="17" width="22" height="2.4" fill="#fff" />
  </svg>
)

export default function App() {
  const hashPage = () => (PAGES.find((p) => p[0] === location.hash.slice(1)) || PAGES[0])[0]
  const [page, setPage] = useState(hashPage())
  const [collapsed, setCollapsed] = useState(false)
  const [health, setHealth] = useState({ state: 'checking' })
  const [running, setRunning] = useState(null)

  useEffect(() => {
    const h = () => setPage(hashPage())
    window.addEventListener('hashchange', h)
    return () => window.removeEventListener('hashchange', h)
  }, [])
  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const [h, d] = await Promise.all([api('/health'), api('/dashboard')])
        if (alive) { setHealth({ state: 'ok', v: h.version }); setRunning(d.running[0] || null) }
      } catch (e) { if (alive) setHealth({ state: 'bad', msg: e.message }) }
    }
    tick()
    const t = setInterval(tick, 5000)
    return () => { alive = false; clearInterval(t) }
  }, [])

  const go = (k) => { location.hash = k }
  const [, title, , Page] = PAGES.find((p) => p[0] === page)
  return (
    <ToastProvider>
      <div className={`shell ${collapsed ? 'collapsed' : ''}`}>
        <aside className="side">
          <div className="brand"><Logo /><b>{!collapsed && <>Entropy-Aware<small>Safety Framework</small></>}</b></div>
          <nav className="nav" aria-label="Main">
            {PAGES.map(([k, label, Icon]) => (
              <button key={k} className={page === k ? 'on' : ''} onClick={() => go(k)} title={label} aria-current={page === k ? 'page' : undefined}>
                <Icon size={17} />{!collapsed && label}
              </button>))}
          </nav>
          <div className="side-foot"><button onClick={() => setCollapsed(!collapsed)} aria-label="Toggle sidebar">
            {collapsed ? <PanelLeftOpen size={17} /> : <><PanelLeftClose size={17} />Collapse</>}</button></div>
        </aside>
        <div className="main">
          <header className="top">
            <strong>{title}</strong>
            <div className="right">
              {running && <span><span className="dot run" />Experiment {Math.round(running.progress * 100)}%</span>}
              <span title={health.msg || ''}>
                <span className={`dot ${health.state === 'ok' ? 'ok' : health.state === 'bad' ? 'bad' : ''}`} />
                {health.state === 'ok' ? 'Backend connected' : health.state === 'bad' ? 'Backend unreachable' : 'Connecting…'}
              </span>
            </div>
          </header>
          <main className="content"><div className="page"><Page go={go} backendOk={health.state === 'ok'} /></div></main>
        </div>
      </div>
    </ToastProvider>
  )
}
