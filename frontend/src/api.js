const BASE = import.meta.env.VITE_API_BASE || ''

export async function api(path, { method = 'GET', body } = {}) {
  let res
  try {
    res = await fetch(`${BASE}/api${path}`, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new Error('Cannot reach the backend. Start it with run_project.bat (or python backend/app.py) and retry.')
  }
  let j
  try { j = await res.json() } catch { throw new Error(`Unexpected response from the server (HTTP ${res.status}).`) }
  if (!j.ok) throw new Error(j.error?.message || 'The request failed.')
  return j.data
}
export const post = (p, body = {}) => api(p, { method: 'POST', body })

export const f = {
  pct: (x, d = 1) => (x == null ? '–' : `${(x * 100).toFixed(d)}%`),
  num: (x, d = 2) => (x == null ? '–' : Number(x).toFixed(d)),
  ms: (x) => (x == null ? '–' : x < 1 ? `${x.toFixed(3)} ms` : `${x.toFixed(2)} ms`),
  short: (h, n = 14) => (h && h.length > n + 6 ? `${h.slice(0, n)}…${h.slice(-4)}` : h),
  time: (t) => (t ? new Date(t).toLocaleString() : ''),
  ci: (r) => (r && r.rate != null ? `${(r.rate * 100).toFixed(1)}% (95% CI ${(r.ci_low * 100).toFixed(1)}–${(r.ci_high * 100).toFixed(1)}, n=${r.n})` : '–'),
}
