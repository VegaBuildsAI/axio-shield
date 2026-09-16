// AXIO Shield Worker — router mismo-origen /shield/* (no rompe el CSP del sitio).
// El SDK se sirve desde Cloudflare Pages (p.ej. /shield-sdk/axio-shield.js); este Worker
// solo expone la API + WebSocket bajo /shield/*.
import { ShieldStore } from './store.js'
import { scanText } from './detection/server_scan.js'

export { ShieldStore }

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff' }
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: JSON_HEADERS })

function store(env) {
  const id = env.SHIELD.idFromName('axio-shield-store')
  return env.SHIELD.get(id)
}

async function authorizeInternal(request, env) {
  const expected = String(env.SHIELD_INTERNAL_TOKEN || '')
  const provided = request.headers.get('Authorization') || ''
  if (!expected || !provided.startsWith('Bearer ')) return false
  return provided.slice(7).trim() === expected
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    const p = url.pathname.replace(/\/+$/, '') || '/'
    const s = store(env)

    try {
      if (p === '/shield/health') return json({ status: 'ok', stub_mode: !env.ANTHROPIC_API_KEY })

      if (p === '/shield/ingest' && request.method === 'POST') {
        const event = await request.json()
        return json(await s.ingest(event))
      }

      if (p === '/shield/tap' && request.method === 'POST') {
        const req = await request.json()
        const headers = Object.fromEntries(Object.entries(req.headers || {}).map(([k, v]) => [k.toLowerCase(), v]))
        const event = {
          session_id: req.session_id || headers['x-session-id'] || ('tap_' + crypto.randomUUID().slice(0, 12)),
          kind: 'xhr', path: req.path || '/', ua: headers['user-agent'] || '',
          client_matches: [], server_matches: scanText(req.body || ''),
          features: { body_len: (req.body || '').length }, extra: { source: 'waf_tap' },
        }
        return json(await s.ingest(event))
      }

      if (p === '/shield/api/incidents') return json(await s.listIncidents())
      if (p === '/shield/api/sessions') return json(await s.sessionsView())
      if (p === '/shield/api/coverage') return json(await s.coverage())
      if (p === '/shield/api/attack-graph') return json(await s.attackGraph())
      if (p === '/shield/api/audit/export') return json(await s.auditAll())
      if (p === '/shield/api/audit/verify') return json(await s.verifyChain())

      const m = p.match(/^\/shield\/api\/incidents\/([^/]+)\/action$/)
      if (m && request.method === 'POST') {
        if (!await authorizeInternal(request, env)) return json({ ok: false, error: 'unauthorized' }, 401)
        const { action, operator } = await request.json()
        return json(await s.action(m[1], action, operator || 'analyst'))
      }

      if (p === '/shield/ws') return s.fetch(request)

      return json({ error: 'not_found', path: p }, 404)
    } catch (err) {
      return json({ ok: false, error: String(err && err.message || err) }, 500)
    }
  },
}
