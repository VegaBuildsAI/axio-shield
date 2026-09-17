// AXIO Shield Worker — router mismo-origen /shield/* (no rompe el CSP del sitio).
// El SDK se sirve desde Cloudflare Pages (p.ej. /shield-sdk/axio-shield.js); este Worker
// solo expone la API + WebSocket bajo /shield/*.
import { ShieldStore } from './store.js'
import { scanText } from './detection/server_scan.js'

export { ShieldStore }

const JSON_HEADERS = { 'Content-Type': 'application/json; charset=utf-8', 'X-Content-Type-Options': 'nosniff' }
const json = (body, status = 200, extraHeaders = {}) => new Response(JSON.stringify(body), { status, headers: { ...JSON_HEADERS, ...extraHeaders } })
const MAX_INGEST_BYTES = 32 * 1024
const MAX_TAP_BYTES = 16 * 1024
const RATE_WINDOW_MS = 60 * 1000
const RATE_LIMIT = 120
const MAX_RATE_BUCKETS = 2048
const rateBuckets = new Map()

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

function shieldMode(env) {
  // Enforcement is intentionally unavailable in this production increment.
  return 'observe'
}

function originAllowed(request, env) {
  const url = new URL(request.url)
  const origin = request.headers.get('Origin')
  if (!origin) return ['localhost', '127.0.0.1', '::1'].includes(url.hostname)
  const expected = String(env.PUBLIC_SITE_ORIGIN || url.origin).replace(/\/+$/, '')
  return origin === expected || origin === url.origin
}

function rateLimitKey(request) {
  return request.headers.get('CF-Connecting-IP') ||
    (request.headers.get('X-Forwarded-For') || '').split(',')[0].trim() || 'unknown'
}

function admitted(request) {
  const key = rateLimitKey(request)
  const current = Date.now()
  const bucket = rateBuckets.get(key)

  for (const [bucketKey, value] of rateBuckets) {
    if (current - value.started >= RATE_WINDOW_MS) rateBuckets.delete(bucketKey)
  }

  if (!bucket && rateBuckets.size >= MAX_RATE_BUCKETS) {
    const oldestKey = rateBuckets.keys().next().value
    if (oldestKey) rateBuckets.delete(oldestKey)
  }

  if (!bucket || current - bucket.started >= RATE_WINDOW_MS) {
    rateBuckets.set(key, { started: current, count: 1 })
    return true
  }
  if (bucket.count >= RATE_LIMIT) return false
  bucket.count++
  return true
}

async function readJson(request, maxBytes) {
  const raw = await request.text()
  if (new TextEncoder().encode(raw).byteLength > maxBytes) return { error: json({ ok: false, error: 'payload_too_large' }, 413) }
  try { return { value: JSON.parse(raw) } } catch { return { error: json({ ok: false, error: 'invalid_json' }, 400) } }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    const p = url.pathname.replace(/\/+$/, '') || '/'
    const s = store(env)

    try {
      if (p === '/shield/health') return json({ status: 'ok', mode: shieldMode(env), engine: 'deterministic', enforcement_enabled: false })

      if (p === '/shield/ingest' && request.method === 'POST') {
        if (!originAllowed(request, env)) return json({ ok: false, error: 'origin_not_allowed' }, 403)
        if (!admitted(request)) return json({ ok: false, error: 'rate_limited' }, 429, { 'Retry-After': '60' })
        const parsed = await readJson(request, MAX_INGEST_BYTES)
        if (parsed.error) return parsed.error
        const event = parsed.value
        if (!event || typeof event !== 'object' || Array.isArray(event)) return json({ ok: false, error: 'event_must_be_object' }, 400)
        return json(await s.ingest(event))
      }

      if (p === '/shield/tap' && request.method === 'POST') {
        if (!originAllowed(request, env)) return json({ ok: false, error: 'origin_not_allowed' }, 403)
        if (!admitted(request)) return json({ ok: false, error: 'rate_limited' }, 429, { 'Retry-After': '60' })
        const parsed = await readJson(request, MAX_TAP_BYTES)
        if (parsed.error) return parsed.error
        const req = parsed.value
        if (!req || typeof req !== 'object' || Array.isArray(req)) return json({ ok: false, error: 'request_must_be_object' }, 400)
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
        const parsed = await readJson(request, 8 * 1024)
        if (parsed.error) return parsed.error
        const { action, operator } = parsed.value || {}
        return json(await s.action(m[1], action, operator || 'analyst', shieldMode(env)))
      }

      if (p === '/shield/ws') return s.fetch(request)

      return json({ error: 'not_found', path: p }, 404)
    } catch (err) {
      return json({ ok: false, error: String(err && err.message || err) }, 500)
    }
  },
}
