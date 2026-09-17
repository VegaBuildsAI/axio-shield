// ShieldStore — Durable Object (SQLite) que persiste y orquesta el pipeline defensivo.
// Espejo de backend/app/store.py + el coordinador de main.py. Estado vivo + audit hash-chained.
import { DurableObject } from 'cloudflare:workers'
import { scoreEvent, detectionTrust } from './detection/rules.js'
import * as P from './pipeline.js'
import { coverageMatrix } from './reporting.js'

const GENESIS = '0'.repeat(64)
const WINDOW_SECS = 120
const MIN_SESSIONS = 2

function canonical(v) {
  // Match JSON.stringify semantics while keeping deterministic key ordering:
  // undefined object properties are omitted and undefined array entries become null.
  if (Array.isArray(v)) return '[' + v.map((item) => item === undefined ? 'null' : canonical(item)).join(',') + ']'
  if (v && typeof v === 'object') return '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}'
  return JSON.stringify(v)
}
async function sha256hex(s) {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('')
}
const uuid = () => crypto.randomUUID().replace(/-/g, '')
const now = () => Date.now() / 1000

export class ShieldStore extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env)
    this.sql = ctx.storage.sql
    this.sockets = new Set()
    this.sessions = {}
    this.eventWindow = []
    this.incidents = []
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(`CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, ts REAL, agent TEXT,
        action TEXT, subject_id TEXT, payload TEXT, prev_hash TEXT, hash TEXT);`)
      this.sql.exec(`CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, ts REAL, data TEXT);`)
      for (const r of this.sql.exec('SELECT data FROM incidents ORDER BY ts ASC')) {
        try { this.incidents.push(JSON.parse(r.data)) } catch { /* skip */ }
      }
    })
  }

  // ---------- audit (hash chain) + broadcast de "defensa" ----------
  async record(agent, action, subject_id, payload) {
    const last = [...this.sql.exec('SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1')][0]
    const prev_hash = last ? last.hash : GENESIS
    const seq = last ? last.seq + 1 : 1
    const ts = now()
    const hash = await sha256hex(canonical({ prev: prev_hash, seq, ts, agent, action, subject: subject_id, payload }))
    this.sql.exec('INSERT INTO audit (seq,ts,agent,action,subject_id,payload,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?)',
      seq, ts, agent, action, subject_id, JSON.stringify(payload), prev_hash, hash)
    this.broadcast({ type: 'defense', agent, action, subject_id, ts })
    return { seq, hash }
  }

  auditAll() {
    return [...this.sql.exec('SELECT * FROM audit ORDER BY seq ASC')].map((r) => ({ ...r, payload: JSON.parse(r.payload) }))
  }
  async verifyChain() {
    let prev = GENESIS
    for (const rec of this.auditAll()) {
      const expected = await sha256hex(canonical({ prev, seq: rec.seq, ts: rec.ts, agent: rec.agent, action: rec.action, subject: rec.subject_id, payload: rec.payload }))
      if (rec.prev_hash !== prev || rec.hash !== expected) return { valid: false, broken_at_seq: rec.seq }
      prev = rec.hash
    }
    return { valid: true, broken_at_seq: null }
  }

  // ---------- estado vivo ----------
  addEvent(event, matched, score) {
    const extra = event.extra || {}
    const phase = String(extra.phase || '').toLowerCase()
    const identity = extra.agent_id || extra.identity || (extra.token ? 'token:' + extra.token : null)
    const target = extra.target || event.path || '/'
    const s = (this.sessions[event.session_id] ??= { first_seen: event.ts, event_count: 0, paths: new Set(), uas: new Set(), max_score: 0, timeline: [] })
    s.last_seen = event.ts; s.event_count++; s.paths.add(event.path); s.uas.add(event.ua)
    s.max_score = Math.max(s.max_score, score)
    s.timeline.push({ ts: event.ts, phase, rules: [...matched], score })
    this.eventWindow.push({ ts: event.ts, session_id: event.session_id, path: event.path, matched_rules: [...matched], score, identity, target, phase })
    const cutoff = now() - WINDOW_SECS
    this.eventWindow = this.eventWindow.filter((e) => e.ts >= cutoff)
  }
  recentEvents() {
    const cutoff = now() - WINDOW_SECS
    return this.eventWindow.filter((e) => e.ts >= cutoff)
  }
  addIncident(inc) {
    this.incidents.push(inc); this.incidents = this.incidents.slice(-500)
    this.sql.exec('INSERT OR REPLACE INTO incidents (id,ts,data) VALUES (?,?,?)', inc.id, inc.ts, JSON.stringify(inc))
  }
  updateIncident(inc) { this.sql.exec('INSERT OR REPLACE INTO incidents (id,ts,data) VALUES (?,?,?)', inc.id, inc.ts, JSON.stringify(inc)) }

  // ---------- pipeline completo (SENTINEL→ORACLE→TRACKER→WARDEN→SPECTER→HERALD→SCRIBE) ----------
  async ingest(event) {
    event.kind ??= 'dom_event'
    event.extra ??= {}
    event.features ??= {}
    event.ts ??= now(); event.event_id ??= uuid()
    const { score, matched } = scoreEvent(event)
    this.addEvent(event, matched, score)
    await this.record('SENTINEL', 'scored', event.event_id, { session: event.session_id, score, rules: matched, kind: event.kind })
    const trust = detectionTrust(event)
    if (!matched.length) return { ok: true, score, matched_rules: [], trust }

    const cls = P.classify({ score, matched })
    const inc = {
      id: uuid(), ts: now(), session_id: event.session_id, kind: event.kind || 'dom_event',
      path: event.path || '/', ua: event.ua || '', score, matched_rules: matched,
      ...cls, trust, evidence: { extra: event.extra || {}, features: event.features || {} },
      status: 'open', actions: [],
    }
    await this.record('ORACLE', 'classified', inc.id, { session: inc.session_id, owasp: inc.owasp, profile: inc.attacker_profile, urgency: inc.urgency, trust })

    // TRACKER++ swarm
    const swarm = P.assessSwarm(this.recentEvents(), MIN_SESSIONS)
    if (swarm.coordinated) {
      inc.swarm = swarm; inc.attacker_profile = 'SWARM'; inc.urgency = P.bump(inc.urgency, 'CONTAIN')
      await this.record('TRACKER', 'swarm_detected', inc.id, { sessions: swarm.session_ids, roles: swarm.roles })
    }
    // TRACKER++ kill-chain
    const kc = P.assessKillchain(this.sessions[inc.session_id]?.timeline || [])
    if (kc.escalating || kc.adaptive_evasion) {
      inc.killchain = kc
      inc.urgency = (kc.adaptive_evasion && kc.escalating) ? 'ELIMINATE' : P.bump(inc.urgency, 'CONTAIN')
      if (['HUMAN', 'UNKNOWN'].includes(inc.attacker_profile)) inc.attacker_profile = 'AUTONOMOUS'
      await this.record('TRACKER', 'killchain_detected', inc.id, { phases: kc.phases, adaptive_evasion: kc.adaptive_evasion })
    }
    // TRACKER++ attack-path
    const path = P.assessAttackPath(this.recentEvents())
    if (path.lateral_movement || path.compromise_reached) {
      inc.attack_path = path
      inc.urgency = path.compromise_reached ? 'ELIMINATE' : P.bump(inc.urgency, 'CONTAIN')
      await this.record('TRACKER', 'attack_path_detected', inc.id, { lateral_movement: path.lateral_movement, compromise_reached: path.compromise_reached, shortest_path: path.shortest_path })
    }
    // WARDEN + SPECTER
    P.wardenEnrich(inc, inc.evidence.extra)
    if (inc.integrity_verdict) await this.record('WARDEN', 'integrity_verdict', inc.id, { findings: inc.integrity_verdict.findings })
    P.specterEnrich(inc, inc.evidence.extra)
    if (inc.identity_verdict) await this.record('SPECTER', 'identity_verdict', inc.id, { findings: inc.identity_verdict.findings })

    this.addIncident(inc)
    await this.record('HERALD', 'alert', inc.id, { urgency: inc.urgency, owasp: inc.owasp })
    this.broadcast({ type: 'incident', incident: inc })
    return { ok: true, score, matched_rules: matched, trust, incident_id: inc.id }
  }

  async action(incidentId, actionName, operator, mode = 'observe') {
    const inc = [...this.incidents].reverse().find((i) => i.id === incidentId)
    const ACTIONS = { rate_limit: 'Rate-limiting dinámico', block_session: 'Sandbox/bloqueo de sesión', revoke_token: 'Revocación de token', dismiss: 'Descartar (falso positivo)' }
    if (!inc || !ACTIONS[actionName]) return { ok: false, error: 'incidente o acción inválida' }
    const observeOnly = mode !== 'enforce'
    inc.actions.push({ action: actionName, description: ACTIONS[actionName], operator, ts: now(), simulated: observeOnly, observe_only: observeOnly })
    // Observe mode records the operator intent but never claims containment.
    if (actionName === 'dismiss') inc.status = 'dismissed'
    else if (!observeOnly) inc.status = 'contained'
    this.updateIncident(inc)
    await this.record('LOCKDOWN', 'human_gate_action', inc.id, { action: actionName, operator, mode, enforced: !observeOnly, new_status: inc.status })
    this.broadcast({ type: 'update', incident: inc })
    return { ok: true, mode, observe_only: observeOnly, incident: inc }
  }

  listIncidents() { return [...this.incidents].reverse() }
  sessionsView() {
    return Object.entries(this.sessions).map(([sid, s]) => ({ session_id: sid, first_seen: s.first_seen, last_seen: s.last_seen, event_count: s.event_count, max_score: s.max_score, paths: [...s.paths] }))
  }
  coverage() {
    const exercised = new Set()
    for (const i of this.incidents) for (const r of i.matched_rules) exercised.add(r)
    return coverageMatrix(exercised)
  }
  attackGraph() { return P.assessAttackPath(this.recentEvents()) }

  // ---------- WebSocket ----------
  broadcast(msg) {
    const s = JSON.stringify(msg)
    for (const ws of [...this.sockets]) { try { ws.send(s) } catch { this.sockets.delete(ws) } }
  }
  fetch(request) {
    if (request.headers.get('Upgrade') === 'websocket') {
      const pair = new WebSocketPair()
      const [client, server] = Object.values(pair)
      server.accept()
      this.sockets.add(server)
      server.send(JSON.stringify({ type: 'snapshot', incidents: this.listIncidents() }))
      server.addEventListener('close', () => this.sockets.delete(server))
      server.addEventListener('error', () => this.sockets.delete(server))
      return new Response(null, { status: 101, webSocket: client })
    }
    return new Response('shield-store', { status: 200 })
  }
}
