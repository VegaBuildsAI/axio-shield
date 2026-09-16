// Port JS del pipeline de agentes (backend/app/agents/*) — modo determinista (stub).
// Funciones puras sobre estado provisto por el Durable Object. Paridad con el backend Python.

import { mapOwasp } from './detection/rules.js'
import { frameworksFor } from './detection/frameworks.js'

const AUTONOMOUS_MARKERS = new Set([
  'agent_framework', 'agent.tool_poisoning', 'agent.memory_poisoning',
  'agent.scope_escape_attempt', 'agent.c2_migration', 'identity.cross_tenant',
])
const HIGH_VALUE_LABELS = new Set([
  'identity.privilege_escalation', 'identity.api_key_access',
  'data.exfiltration_canary', 'data.database_query_abuse',
])
const IDENTITY_LABELS = {
  'identity.cross_tenant': 'cruce_de_tenant',
  'identity.credential_access': 'acceso_a_credenciales',
  'identity.session_token_access': 'robo_de_token_de_sesion',
  'identity.api_key_access': 'acceso_a_api_key',
  'identity.privilege_escalation': 'escalada_de_privilegios',
}

// ---------- ORACLE ----------
export function profileFromRules(rules) {
  const s = new Set(rules)
  if (s.has('agent.a2a_spoof')) return 'A2A_HOSTILE'
  if (s.has('swarm.deaddrop')) return 'SWARM'
  if ([...AUTONOMOUS_MARKERS].some((m) => s.has(m))) return 'AUTONOMOUS'
  if (rules.some((r) => r.startsWith('automation.') && r !== 'automation.timing')) return 'AUTONOMOUS'
  if (s.has('ai_browser.ua')) return 'HUMAN_AI'
  return 'HUMAN'
}

export function urgencyFromScore(score) {
  if (score >= 0.9) return 'ELIMINATE'
  if (score >= 0.7) return 'CONTAIN'
  if (score >= 0.4) return 'WATCH'
  return 'INFO'
}

const RANK = { INFO: 0, WATCH: 1, CONTAIN: 2, ELIMINATE: 3 }
const bump = (u, min) => (RANK[u] < RANK[min] ? min : u)

export function classify(signal) {
  const [owasp, owaspName] = mapOwasp(signal.matched)
  return {
    owasp, owasp_name: owaspName,
    attacker_profile: profileFromRules(signal.matched),
    urgency: urgencyFromScore(signal.score),
    confidence: signal.score,
    rationale: `Reglas disparadas: ${signal.matched.join(', ')}.`,
    frameworks: frameworksFor(signal.matched),
  }
}

// ---------- TRACKER++ : swarm ----------
export function assessSwarm(recent, minSessions) {
  const anomalous = recent.filter((e) => e.score > 0)
  const order = []
  for (const e of anomalous) if (!order.includes(e.session_id)) order.push(e.session_id)
  const deaddrop = new Set(anomalous.filter((e) => e.matched_rules.includes('swarm.deaddrop')).map((e) => e.session_id))
  const labelSessions = {}
  for (const e of anomalous) for (const l of e.matched_rules) (labelSessions[l] ??= new Set()).add(e.session_id)
  const sharedTtp = Object.entries(labelSessions).filter(([, ss]) => ss.size >= 2).map(([l]) => l)
  const coordinated = order.length >= minSessions && (deaddrop.size > 0 || sharedTtp.length > 0)
  if (!coordinated) return { coordinated: false, session_ids: order }
  const counts = {}
  for (const e of anomalous) counts[e.session_id] = (counts[e.session_id] || 0) + 1
  const c2 = Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0]
  const roles = {}
  for (const sid of order) {
    if (deaddrop.has(sid)) roles[sid] = 'exfiltrator'
    else if (sid === order[0]) roles[sid] = 'exploiter'
    else if (sid === c2) roles[sid] = 'C2_manager'
    else roles[sid] = 'recruiter'
  }
  return {
    coordinated: true, session_ids: order, roles,
    c2_indicator: deaddrop.size ? 'dead-drops en campos libres del portal' : `TTP compartido: ${sharedTtp.sort()}`,
    confidence: Math.round(Math.min(0.95, 0.5 + 0.1 * order.length) * 1000) / 1000,
  }
}

// ---------- TRACKER++ : kill-chain ----------
export function assessKillchain(timeline) {
  const phases = []
  for (const e of timeline) if (e.phase && !phases.includes(e.phase)) phases.push(e.phase)
  const techniques = []
  for (const e of timeline) for (const r of e.rules) if (!techniques.includes(r)) techniques.push(r)
  let adaptive = false, detected = false
  const seen = new Set()
  for (const e of timeline) {
    const rules = new Set(e.rules)
    if (detected && [...rules].some((r) => !seen.has(r))) adaptive = true
    if (rules.size) detected = true
    for (const r of rules) seen.add(r)
  }
  return {
    phases, techniques, escalating: phases.length >= 3, adaptive_evasion: adaptive,
    confidence: Math.round(Math.min(0.95, 0.4 + 0.15 * phases.length) * 1000) / 1000,
  }
}

// ---------- TRACKER++ : attack-path (BloodHound-style) ----------
export function assessAttackPath(recent) {
  const anomalous = recent.filter((e) => e.score > 0)
  if (!anomalous.length) return { nodes: [], edges: [], lateral_movement: false, compromise_reached: false, shortest_path: [] }
  const nodes = new Map(); const edges = []
  const node = (id, kind, label) => { if (!nodes.has(id)) nodes.set(id, { id, kind, label }) }
  const identitySessions = {}; const compromise = new Set()
  for (const e of anomalous) {
    const sid = 's:' + e.session_id
    node(sid, 'session', e.session_id.slice(0, 12))
    const tech = e.matched_rules.join(','); const phase = e.phase || ''
    if (e.identity) {
      const nid = 'i:' + e.identity
      node(nid, 'identity', e.identity)
      edges.push({ src: nid, dst: sid, phase, technique: tech });
      (identitySessions[e.identity] ??= new Set()).add(sid)
    }
    const tgt = 't:' + (e.target || '/')
    node(tgt, 'target', e.target || '/')
    edges.push({ src: sid, dst: tgt, phase, technique: tech })
    if (e.matched_rules.some((r) => HIGH_VALUE_LABELS.has(r))) compromise.add(tgt)
  }
  const lateral = Object.values(identitySessions).some((s) => s.size >= 2)
  const reached = compromise.size > 0
  let shortest = []
  if (reached) {
    const adj = {}
    for (const ed of edges) (adj[ed.src] ??= []).push(ed.dst)
    const starts = [...nodes.keys()].filter((n) => n.startsWith('i:'))
    const pool = starts.length ? starts : [...nodes.keys()].filter((n) => n.startsWith('s:'))
    for (const start of pool) {
      const q = [[start]]; const seen = new Set([start])
      while (q.length) {
        const path = q.shift()
        if (compromise.has(path[path.length - 1])) { shortest = path; break }
        for (const nx of adj[path[path.length - 1]] || []) if (!seen.has(nx)) { seen.add(nx); q.push([...path, nx]) }
      }
      if (shortest.length) break
    }
  }
  return { nodes: [...nodes.values()], edges, lateral_movement: lateral, compromise_reached: reached, shortest_path: shortest }
}

// ---------- WARDEN ----------
export function wardenEnrich(incident, extra = {}) {
  const matched = new Set(incident.matched_rules)
  const findings = []
  const tool = extra.tool_fixture
  if (matched.has('tool.high_impact_call')) findings.push({ type: 'tool_high_impact', tool: tool || 'desconocida', status: 'llamada_de_alto_impacto' })
  else if (extra.mutation || matched.has('agent.tool_poisoning')) findings.push({ type: 'tool_poisoning', tool: tool || 'desconocida', status: 'metadata_mutada' })
  if (matched.has('agent.memory_poisoning') || String(extra.memory_scope || '').startsWith('shared'))
    findings.push({ type: 'memory_poisoning', status: 'escritura_sin_procedencia' })
  if (matched.has('agent.scope_escape_attempt')) findings.push({ type: 'scope_escape', status: 'intento_de_salir_del_sandbox' })
  if (!findings.length) return
  incident.integrity_verdict = { findings, by: 'WARDEN' }
  incident.urgency = bump(incident.urgency, 'CONTAIN')
  incident.rationale += ' | WARDEN: ' + findings.map((f) => `${f.type}:${f.status}`).join('; ')
}

// ---------- SPECTER ----------
export function specterEnrich(incident, extra = {}) {
  const matched = new Set(incident.matched_rules)
  const findings = []
  const src = extra.source_tenant, req = extra.requested_tenant
  if (src && req && src !== req && (!extra.credential_material || extra.credential_material === 'never-sent'))
    findings.push({ type: 'cross_tenant', status: 'acceso_cross_tenant_sin_credencial' })
  else if (matched.has('identity.cross_tenant')) findings.push({ type: 'cross_tenant', status: 'cruce_de_tenant_detectado' })
  const agentId = extra.agent_id
  const VERIFIED = new Set(['axio.portal.frontend', 'axio.soc.dashboard'])
  if (matched.has('agent.a2a_spoof') || (agentId && !VERIFIED.has(agentId)))
    findings.push({ type: 'a2a_spoof', status: 'identidad_no_verificada' })
  const idHits = [...matched].filter((m) => IDENTITY_LABELS[m]).map((m) => IDENTITY_LABELS[m])
  if (idHits.length) findings.push({ type: 'identity_abuse', status: [...new Set(idHits)].sort().join(', ') })
  if (!findings.length) return
  incident.identity_verdict = { findings, identity_verified: false, by: 'SPECTER' }
  if (findings.some((f) => f.type === 'a2a_spoof' || f.type === 'cross_tenant')) incident.attacker_profile = 'A2A_HOSTILE'
  incident.urgency = bump(incident.urgency, 'CONTAIN')
  incident.rationale += ' | SPECTER: ' + findings.map((f) => `${f.type}:${f.status}`).join('; ')
}

export { bump, HIGH_VALUE_LABELS }
