// Port JS de backend/app/detection/rules.py — MISMO vocabulario de labels (paridad).
// Determinista antes que LLM. server_matches (autoritativo) + client_matches (hint) + UA + features.

export const UA_SIGNATURES = {
  'ai_browser.ua': ['gptbot', 'chatgpt-user', 'oai-searchbot', 'operator', 'perplexitybot',
    'perplexity-user', 'claudebot', 'claude-user', 'anthropic', 'google-extended', 'ccbot', 'bytespider'],
  'automation.headless': ['headlesschrome', 'phantomjs', 'puppeteer', 'playwright', 'selenium'],
  'automation.client': ['python-requests', 'python-httpx', 'curl/', 'wget/', 'go-http-client',
    'node-fetch', 'axios/', 'aiohttp'],
  'agent_framework': ['langchain', 'crewai', 'browser-use', 'autogpt', 'llamaindex', 'openai-agents'],
}

export const RULE_WEIGHTS = {
  'prompt_injection.instruction_override': 0.85,
  'prompt_injection.role_hijack': 0.80,
  'prompt_injection.exfil': 0.80,
  'xss.script': 0.80,
  'sqli': 0.80,
  'ssrf': 0.75,
  'swarm.deaddrop': 0.55,
  'ai_browser.ua': 0.50,
  'automation.headless': 0.55,
  'automation.client': 0.45,
  'agent_framework': 0.65,
  'automation.timing': 0.40,
  'agent.tool_poisoning': 0.80,
  'agent.memory_poisoning': 0.75,
  'identity.cross_tenant': 0.90,
  'agent.scope_escape_attempt': 0.90,
  'agent.c2_migration': 0.65,
  'agent.a2a_spoof': 0.80,
  'identity.credential_access': 0.85,
  'identity.session_token_access': 0.90,
  'identity.api_key_access': 0.90,
  'data.database_query_abuse': 0.85,
  'identity.privilege_escalation': 0.90,
  'tool.high_impact_call': 0.80,
  'data.exfiltration_canary': 0.90,
  'recon.enumeration': 0.50,
  'identity.lateral_movement': 0.85,
  'persistence.rogue_rule': 0.80,
}

// Orden de prioridad -> (código, nombre)
export const OWASP_MAP = [
  ['prompt_injection.instruction_override', 'ASI02', 'Prompt Injection directa'],
  ['prompt_injection.role_hijack', 'ASI01', 'Goal Hijacking'],
  ['prompt_injection.exfil', 'ASI07', 'Data Exfiltration'],
  ['swarm.deaddrop', 'ASI08', 'Agent Spoofing / Coordinación covert'],
  ['agent_framework', 'ASI10', 'Rogue Agent Autonomy'],
  ['ssrf', 'ASI04', 'Tool Hijacking'],
  ['sqli', 'ASI06', 'Privilege Escalation'],
  ['xss.script', 'ASI03', 'Indirect Prompt Injection'],
  ['ai_browser.ua', 'ASI02', 'Prompt Injection directa'],
  ['automation.headless', 'ASI02', 'Prompt Injection directa'],
  ['automation.client', 'ASI02', 'Prompt Injection directa'],
  ['automation.timing', 'ASI02', 'Prompt Injection directa'],
  ['agent.scope_escape_attempt', 'ASI05', 'Ejecución inesperada de código'],
  ['identity.cross_tenant', 'ASI03', 'Abuso de identidad y privilegios'],
  ['agent.tool_poisoning', 'ASI04', 'Tool Hijacking'],
  ['agent.memory_poisoning', 'ASI06', 'Memory & Context Poisoning'],
  ['agent.a2a_spoof', 'ASI07', 'Comunicación inter-agente insegura'],
  ['agent.c2_migration', 'ASI07', 'Comunicación inter-agente insegura'],
  ['identity.session_token_access', 'ASI03', 'Abuso de identidad y privilegios'],
  ['identity.api_key_access', 'ASI03', 'Abuso de identidad y privilegios'],
  ['identity.credential_access', 'ASI03', 'Abuso de identidad y privilegios'],
  ['identity.privilege_escalation', 'ASI03', 'Abuso de identidad y privilegios'],
  ['data.database_query_abuse', 'ASI06', 'Acceso indebido a datos'],
  ['data.exfiltration_canary', 'ASI07', 'Data Exfiltration'],
  ['tool.high_impact_call', 'ASI04', 'Tool Hijacking'],
  ['identity.lateral_movement', 'ASI03', 'Abuso de identidad y privilegios'],
  ['persistence.rogue_rule', 'ASI03', 'Abuso de identidad y privilegios'],
  ['recon.enumeration', 'ASI10', 'Reconocimiento / mapeo de superficie'],
]

const FEATURE_LABELS = [
  ['deaddrop_suspect', 'swarm.deaddrop'],
  ['tool_poisoning_suspect', 'agent.tool_poisoning'],
  ['memory_poisoning_suspect', 'agent.memory_poisoning'],
  ['cross_tenant_suspect', 'identity.cross_tenant'],
  ['scope_escape_attempt', 'agent.scope_escape_attempt'],
  ['c2_migration', 'agent.c2_migration'],
  ['a2a_spoof_suspect', 'agent.a2a_spoof'],
  ['credential_access_attempt', 'identity.credential_access'],
  ['session_token_access_attempt', 'identity.session_token_access'],
  ['api_key_access_attempt', 'identity.api_key_access'],
  ['database_query_abuse', 'data.database_query_abuse'],
  ['privilege_escalation_attempt', 'identity.privilege_escalation'],
  ['high_impact_tool_call', 'tool.high_impact_call'],
  ['exfiltration_attempt', 'data.exfiltration_canary'],
  ['enumeration_suspect', 'recon.enumeration'],
  ['lateral_movement_suspect', 'identity.lateral_movement'],
  ['rogue_rule_suspect', 'persistence.rogue_rule'],
]

export function uaMatches(ua) {
  const s = (ua || '').toLowerCase()
  const hits = []
  for (const [label, needles] of Object.entries(UA_SIGNATURES)) {
    if (needles.some((n) => s.includes(n))) hits.push(label)
  }
  return hits
}

export function featureMatches(features = {}) {
  const hits = []
  const fill = features.form_fill_ms
  if (typeof fill === 'number' && fill > 0 && fill < 350) hits.push('automation.timing')
  for (const [feat, label] of FEATURE_LABELS) {
    if (features[feat] === true) hits.push(label)
  }
  return hits
}

export function scoreEvent(event) {
  let matched = []
  for (const m of event.server_matches || []) if (m in RULE_WEIGHTS) matched.push(m)
  for (const m of event.client_matches || []) if (m in RULE_WEIGHTS) matched.push(m)
  matched.push(...uaMatches(event.ua))
  matched.push(...featureMatches(event.features))
  matched = [...new Set(matched)].sort()
  if (matched.length === 0) return { score: 0.0, matched: [] }
  let complement = 1.0
  for (const label of matched) complement *= 1.0 - (RULE_WEIGHTS[label] ?? 0.3)
  return { score: Math.round((1.0 - complement) * 1000) / 1000, matched }
}

export function detectionTrust(event) {
  const authoritative = new Set([
    ...(event.server_matches || []),
    ...uaMatches(event.ua),
    ...featureMatches(event.features),
  ])
  return authoritative.size ? 'server' : 'client_hint'
}

export function mapOwasp(matched) {
  const set = new Set(matched)
  for (const [label, code, name] of OWASP_MAP) if (set.has(label)) return [code, name]
  return ['N/A', 'Sin clasificación']
}
