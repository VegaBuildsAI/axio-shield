// Port JS de backend/app/reporting/coverage_matrix.py — matriz de cobertura.
import { RULE_WEIGHTS, mapOwasp } from './detection/rules.js'
import { frameworksFor } from './detection/frameworks.js'

const DEFENDER_OWNERSHIP = {
  'prompt_injection.instruction_override': 'SENTINEL/ORACLE', 'prompt_injection.role_hijack': 'SENTINEL/ORACLE',
  'prompt_injection.exfil': 'SENTINEL/ORACLE', 'xss.script': 'SENTINEL/ORACLE', 'sqli': 'SENTINEL/ORACLE',
  'ssrf': 'SENTINEL/ORACLE', 'ai_browser.ua': 'SENTINEL/ORACLE', 'automation.headless': 'SENTINEL/ORACLE',
  'automation.client': 'SENTINEL/ORACLE', 'automation.timing': 'SENTINEL/ORACLE', 'agent_framework': 'ORACLE',
  'swarm.deaddrop': 'TRACKER', 'agent.c2_migration': 'TRACKER', 'recon.enumeration': 'TRACKER',
  'identity.lateral_movement': 'TRACKER/SPECTER', 'agent.tool_poisoning': 'WARDEN',
  'agent.memory_poisoning': 'WARDEN', 'agent.scope_escape_attempt': 'WARDEN', 'tool.high_impact_call': 'WARDEN',
  'identity.cross_tenant': 'SPECTER', 'identity.credential_access': 'SPECTER',
  'identity.session_token_access': 'SPECTER', 'identity.api_key_access': 'SPECTER',
  'identity.privilege_escalation': 'SPECTER', 'agent.a2a_spoof': 'SPECTER', 'persistence.rogue_rule': 'SPECTER/WARDEN',
  'data.database_query_abuse': 'ORACLE', 'data.exfiltration_canary': 'ORACLE/HERALD',
}

export function coverageMatrix(exercisedSet) {
  const rows = []
  for (const label of Object.keys(RULE_WEIGHTS).sort()) {
    const [owasp, owaspName] = mapOwasp([label])
    const fw = frameworksFor([label])
    const seen = exercisedSet.has(label)
    rows.push({
      technique: label, owasp, owasp_name: owaspName, attack: fw.attack, atlas: fw.atlas,
      defender: DEFENDER_OWNERSHIP[label] || '—', rule_exists: true, exercised: seen,
      status: seen ? 'detectado' : 'cubierto (no ejercido)',
    })
  }
  const summary = {
    tecnicas: rows.length, con_regla: rows.length,
    ejercidas_y_detectadas: rows.filter((r) => r.exercised).length,
  }
  return { summary, rows }
}
