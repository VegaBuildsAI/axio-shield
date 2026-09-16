// Port JS de backend/app/detection/frameworks.py — mapeo label -> MITRE ATT&CK / ATLAS.

export const FRAMEWORKS = {
  'prompt_injection.instruction_override': { attack: [['T1059', 'Command and Scripting Interpreter']], atlas: [['AML.T0051.000', 'LLM Prompt Injection: Direct']] },
  'prompt_injection.role_hijack': { attack: [['T1656', 'Impersonation']], atlas: [['AML.T0051.000', 'LLM Prompt Injection: Direct']] },
  'prompt_injection.exfil': { attack: [['T1041', 'Exfiltration Over C2 Channel']], atlas: [['AML.T0057', 'LLM Data Leakage']] },
  'xss.script': { attack: [['T1059.007', 'JavaScript']], atlas: [] },
  'sqli': { attack: [['T1190', 'Exploit Public-Facing Application']], atlas: [] },
  'ssrf': { attack: [['T1190', 'Exploit Public-Facing Application']], atlas: [] },
  'swarm.deaddrop': { attack: [['T1102', 'Web Service (C2)']], atlas: [['AML.T0029', 'Denial of ML Service']] },
  'ai_browser.ua': { attack: [['T1071', 'Application Layer Protocol']], atlas: [] },
  'automation.headless': { attack: [['T1071', 'Application Layer Protocol']], atlas: [] },
  'automation.client': { attack: [['T1071', 'Application Layer Protocol']], atlas: [] },
  'automation.timing': { attack: [['T1071', 'Application Layer Protocol']], atlas: [] },
  'agent_framework': { attack: [['T1204', 'User Execution']], atlas: [['AML.T0053', 'LLM Plugin Compromise']] },
  'agent.tool_poisoning': { attack: [['T1195', 'Supply Chain Compromise']], atlas: [['AML.T0053', 'LLM Plugin Compromise']] },
  'agent.memory_poisoning': { attack: [['T1565', 'Data Manipulation']], atlas: [['AML.T0070', 'RAG Poisoning']] },
  'agent.scope_escape_attempt': { attack: [['T1611', 'Escape to Host']], atlas: [['AML.T0053', 'LLM Plugin Compromise']] },
  'agent.c2_migration': { attack: [['T1568', 'Dynamic Resolution']], atlas: [] },
  'agent.a2a_spoof': { attack: [['T1036', 'Masquerading'], ['T1078', 'Valid Accounts']], atlas: [['AML.T0051.001', 'LLM Prompt Injection: Indirect']] },
  'identity.cross_tenant': { attack: [['T1078', 'Valid Accounts']], atlas: [] },
  'identity.credential_access': { attack: [['T1555', 'Credentials from Password Stores']], atlas: [] },
  'identity.session_token_access': { attack: [['T1528', 'Steal Application Access Token']], atlas: [] },
  'identity.api_key_access': { attack: [['T1552.001', 'Unsecured Credentials: Credentials In Files']], atlas: [] },
  'identity.privilege_escalation': { attack: [['T1068', 'Exploitation for Privilege Escalation']], atlas: [] },
  'data.database_query_abuse': { attack: [['T1213', 'Data from Information Repositories']], atlas: [] },
  'data.exfiltration_canary': { attack: [['T1041', 'Exfiltration Over C2 Channel']], atlas: [['AML.T0057', 'LLM Data Leakage']] },
  'tool.high_impact_call': { attack: [['T1106', 'Native API']], atlas: [['AML.T0053', 'LLM Plugin Compromise']] },
  'recon.enumeration': { attack: [['T1087', 'Account Discovery'], ['T1069', 'Permission Groups Discovery']], atlas: [['AML.T0013', 'Discover ML Artifacts']] },
  'identity.lateral_movement': { attack: [['T1550', 'Use Alternate Authentication Material'], ['T1021', 'Remote Services']], atlas: [] },
  'persistence.rogue_rule': { attack: [['T1098', 'Account Manipulation'], ['T1136', 'Create Account']], atlas: [] },
}

export function frameworksFor(matched) {
  const attack = new Map(); const atlas = new Map()
  for (const label of matched) {
    const e = FRAMEWORKS[label]
    if (!e) continue
    for (const [id, name] of e.attack) attack.set(id, name)
    for (const [id, name] of e.atlas) atlas.set(id, name)
  }
  const fmt = (m) => [...m.entries()].sort().map(([id, name]) => `${id} ${name}`)
  return { attack: fmt(attack), atlas: fmt(atlas) }
}
