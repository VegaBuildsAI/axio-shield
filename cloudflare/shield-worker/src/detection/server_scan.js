// Port JS de backend/app/detection/server_scan.py — escaneo server-side de contenido crudo.
// Independiente del SDK: detecta aunque el atacante NO mande client_matches (usado por /shield/tap).

const PATTERNS = [
  ['prompt_injection.instruction_override', [
    /ignore\s+(all\s+)?(previous|prior|above)/i,
    /disregard\s+(the\s+)?(above|previous|prior)/i,
    /forget\s+(everything|all\s+previous)/i,
    /new\s+instructions?\s*[:\-]/i,
  ]],
  ['prompt_injection.role_hijack', [
    /you\s+are\s+now/i, /system\s+prompt/i, /\bact\s+as\s+(an?|the)\b/i, /pretend\s+to\s+be/i,
  ]],
  ['prompt_injection.exfil', [
    /(reveal|print|show|repeat|dump)[^.]{0,25}(system|prompt|instructions?|api[_\s-]?key|password|secret|token|env)/i,
    /environment\s+variables?/i,
  ]],
  ['xss.script', [/<script\b/i, /on(error|load|click)\s*=/i, /javascript:/i]],
  ['sqli', [/'\s*or\s*'?1'?\s*=\s*'?1/i, /union\s+select/i, /;\s*drop\s+table/i, /--\s/]],
  ['ssrf', [/169\.254\.169\.254/, /file:\/\//i, /https?:\/\/(localhost|127\.0\.0\.1)/i, /metadata\.(google|internal)/i]],
  ['swarm.deaddrop', [/remote\s+confirmed/i, /exposing?\s+creds?/i, /join\s+the\s+swarm/i, /\brecruit(ing)?\b/i, /^[A-Za-z0-9+/=]{48,}$/]],
]

export function scanText(text) {
  if (!text) return []
  const hits = []
  for (const [label, regexes] of PATTERNS) {
    if (regexes.some((rx) => rx.test(text))) hits.push(label)
  }
  return [...new Set(hits)].sort()
}
