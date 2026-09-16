# axio-shield-gateway — Cloudflare Worker

Port nativo del backend de AXIO Shield a un **Cloudflare Worker + Durable Object (SQLite)**,
mismo patrón que `agent-gateway` del sitio. Se monta **mismo-origen** bajo `/shield/*` en
`www.axiostaging.com`, por lo que **no rompe el CSP** del sitio (`script-src 'self'`,
`connect-src` heredado de `default-src 'self'`).

## Endpoints (`/shield/*`)

| Método · Ruta | Descripción |
|---|---|
| `GET /shield/health` | estado + modo stub |
| `POST /shield/ingest` | entrada del pipeline (eventos del SDK) |
| `POST /shield/tap` | sensor server-side de tráfico crudo (anti-bypass del SDK) |
| `GET /shield/api/incidents` · `/sessions` · `/coverage` · `/attack-graph` | lecturas del SOC |
| `GET /shield/api/audit/export` · `/verify` | audit log inmutable (hash chain) |
| `POST /shield/api/incidents/:id/action` | human-gate → LOCKDOWN (bearer `SHIELD_INTERNAL_TOKEN`) |
| `GET /shield/ws` | stream en vivo (incidentes + telemetría de defensa) |

## Agentes portados (paridad con `backend/app`)

SENTINEL, ORACLE, TRACKER++ (swarm + kill-chain + **attack-path BloodHound-style**), WARDEN
(integridad), SPECTER (identidad/A2A), HERALD, LOCKDOWN (human-gate), SCRIBE (audit hash-chained).
Mapeo triple OWASP ASI / MITRE ATT&CK / ATLAS. Modo **stub** determinista si no hay
`ANTHROPIC_API_KEY`.

## Correr

```bash
npm install
node tests/parity.mjs        # paridad JS↔Python (sin runtime de Worker)
wrangler dev                 # levanta el Worker local (DO+SQLite)
# smoke:
curl -XPOST localhost:8787/shield/ingest -H 'content-type: application/json' \
  -d '{"session_id":"s1","client_matches":["prompt_injection.instruction_override"]}'
curl localhost:8787/shield/api/audit/verify
```

## Deploy

```bash
wrangler secret put ANTHROPIC_API_KEY     # opcional (sin ella: modo stub)
wrangler secret put SHIELD_INTERNAL_TOKEN # human-gate
wrangler deploy                            # descomentar `routes` en wrangler.jsonc primero
```

El **SDK** se sirve aparte desde Cloudflare Pages (p.ej. `/shield-sdk/axio-shield.js`), mismo
dominio → mismo-origen con las páginas del sitio. Ver `docs/DEPLOYMENT_CLOUDFLARE.md`.

> El backend Python (`backend/`) permanece como referencia y oráculo de paridad.
