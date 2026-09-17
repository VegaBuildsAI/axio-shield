# AXIO Shield — Runbook de despliegue en Cloudflare (www.axiostaging.com)

> Objetivo: desplegar Shield en producción sobre el sitio de AXIO **sin romper el AEO/GEO** ni el
> Worker `agent-gateway` existente. Arquitectura aprobada: **Worker nativo + Durable Objects**,
> mismo-origen bajo `/shield/*`.

## Contexto del sitio (repo `AXIO Website`)

- **Cloudflare Pages** (proyecto `axio`, `react-scaffold/`, Pages Functions + KV `RL`).
- **Worker** `agent-gateway` (A2A) con Durable Objects + SQLite — patrón de referencia.
- **CSP** (`_headers`): `script-src 'self' 'unsafe-inline'`, **sin `connect-src`** ⇒ todo debe
  ser **mismo-origen**. Un backend cross-origin rompería el CSP.

## Restricciones AEO (NO romper)

- No editar `robots.txt`, `llms.txt`, `sitemap.xml`, schema JSON-LD, `_headers`/CSP, canonical/OG,
  contenido de `react-scaffold/`, ni el Worker `agent-gateway`.
- SDK: mismo-origen, `async`/`defer`, mínimo (<5 KB), sin bloqueo ni layout shift.
- Todo Shield bajo `/shield/*`; excluir del sitemap. Un `Disallow: /shield/` se coordina con la
  skill `aeo-technical` (no editar robots a mano).

## Arquitectura de deploy

```
Navegador (www.axiostaging.com)
  │  <script src="/shield/axio-shield.js" defer>   (mismo-origen, CSP OK)
  │  fetch("/shield/ingest")                         (mismo-origen, CSP OK)
  ▼
Cloudflare  ── route: www.axiostaging.com/shield/*  ──▶  Worker axio-shield-gateway
   (Pages sirve el resto del sitio)                        │  Durable Object ShieldStore (SQLite)
   (Worker agent-gateway intacto en su ruta)               │  DO WebSocket  → /shield/ws
                                                           │  pipeline determinista + SQLite
```

## Componentes (`cloudflare/shield-worker/`)

- `wrangler.jsonc` — `name: axio-shield-gateway`, DO `SHIELD`→`ShieldStore`
  (`new_sqlite_classes`), `SHIELD_MODE: observe`, `routes: [{pattern:"www.axiostaging.com/shield/*", zone_name:"axiostaging.com"}]`,
  secreto `SHIELD_INTERNAL_TOKEN`, `observability:true`.
- `src/index.js` — router de `/shield/*` (ingest, tap, api/*, ws, human-gate con bearer interno).
- `src/detection/*` + `src/agents/*` — port JS del pipeline (paridad con `backend/app`).
- `src/store.js` — `ShieldStore` DO+SQLite (audit hash-chained, sesiones, incidentes).

## Pasos

```bash
# Prerrequisitos: wrangler autenticado en la cuenta Cloudflare de AXIO (misma de agent-gateway)
cd "AXIO Shield/cloudflare/shield-worker"
 npm install
wrangler secret put SHIELD_INTERNAL_TOKEN   # para el human-gate

# Local
wrangler dev                                 # prueba /shield/ingest, /shield/tap, /shield/api/*

# Paridad con el backend Python (oráculo)
node tests/parity.mjs

# Staging
wrangler deploy                              # publica el Worker + la ruta /shield/*
```

## Verificación post-deploy

- `GET https://www.axiostaging.com/shield/api/audit/verify` → `{"valid":true}`.
- Consola del navegador en el sitio: **sin violaciones de CSP** al cargar el SDK.
- AEO intacto: `robots.txt`, `sitemap.xml`, schema y Lighthouse sin cambios.
- `agent-gateway` sigue respondiendo (no se tocó).

## Rollback

- `wrangler deployments list` + `wrangler rollback` para el Worker.
- Quitar el `<script>` del SDK del sitio revierte la instrumentación sin afectar nada más.

## Dependencias externas

- **Cuenta Cloudflare de AXIO** (para `wrangler deploy` y la ruta en `axiostaging.com`).
- La zona `axiostaging.com` debe permitir un route de Worker en `/shield/*` (coexiste con Pages).
