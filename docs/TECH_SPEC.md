# AXIO Shield — Especificación Técnica

> Versión 0.3 · Septiembre 2026 · AXIO Confidencial
> Motor: Claude API (Haiku 4.5 + Sonnet 5) · Deploy: JS SDK web-embedded + Shield Backend

Este documento describe la arquitectura, los agentes (atacantes y defensores), el modelo de
datos, el pipeline de detección, las APIs y la estrategia de verificación del MVP de AXIO Shield.

---

## 1. Visión general

AXIO Shield es un ecosistema de **agentes defensivos** que se despliegan en el portal web del
cliente (banca/gobierno) y ejecutan, en tiempo real, la cadena:

```
detectar → clasificar → correlacionar → alertar → contener (human-gate) → auditar
```

Para validarlo se incluye un **laboratorio de agentes atacantes** determinista y local, y una
**War Room** que muestra atacante vs. defensa en vivo. Todo mapeado a **OWASP Agentic Top 10**.

### Principios de diseño

1. **Determinista antes que LLM** — reglas/regex resuelven la mayoría en microsegundos; Claude
   solo se invoca en casos ambiguos (control de costo, demo confiable).
2. **Server-authoritative, client-hint** — los labels que manda el SDK del navegador son *hints*;
   el sensor server-side produce labels **autoritativos**. La detección no depende de que el
   atacante coopere.
3. **Privacidad por diseño** — el SDK envía metadata y labels, **nunca contenido crudo** del
   usuario (requisito de cumplimiento bancario).
4. **Audit-first** — cada decisión de agente se registra en un log inmutable antes/al emitirse.
5. **Human-in-the-loop** — las acciones irreversibles requieren aprobación de un operador.
6. **Fail-safe** — si el backend no responde, el SDK cae a modo pasivo (no bloquea).

---

## 2. Arquitectura

```
┌───────────────────────────────────────────────────────────────────────────┐
│  SUPERFICIE — Portal web del cliente (o portal-banco simulado del demo)     │
│  [Login] [Transferencia] [Formularios]  ← aquí viven los sensores           │
└──────────────┬───────────────────────────────────┬────────────────────────┘
   sdk/axio-shield.js (metadata)          Tráfico crudo que evita el SDK
               │ POST /ingest                        │ POST /tap
               ▼                                      ▼
        ┌──────────────────────────────────────────────────────┐
        │  SHIELD BACKEND — FastAPI + asyncio EventBus          │
        │                                                       │
        │  SENTINEL ─▶ ORACLE ─▶ [coordinador de enriquecimiento]│
        │                          TRACKER++ ▶ WARDEN ▶ SPECTER │
        │                                   │                    │
        │                                   ▼                    │
        │                        HERALD ▶ LOCKDOWN(human-gate)   │
        │        Todos escriben a ▶ SCRIBE (audit hash-chained)  │
        └───────────────┬───────────────────────┬───────────────┘
             WebSocket /ws                 SQLite (audit + incidentes)
                        │
        ┌───────────────▼──────────┐   ┌──────────────────────────────┐
        │ Dashboard SOC  /dashboard│   │ War Room /arena (atk vs def)  │
        └──────────────────────────┘   └──────────────────────────────┘
                        ▲
        ┌───────────────┴──────────────────────────────────────────────┐
        │ Laboratorio atacante (Codex)  simulator/  → ataca /ingest      │
        └───────────────────────────────────────────────────────────────┘
```

### Stack

| Capa | Tecnología |
|---|---|
| SDK web | JavaScript vanilla (sin build), `<script>` embebido |
| Backend | Python 3.11+, FastAPI, asyncio, pydantic v2 |
| Motor IA | Claude Haiku 4.5 (volumen) · Sonnet 5 (razonamiento) · **modo stub** offline |
| Detección | Reglas/regex deterministas (cliente + servidor) |
| Persistencia | SQLite (audit log + incidentes) |
| Tiempo real | WebSocket |
| Frontend SOC/Arena | HTML/CSS/JS vanilla |
| Deploy | Docker Compose |

---

## 3. Agentes DEFENSORES (`backend/app/agents/`)

| Agente | Rol | OWASP | Motor |
|---|---|---|---|
| **SENTINEL** | Scanner de primera línea: puntúa cada evento con reglas y marca ambigüedad | — | reglas → Haiku |
| **ORACLE** | Clasifica a OWASP ASI01–10 + perfil de atacante + urgencia | todos | reglas → Haiku |
| **TRACKER++** | Correlación cross-sesión (swarm) + kill-chain por sesión + evasión adaptativa | ASI08 + multi | reglas → Sonnet |
| **WARDEN** | Integridad/procedencia: tool poisoning, memory poisoning, scope escape, tool de alto impacto | ASI04/05/06 | reglas |
| **SPECTER** | Identidad / A2A: cross-tenant, credenciales/tokens/API-keys, agent spoofing | ASI03/07 | reglas |
| **HERALD** | Alertas priorizadas al SOC (dashboard + webhook) según urgencia | — | — |
| **LOCKDOWN** | Contención **simulada** (rate-limit/bloqueo/revocación) con human-gate | — | — |
| **SCRIBE** | Audit log inmutable con hash chaining (Merkle-style) | — | — |

**Perfiles de atacante** (ORACLE): `HUMAN`, `HUMAN_AI`, `AUTONOMOUS`, `SWARM`, `A2A_HOSTILE`.
**Niveles de urgencia** (HERALD): `INFO` → dashboard · `WATCH` → analista · `CONTAIN` → alerta +
acción sugerida · `ELIMINATE` → crítico + CISO + human-in-the-loop obligatorio.

### Detalle de los defensores nuevos (Fase 5)

- **WARDEN** mantiene un `TOOL_BASELINE` (hash de la descripción legítima de cada herramienta):
  si la metadata declarada difiere → *tool poisoning*. Lleva procedencia de escrituras de
  memoria por sesión: una escritura en contexto compartido sin procedencia → *memory poisoning*.
  Detecta `scope_escape` y llamadas de herramienta de alto impacto. Adjunta `integrity_verdict`.
- **SPECTER** compara `source_tenant` vs `requested_tenant` (cruce sin credencial → ASI03),
  reconoce la familia `identity.*` (credenciales, tokens de sesión, API keys, escalada de
  privilegios) y, ante `a2a_spoof` o una identidad de agente no verificada (estilo SPIFFE/DID),
  emite un *challenge*. Fija perfil `A2A_HOSTILE` y adjunta `identity_verdict`.
- **TRACKER++** además del swarm cross-sesión, usa `store.session_timeline()` para detectar una
  **campaña multietapa** (≥3 fases distintas en una sesión = kill-chain, severidad creciente) y
  **evasión adaptativa** (aparición de una técnica nueva *después* de la primera detección).

---

## 4. Agentes ATACANTES (`simulator/` — construido en Codex)

Laboratorio **determinista y local**: sin LLM, sin shell, sin exploits reales, sin Internet.
El `ScopeGuard` solo permite HTTP a localhost y el `ActionExecutor` solo publica eventos JSON
tipados en `/ingest`. Un `GroundTruthLog` y un `evaluator` miden la contención.

| Agente / Escenario | ID | Técnica | OWASP esperado |
|---|---|---|---|
| Usuario legítimo (control) | `BASELINE_USER` | tráfico normal | — (sin incidente) |
| Injection | `INJECTION_AGENT` | prompt injection / goal hijack | ASI01/02 |
| AI Browser | `BROWSER_AGENT` | user-agent de bot + timing de automatización | ASI02 |
| Exfiltration | `EXFILTRATION_AGENT` | micro-exfiltración con canary | ASI07 |
| Swarm C2 | `SWARM_COORDINATOR` | dead-drops coordinados entre sesiones | ASI08 |
| Tool Poisoning | `TOOL_POISONING_AGENT` | mutación de metadata de herramienta | ASI04 |
| Memory Poisoning | `MEMORY_POISONING_AGENT` | escritura en contexto compartido | ASI06 |
| Identity Abuse | `IDENTITY_ABUSE_AGENT` | cruce de tenant sin credencial | ASI03 |
| A2A hostil | `A2A_IMPERSONATOR` | suplantación de agente | ASI07 |
| Chain (multietapa) | `CHAIN_AGENT` | recon → tool → memoria → identidad → C2 | multi |
| Adaptive | `ADAPTIVE_AGENT` | rota de variante tras ser detectado | — |
| Objectives | (director) | credenciales, tokens, API keys, DB, priv-esc, tool de alto impacto, exfil | ASI03/04/06/07 |
| SDK Bypass | `SDK_BYPASS` | pega directo a la API sin el SDK del cliente | varios |

**Fases (kill-chain):** `RECON → DELIVERY → EXPLOITATION → PERSISTENCE → COMMAND_AND_CONTROL →
EXFIL_ATTEMPT → ADAPT`. Orquestados por `AttackDirector`; las señales sintéticas heredan de
`MetadataSignalAgent`.

> Los dos simuladores (atacante en Codex, defensor de AXIO) viven **separados**; se integran solo
> por un contrato de telemetría (ver `arena/INTEGRATION.md`), no por código compartido.

---

## 5. Pipeline de detección

1. **Ingesta.** El SDK envía eventos normalizados a `POST /ingest` (metadata + `client_matches`
   como *hints*). El sensor server-side `POST /tap` recibe tráfico crudo, lo escanea con
   `server_scan.py` y produce `server_matches` **autoritativos** (resiliencia anti-bypass).
2. **SENTINEL** (`score_event`) combina `server_matches` (confiable) + `client_matches` (hint) +
   firmas de user-agent + features estadísticas en un score [0..1]. Emite `ThreatSignal` y marca
   `needs_llm` si el caso es ambiguo. `detection_trust` marca el incidente como `server` o
   `client_hint`.
3. **ORACLE** mapea a OWASP (`map_owasp`), deduce perfil y urgencia; si `needs_llm`, consulta a
   Claude Haiku (con *stub* determinista de respaldo). Crea el `Incident` con la `evidence`
   (extra + features) embebida y lo publica en `TOPIC_CLASSIFIED`.
4. **Coordinador de enriquecimiento** (en `main.py`) ejecuta, sobre el mismo incidente y en
   orden: `TRACKER++.enrich` → `WARDEN.enrich` → `SPECTER.enrich`, y publica una sola vez en
   `TOPIC_INCIDENT`.
5. **HERALD** notifica al SOC (WebSocket + webhook) según urgencia.
6. **LOCKDOWN** aplica contención **simulada** solo tras aprobación humana (endpoint dedicado).
7. **SCRIBE** registra cada decisión (SENTINEL/ORACLE/TRACKER/WARDEN/SPECTER/HERALD/LOCKDOWN) en
   el audit log con hash chaining y emite telemetría de "defensa" a la War Room.

---

## 6. Modelo de datos (`backend/app/models/events.py`)

- **`IngestEvent`** — `session_id`, `kind`, `path`, `ua`, `features`, `client_matches` (hints),
  `server_matches` (autoritativo), `extra`.
- **`ThreatSignal`** (SENTINEL) — `score`, `matched_rules`, `needs_llm`.
- **`Incident`** — clasificación completa: `owasp`, `attacker_profile`, `urgency`, `confidence`,
  `trust` (`server`|`client_hint`), `evidence`, y los enriquecimientos: `swarm`
  (`SwarmAssessment`), `killchain` (`KillChainAssessment`), `integrity_verdict` (WARDEN),
  `identity_verdict` (SPECTER), `status`, `actions`.
- **`AuditRecord`** (SCRIBE) — `seq`, `ts`, `agent`, `action`, `subject_id`, `payload`,
  `prev_hash`, `hash`.

Vocabulario de labels **compartido** entre `sdk/src/rules.js`, `backend/app/detection/rules.py`
y `backend/app/detection/server_scan.py`.

---

## 7. API (backend)

| Método · Ruta | Descripción |
|---|---|
| `GET /health` | Estado + si corre en modo stub |
| `POST /ingest` | Entrada del pipeline (eventos del SDK) |
| `POST /tap` | Sensor server-side de tráfico crudo (anti-bypass) |
| `GET /api/incidents` | Lista de incidentes (dashboard) |
| `GET /api/sessions` | Resumen de sesiones |
| `POST /api/incidents/{id}/action` | Human-gate → LOCKDOWN (simulado) |
| `GET /api/audit/export` | Exporta el audit log completo |
| `GET /api/audit/verify` | Valida la integridad de la cadena de hash |
| `WS /ws` | Stream en vivo (incidentes + telemetría atk/def) |
| `GET /api/arena/roster` | Roster de atacantes y defensores |
| `POST /api/arena/launch` | Dispara un escenario desde la War Room |
| `POST /api/attack/event` | Telemetría de ataque externa (contrato Codex) |
| Static | `/portal` · `/dashboard` · `/arena` · `/sdk` |

---

## 8. Deploy

- **Local:** `docker compose up --build` → `/portal/`, `/dashboard/`, `/arena/` en `:8000`.
- **Modo stub:** sin `SHIELD_ANTHROPIC_API_KEY` corre offline determinista (demo sin gastar
  tokens ni depender de la red). Con key usa Claude real (Haiku volumen / Sonnet TRACKER).
- **Público (preparado):** URLs y CORS por env; backend en contenedor con HTTPS, estáticos en
  host estático. El deploy sobre el sitio real de un cliente es la fase de *assessment*, con
  autorización escrita — nunca se toca infra de terceros sin permiso.

Configuración por variables `SHIELD_*` (ver `.env.example`).

---

## 9. Verificación

- **Unit/Integración (pytest):** 31 pruebas en verde — reglas, integridad del hash chain (y
  detección de manipulación), server_scan (detección desde texto crudo sin labels), WARDEN,
  SPECTER, kill-chain, y el pipeline end-to-end.
- **Contra el laboratorio Codex:** `python -m simulator.attack_sim all` → los 10 escenarios
  (S0–S13) dan **pass**; canary **contenido** en todos; `/api/audit/verify` íntegro.
- **Anti-bypass demostrado:** `POST /tap` con cuerpo crudo y `client_matches=[]` genera incidente
  con `trust=server`.
- **Demo manual:** portal (login + injection) → dashboard (incidente con vector) → War Room
  (atacante vs. defensor en vivo, kill-chain, swarm) → human-gate → export de auditoría.

---

## 10. Cumplimiento

Diseñado para apoyar: **EU AI Act** (Art. 12, logging de IA de alto riesgo), **DORA**
(resiliencia operacional financiera), **PCI DSS v4.0**, **ISO 27001 / 42001**,
**MITRE ATLAS**, **OWASP Agentic Top 10**.

## 11. Fuera de alcance (roadmap)

MIMIC (honeypots dinámicos en DOM), integración WAF real (Cloudflare/ModSecurity), email
gateway tap, motor de políticas OPA, verificación de identidad SPIFFE/SPIRE en producción.
