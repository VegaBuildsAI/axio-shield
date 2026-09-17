# AXIO Shield — MVP Demo

> Agentes defensivos autónomos para banca e instituciones de gobierno.
> **Defenders That Never Sleep.**

AXIO Shield detecta, clasifica, correlaciona, alerta, contiene (con aprobación humana)
y audita ataques impulsados por IA (prompt injection, AI browsers, swarms coordinados)
directamente en el portal web del cliente — donde el atacante entra.

Este repositorio es el **MVP demo vendible**: corre local con Docker y se puede desplegar
en una URL pública. Sirve para probar que la solución funciona y para presentar propuestas
a clientes (bancos, gobierno).

> ⚠️ El portal incluido es un **banco ficticio** de demostración con datos 100% sintéticos.
> No representa a ninguna entidad real. El simulador de ataques solo ataca este portal demo.

---

## Metodología y créditos — Active Directory Attack Lab

La disciplina purple-team de AXIO Shield (atacar → monitorear → identificar el gap → escribir la
regla → re-testear, con mapeo a **MITRE ATT&CK** y grafo de rutas estilo **BloodHound**) está
**adaptada del [Active Directory Attack Lab](https://github.com/PabloSCybersec/Active-Directory-Attack-Lab)
de PabloSCybersec**. Todo el crédito de esa metodología es de Pablo.

- Detalle: [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) (bucle purple-team, triple mapeo
  **OWASP ASI / MITRE ATT&CK / MITRE ATLAS**, matriz de cobertura "atrapado vs. escapado").
- Integración documentada en un **fork** (sin tocar el repo de Pablo):
  [`VegaBuildsAI/Active-Directory-Attack-Lab` @ `axio-shield-integration`](https://github.com/VegaBuildsAI/Active-Directory-Attack-Lab/tree/axio-shield-integration).

**Traducción AD → agéntico** (cada técnica tiene su defensor):

| Técnica AD | ATT&CK | Defensor AXIO Shield |
|---|---|---|
| BloodHound (enumeración/grafo) | T1087 | TRACKER++ (attack-path) |
| Kerberoasting / cosecha de credenciales | T1558 | SPECTER |
| Pass-the-Hash (movimiento lateral) | T1550 | TRACKER++ + SPECTER |
| DCSync / escalada de privilegios | T1068 | SPECTER |
| Golden Ticket / persistencia | T1136 | SPECTER / WARDEN |

> Los agentes atacantes (familias recon/credential/lateral/privesc/persistence en `simulator/`)
> son **solo para entrenar y validar** a los defensores — nunca se despliegan.

---

## Qué hay dentro

```
demo-portal/   Portal-banco simulado (HTML/JS) con el SDK embebido
sdk/           SDK JS: sensor DOM, fingerprint de AI browsers, transporte (solo metadata)
backend/       Shield Backend (FastAPI + asyncio): los agentes defensivos
dashboard/     SOC en vivo (WebSocket): incidentes, grafo de swarm, audit trail
simulator/     Simulador de ataques (prompt injection, AI browser, swarm)
deployment/    Dockerfile
```

### Los agentes (backend/app/agents/)

| Agente | Rol | Motor |
|--------|-----|-------|
| **SENTINEL** | Scanner determinista: puntúa cada evento con reglas | reglas (Haiku si es ambiguo) |
| **ORACLE** | Clasifica a OWASP Agentic Top 10 (ASI01-10) + perfil + urgencia | reglas → Haiku |
| **TRACKER++** | Swarm cross-sesión + kill-chain por sesión + evasión adaptativa | reglas → Sonnet |
| **WARDEN** | Integridad/procedencia: tool poisoning, memory poisoning, scope escape (ASI04/05/06) | reglas |
| **SPECTER** | Identidad / A2A: cross-tenant, credenciales, agent spoofing (ASI03/07) | reglas |
| **HERALD** | Alertas priorizadas al SOC (dashboard + webhook) | — |
| **LOCKDOWN** | Contención **simulada** con human-gate (no toca infra real) | — |
| **SCRIBE** | Audit log inmutable con hash chaining (EU AI Act / DORA) | — |

**Anti-bypass del SDK:** el sensor server-side `/tap` inspecciona el tráfico REAL (no depende
de que el cliente mande labels), así un atacante que evita el SDK igual es detectado
(`server_matches` autoritativo, `trust=server`).

Roadmap (no en este MVP): **MIMIC** (honeypots dinámicos), integración WAF real, email gateway.

### War Room / Arena (`/arena/`)

Vista de **atacante vs defensa en vivo**: el operador dispara ataques contra la página y ve,
en paralelo, cómo cada **agente atacante** y cada **agente defensor** actúan y reaccionan.
Los agentes atacantes se construyen aparte en Codex (`simulator/`); la Arena los muestra sin
mezclar código, vía un seam de telemetría — ver [arena/INTEGRATION.md](arena/INTEGRATION.md).
Incluye un atacante integrado para demostrar sin Codex (botones de la Arena). Abrí
`http://localhost:8000/arena/`.

### Principios

- **Determinista antes que LLM** — las reglas resuelven en microsegundos; Claude solo para casos ambiguos.
- **Solo metadata** — el SDK inspecciona el contenido en el navegador y envía *labels + features*, **nunca el texto crudo**.
- **Audit-first** — cada decisión de agente queda en un log inmutable verificable.
- **Human-in-the-loop** — las acciones de contención requieren aprobación de un operador.
- **Fail-safe** — si el backend no responde, el SDK cae a modo pasivo (no bloquea).

---

## Quickstart

### Opción A — Docker (recomendado)

```bash
docker compose up --build
```

- Portal:    http://localhost:8000/portal/
- Dashboard: http://localhost:8000/dashboard/

Lanzar ataques (en otra terminal):

```bash
python simulator/attack_sim.py all
```

### Opción B — Local sin Docker

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   ·   Linux/Mac: source .venv/bin/activate
pip install -e "backend[dev]"
uvicorn app.main:app --app-dir backend --port 8000
```

Luego abrí el dashboard y corré `python simulator/attack_sim.py all`.

### Modo STUB vs Claude real

Sin `SHIELD_ANTHROPIC_API_KEY`, el sistema corre en **modo stub**: clasificaciones
deterministas, sin red, sin gastar tokens — ideal para demos en vivo. Con API key
(copiá `.env.example` a `.env`), ORACLE/TRACKER usan Claude real para los casos ambiguos.

---

## Flujo de la demo

1. Abrí el **dashboard** — queda escuchando en vivo.
2. Abrí el **portal**, ingresá (cualquier usuario/clave) y hacé una transferencia normal → sin alertas.
3. Hacé otra transferencia con `Ignore all previous instructions...` en el campo *concepto*
   → aparece un incidente **ASI02 / ELIMINATE** en el dashboard (y el texto crudo nunca sale del navegador).
4. Corré `python simulator/attack_sim.py swarm` → **TRACKER** une las sesiones en el grafo de swarm.
5. Aprobá una acción de contención (Rate-limit / Bloquear sesión) → **human-gate** + queda auditado.
6. Botón **Verificar audit log** → confirma que la cadena de hash es íntegra.

Guion detallado: [DEMO_SCRIPT.md](DEMO_SCRIPT.md).

---

## Tests

```bash
pip install -e "backend[dev]"
cd backend && pytest
```

Cubren: reglas de detección, integridad del hash chain (y detección de manipulación),
y el pipeline completo end-to-end (injection, AI browser, swarm, human-gate).

---

## Deploy público (subdominio AXIO)

El build ya está listo para desplegarse (URLs y CORS por env). Pasos:

1. **Backend**: contenedor (`deployment/Dockerfile`) en una VM/servicio con HTTPS.
   Ajustar `SHIELD_CORS_ORIGINS` al dominio del portal.
2. **Estáticos** (portal/dashboard/sdk): se sirven desde el mismo backend, o por separado
   en un host estático apuntando el SDK al backend vía `data-endpoint` / `window.AXIO_SHIELD_ENDPOINT`.
3. Definir `SHIELD_ANTHROPIC_API_KEY` para clasificación con Claude real.

> Para un cliente real, el SDK se embebe en **su** portal — con autorización escrita — como
> fase de *assessment*. Nunca se despliega sobre sitios de terceros sin permiso.

---

## Cumplimiento

Diseñado para apoyar: **EU AI Act** (Art. 12 logging), **DORA**, **PCI DSS v4.0**,
**ISO 27001 / 42001**, **OWASP Agentic Top 10**, **MITRE ATLAS**.
