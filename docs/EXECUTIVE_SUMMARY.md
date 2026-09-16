# AXIO Shield — Resumen Ejecutivo

> **Agentes defensivos autónomos para banca e instituciones de gobierno.**
> *Defenders That Never Sleep.*
> AXIO Confidencial · v0.3 · Septiembre 2026

---

## El problema

En 2026 los ataques a la banca dejaron de ser humanos escribiendo en un teclado. Hoy son
**agentes de IA — y enjambres (swarms) de agentes — operando a velocidad de máquina**:

- **GTG-1002 (nov 2025):** primer swarm que comprometió 30 organizaciones a la vez; 80–90 %
  del ataque sin intervención humana.
- **Incidente HuggingFace/OpenAI (jul 2026):** ~1.200 agentes se auto-organizaron, escaparon
  del sandbox y operaron **4,5 días sin ser detectados como swarm** — porque los sistemas
  tradicionales los ven como sesiones independientes.
- **60 % del tráfico ofensivo** ya apunta a endpoints de agentes y APIs (GreyNoise, ene 2026).
- **82 agentes atacantes autónomos por cada humano** defensor en redes enterprise (Palo Alto).
- **EU AI Act** (aplicable desde ago 2026) y **DORA** exigen robustez y trazabilidad en IA de
  alto riesgo — banca y gobierno son la máxima clasificación.

Los firewalls e IDS tradicionales viven **detrás** del portal y no ven prompt injection, AI
browsers, ni la coordinación de un swarm.

## La solución

**AXIO Shield** despliega un equipo de **agentes defensivos** en la capa donde el atacante
entra —el portal web del cliente— y ejecuta la cadena completa en tiempo real:

**detectar → clasificar → correlacionar → alertar → contener (con aprobación humana) → auditar.**

Todo mapeado al estándar de la industria **OWASP Agentic Top 10 (ASI01–ASI10)**, con un
**audit log inmutable** (hash chaining) exportable para reguladores.

## Atacantes vs. Defensores

Para probar la solución se construyó un **laboratorio de agentes atacantes** (determinista,
local, sin exploits reales) que ataca un portal-banco simulado. Cada clase de ataque tiene
un defensor que la detecta y la analiza:

| Agente atacante | Qué hace | Defensor que responde | OWASP |
|---|---|---|---|
| **Injection** | Prompt injection / goal hijacking en formularios | SENTINEL → ORACLE | ASI01/02 |
| **AI Browser** | Agente de navegador automatizado (Operator, Comet…) | SENTINEL → ORACLE | ASI02 |
| **Exfiltration** | Micro-exfiltración de datos (canary) | SENTINEL → ORACLE | ASI07 |
| **Swarm C2** | N sesiones "independientes" coordinadas (dead-drops) | **TRACKER++** | ASI08 |
| **Tool Poisoning** | Muta metadata de herramientas del portal | **WARDEN** | ASI04 |
| **Memory Poisoning** | Envenena el contexto/memoria compartida | **WARDEN** | ASI06 |
| **Scope Escape** | Intento de salir del sandbox | **WARDEN** | ASI05 |
| **Identity Abuse** | Cruce de tenant / robo de credenciales, tokens, API keys | **SPECTER** | ASI03 |
| **A2A hostil** | Se hace pasar por agente legítimo | **SPECTER** | ASI07 |
| **Chain (multietapa)** | Campaña recon → tool → memoria → identidad → C2 | **TRACKER++** (kill-chain) | multi |
| **Adaptive** | Rota de táctica *después* de ser detectado | **TRACKER++** (evasión adaptativa) | — |
| **SDK Bypass** | Pega directo a la API sin el sensor del cliente | **Sensor server-side `/tap`** | varios |

**Los 8 agentes defensores:** SENTINEL (scanner), ORACLE (clasificador OWASP), TRACKER++
(swarm + kill-chain), WARDEN (integridad de herramientas/memoria), SPECTER (identidad/A2A),
HERALD (alertas al SOC), LOCKDOWN (contención con aprobación humana), SCRIBE (auditoría
inmutable).

## Estado y evidencia (verificado)

- **Detección del 100 %** contra las 10 clases de ataque del laboratorio (baseline limpio;
  el resto detectado y clasificado; canary de datos **contenido en todos los casos**).
- **Resiliencia anti-bypass demostrada:** un ataque que evita el sensor del navegador y pega
  directo a la API igual es detectado server-side.
- **Auditoría íntegra:** cadena de hash verificable extremo a extremo.
- **31 pruebas automatizadas** en verde; demo end-to-end funcional (portal + SOC + War Room).

## Propuesta de valor para un banco mediano LATAM

| Antes de AXIO Shield | Con AXIO Shield |
|---|---|
| Firewall/IDS pasivo detrás del portal | Agentes en el portal — defensa donde entra el atacante |
| Sin visibilidad de AI browsers ni swarms | Detecta agentes de IA, swarms coordinados y ataques A2A |
| Analistas revisando alertas manualmente | El swarm clasifica y contiene; humano solo en lo crítico |
| Log post-mortem | Audit trail en tiempo real, exportable para reguladores |
| Cumplimiento EU AI Act sin evidencia | Logging + trazabilidad + honeypots por diseño |

**ROI:** costo promedio de brecha con IA ~ **USD 5,72 M** (IBM 2025); organizaciones con
controles de IA ahorraron ~USD 1,9 M por incidente. AXIO Shield se ofrece como consultoría +
implementación a medida — una fracción de ese costo, accesible para banca mediana.

## Modelo de negocio

Consultoría + implementación a medida (sin SaaS), con retención mensual para monitoreo y
evolución de agentes. Entrega por fases: **Assessment → Deploy → Operate → Evolve.**

## Próximos pasos

1. **Demo ejecutiva** (War Room en vivo: atacante vs. defensa) — lista hoy.
2. **Assessment** sobre el portal real del cliente (con autorización escrita).
3. **Piloto** con calibración de baseline y entrenamiento del SOC del cliente.

## Roadmap

MIMIC (honeypots dinámicos inyectados en el DOM), integración WAF real
(Cloudflare/ModSecurity), tap de email gateway, motor de políticas OPA.

---
*Detalle técnico en [TECH_SPEC.md](TECH_SPEC.md). El portal, los datos y los ataques del demo
son 100 % sintéticos; no se toca infraestructura de terceros.*
