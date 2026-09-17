# AXIO Shield — Metodología Purple-Team

> Adaptada del **Active Directory Attack Lab** (PabloSCybersec) al contexto agéntico/web.
> v1.0 · Septiembre 2026 · AXIO Confidencial

El AD Attack Lab de Pablo demuestra una disciplina que AXIO Shield adopta como método central:
para cada técnica de ataque, **atacar → monitorear → identificar el gap → escribir una regla de
detección → re-testear**, documentando honestamente *qué se atrapó y qué se escapó*, y mapeando
todo a **MITRE ATT&CK**. Este documento traduce ese método al mundo de los agentes de IA.

---

## 1. Principios del laboratorio

Iguales al AD lab, adaptados:

| AD Attack Lab (Pablo) | AXIO Shield |
|---|---|
| Entorno aislado (VLAN airgapped 192.168.250.0/24) | Simulador determinista local, solo `/ingest` en localhost (`ScopeGuard`) |
| Debilidades intencionales documentadas | Portal-banco demo con superficie de ataque conocida |
| Kali + Impacket + BloodHound + Hashcat | Simulador metadata-only (sin exploits/credenciales/red reales) |
| Monitoreo del AD lab | Los 8 agentes defensores + audit log inmutable del Worker |
| Reproducible | `DeterministicClock` + `GroundTruthLog` + `evaluator` |

**Seguridad:** el laboratorio nunca ejecuta exploits, shell, credenciales ni tráfico externo.
Solo publica eventos JSON tipados (labels + features). Es seguro correrlo en cualquier momento.

## 2. El bucle por técnica (purple-team)

```
   ┌─────────┐   ┌────────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
   │ ATACAR  │──▶│ MONITOREAR │──▶│   GAP    │──▶│   FIX    │──▶│ RE-TEST  │
   │escenario│   │ ¿qué agente│   │¿qué pasó │   │regla /   │   │evaluator │
   │del sim  │   │ detectó?   │   │como normal?│ │lógica    │   │= pass?   │
   └─────────┘   └────────────┘   └──────────┘   └──────────┘   └──────────┘
```

- **Atacar:** un escenario del simulador (`simulator/attack_sim.py`).
- **Monitorear:** qué defensor lo detectó y con qué severidad (audit log / `/api/coverage`).
- **Gap:** técnicas que pasan como tráfico normal (en el AD lab, Kerberoasting se veía idéntico
  a actividad normal y **se escapó** con reglas por defecto). Se documentan sin adornos.
- **Fix:** nueva regla en `rules.py`/`server_scan.py` o lógica de agente (WARDEN/SPECTER/TRACKER).
- **Re-test:** el `evaluator` de Codex confirma `detected>0` y canary contenido.

## 3. Triple mapeo de frameworks

Cada técnica se cruza contra tres marcos (`backend/app/detection/frameworks.py`):

- **OWASP Agentic Top 10 (ASI01–ASI10)** — el estándar de apps agénticas.
- **MITRE ATT&CK Enterprise (Txxxx)** — el marco que ya corre el SOC del banco.
- **MITRE ATLAS (AML.Txxxx)** — amenazas específicas de IA.

Tabla de equivalencias **AD → agéntico**:

| Técnica AD (Pablo) | ATT&CK | Análogo agéntico (AXIO Shield) | Defensor |
|---|---|---|---|
| Enumeración BloodHound | T1087/T1069 | Recon del portal / mapeo de identidades | TRACKER |
| Kerberoasting / AS-REP | T1558/T1110 | Cosecha de credenciales/tokens | SPECTER |
| Pass-the-Hash | T1550 | Reuso de sesión/token entre sesiones | TRACKER + SPECTER |
| DCSync / ACL abuse | T1068/T1003 | Escalada de privilegios / acceso a API keys | SPECTER |
| Golden Ticket | T1136/T1098 | Identidad de agente forjada / regla persistente | SPECTER/WARDEN |

## 4. Kill-chain / fases

Alineadas a tácticas ATT&CK y detectadas por **TRACKER++** (`store.session_timeline`):

```
recon → initial_access → credential_access → lateral_movement →
privilege_escalation → persistence → command_and_control → exfil
```

- **Kill-chain:** una sola sesión que recorre ≥3 fases = UNA campaña (severidad creciente).
- **Evasión adaptativa:** la sesión cambia de TTP *después* de ser detectada → se marca y escala.

## 5. Grafo de rutas de ataque (BloodHound-style)

TRACKER++ construye un grafo de nodos (identidad / sesión / objetivo) y aristas (relaciones por
fase). Detecta **movimiento lateral** (misma identidad/token reusada entre sesiones) y calcula el
**camino más corto a compromiso total** (p. ej. `identidad → sesión → /portal/admin`). Es el
equivalente agéntico del grafo de BloodHound hacia *domain admin*. Expuesto en
`GET /shield/api/attack-graph`.

## 6. Matriz de cobertura + detection-findings

`backend/app/reporting/coverage_matrix.py` genera, por técnica: **detectado / cubierto / gap**,
severidad, el **defensor dueño** y el mapeo OWASP/ATT&CK/ATLAS. Es el equivalente del
`detection-findings.md` del AD lab — el "atrapado vs. escapado" para el auditor del banco
(`GET /shield/api/coverage`, export a `docs/DETECTION_FINDINGS.md`).

## 7. Registro de gaps conocidos (honestidad intelectual)

Como el AD lab documentó que Kerberoasting se le escapó a las reglas por defecto, AXIO Shield
documenta sus límites reales:

- La detección basada en labels del **SDK** es un *hint*; el sensor server-side `/tap`
  (`server_matches` autoritativos) cierra el bypass del SDK.
- Una técnica **sin regla** en `RULE_WEIGHTS` no se detecta hasta que el bucle purple-team la
  incorpora. El catálogo crece por iteración, no se asume completo.
- La clasificación de esta implementación es determinista; no depende de Claude ni de
  un SIEM externo para detectar, correlacionar o auditar.

## 8. Cómo correr el bucle

```bash
# 1) Backend arriba (local o wrangler dev)
# 2) Atacar con el laboratorio de Codex
python -m simulator.attack_sim all --url http://127.0.0.1:8000 --no-sleep
# 3) Ver cobertura (atrapado vs. escapado) y el grafo de rutas
curl /shield/api/coverage ; curl /shield/api/attack-graph
# 4) Verificar integridad del audit trail
curl /shield/api/audit/verify
```

*Crédito de metodología: Active Directory Attack Lab — https://github.com/PabloSCybersec/Active-Directory-Attack-Lab*
*Integración (fork, sin tocar el repo original): https://github.com/VegaBuildsAI/Active-Directory-Attack-Lab/tree/axio-shield-integration*
