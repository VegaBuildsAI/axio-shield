# Escenarios de ataque

Los escenarios están definidos en [`../attack_sim.py`](../attack_sim.py). Cada uno emula
a un cliente malicioso enviando eventos ya "escaneados" al endpoint `/ingest` del backend.

| Escenario | Qué prueba | OWASP / perfil esperado |
|-----------|-----------|-------------------------|
| `baseline` | Tráfico legítimo — no debe generar incidentes | — |
| `injection` | Prompt injection en un formulario | ASI02 · ELIMINATE |
| `ai_browser` | AI browser / bot por user-agent + timing | ASI02 · HUMAN_AI |
| `swarm` | N sesiones coordinadas con dead-drops | ASI08 · SWARM (TRACKER) |
| `tool_poisoning` | Mutación sintética de metadata de herramienta local | ASI04 · Tool Hijacking |
| `memory_poisoning` | Marcador de contexto compartido de prueba | ASI06 · Memory & Context Poisoning |
| `identity_abuse` | Cruce de tenant sintético sin credenciales | ASI03 · Identity & Privilege Abuse |
| `chain` | Cadena recon → herramienta → memoria → identidad → C2 | multietapa |
| `adaptive` | Rotación finita de variante después de detección | adaptación determinista |
| `objectives` | Objetivos señuelo: credenciales, tokens, API keys, datos, privilegios y herramientas | extracción contenida |
| `enumeration` | Enumeración de directorio/permisos sintética | `recon.enumeration` |
| `credential_harvest` | Cosecha sintética Kerberoast/AS-REP + sesión | ASI03 |
| `lateral_movement` | Mismo token/identidad en dos workstations señuelo | `identity.lateral_movement` |
| `privilege_escalation` | DCSync/ACL abuse sintético | ASI03 |
| `persistence` | Golden Ticket/rogue rule sintético | `persistence.rogue_rule` |
| `ad_killchain` | Recon → credential → lateral → privesc → persistence | kill-chain + attack graph |

```bash
python simulator/attack_sim.py all
python simulator/attack_sim.py swarm --sessions 4 --url http://localhost:8000
python -m simulator.attack_sim chain --url http://127.0.0.1:8000 --no-sleep
```

Cada escenario publica únicamente eventos JSON en `/ingest`. `fixture_id`, fases y
`features` forman el ground truth; no se ejecutan herramientas, comandos, navegadores
ni conexiones externas reales.
