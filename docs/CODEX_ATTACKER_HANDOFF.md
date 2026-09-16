# Handoff a Codex — Agentes atacantes (AD Attack Lab)

Instrucciones para que **Codex** construya/mantenga las familias de ataque inspiradas en el AD
lab dentro de `simulator/`. Mantiene la separación: Codex es dueño de `simulator/`; el equipo
defensor es dueño de `backend/app/`. Los dos se integran por el **contrato de labels/eventos**.

## Regla de oro

Cada evento se publica en `/ingest` (metadata-only, determinista, localhost, sin exploits) y
debe emitir EXACTAMENTE los `client_matches` y `features` de la tabla, y llevar en `extra`:
`phase` (string minúscula), `identity` o `token`, y `target`. Estos labels ya existen en
`backend/app/detection/rules.py`.

## Roster (heredan de `MetadataSignalAgent`, patrón de `tool_poison_agent.py`)

| Archivo | attacker_id | Análogo AD | ATT&CK | client_matches | features | extra |
|---|---|---|---|---|---|---|
| `recon_agent.py` | `RECON_AGENT` | BloodHound | T1087/T1069 | `["recon.enumeration"]` | `{"enumeration_suspect":true}` | `phase:"recon"`, `identity`, `target:"/portal/directory"` |
| `credential_agent.py` | `CREDENTIAL_AGENT` | Kerberoast | T1558/T1110 | `["identity.credential_access","identity.session_token_access"]` | `{"credential_access_attempt":true,"session_token_access_attempt":true}` | `phase:"credential_access"`, `identity`, `target:"/portal/auth"` |
| `lateral_agent.py` | `LATERAL_AGENT` | Pass-the-Hash | T1550 | `["identity.lateral_movement"]` | `{"lateral_movement_suspect":true}` | `phase:"lateral_movement"`, **mismo `token`+`identity` en 2 sesiones**, `target:"/portal/wkstn1"` y `/wkstn2` |
| `privesc_agent.py` | `PRIVESC_AGENT` | DCSync | T1068/T1003 | `["identity.privilege_escalation","identity.api_key_access"]` | `{"privilege_escalation_attempt":true,"api_key_access_attempt":true}` | `phase:"privilege_escalation"`, `identity`, `target:"/portal/admin"` |
| `persistence_agent.py` | `PERSISTENCE_AGENT` | Golden Ticket | T1136/T1098 | `["persistence.rogue_rule"]` | `{"rogue_rule_suspect":true}` | `phase:"persistence"`, `identity`, `target:"/portal/rules"` |

## Detalles críticos

1. `extra["phase"]` = string minúscula de la tabla (lo lee `store.add_event` para el kill-chain
   y el grafo). Además setear el `AttackPhase` enum del ground-truth.
2. `extra["identity"]` = identidad de servicio ficticia estable (ej. `"svc_account_demo"`);
   reusarla dispara movimiento lateral + grafo de rutas.
3. **LateralAgent** emite ≥2 eventos en 2 `session_id` con el MISMO `token`+`identity`.
4. Solo labels + features, nunca contenido crudo.

## Componer y registrar

- `AttackDirector` (`director.py`): `run_enumeration`, `run_credential_harvest`,
  `run_lateral_movement`, `run_privilege_escalation`, `run_persistence`, y `run_ad_killchain`
  (una sesión con `identity` reusada recorriendo recon→credential→lateral→privesc→persistence).
- `attack_sim.py`: añadir a `choices` y `main()` los escenarios `enumeration`,
  `credential_harvest`, `lateral_movement`, `privilege_escalation`, `persistence`, `ad_killchain`
  (scenario_id sugeridos: `S14-recon`…`S19-ad-chain`).
- Tests (`simulator/tests/test_attack_lab.py`): por agente, afirmar `fixture_id`, fase y
  `observation["matched_rules"]` no vacío; lateral = 2 records con el mismo token.

## Validación (bucle purple-team)

Con el backend arriba: `python -m simulator.attack_sim all --url http://127.0.0.1:8000 --no-sleep`
→ todos `pass=True`, canary contenido. En `/shield/api/coverage` cada técnica nueva aparece
detectada por su defensor (RECON→TRACKER; CREDENTIAL/PRIVESC/PERSISTENCE→SPECTER;
LATERAL→TRACKER+SPECTER) y `/shield/api/attack-graph` muestra la ruta a `/portal/admin`.

## Prohibido

Tocar `backend/app/*`; apuntar a orígenes que no sean localhost (o el host de `wrangler dev`
en el allowlist del `ScopeGuard`); agregar dependencias; ejecutar comandos/exploits reales.
