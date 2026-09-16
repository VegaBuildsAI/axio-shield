# AXIO Shield · laboratorio ofensivo local

Este paquete contiene agentes atacantes deterministas para validar el portal demo
y el pipeline defensivo. No es un framework de pentesting general.

Garantias del primer incremento:

- solo HTTP hacia `localhost` o `127.0.0.1`;
- sin proxies, redirecciones, DNS externo ni Internet;
- solo acciones tipadas de emision de metadata a `/ingest`;
- sin shell, `eval`, `exec`, credenciales o exploits;
- canarios en memoria y ground truth separado de la telemetria defensiva;
- la misma semilla produce los mismos IDs, fases y fixtures.

Uso desde la raiz del proyecto:

```text
python -m simulator.attack_sim baseline --url http://127.0.0.1:8000
python -m simulator.attack_sim injection --url http://127.0.0.1:8000
python -m simulator.attack_sim ai_browser --url http://127.0.0.1:8000
python -m simulator.attack_sim swarm --sessions 3 --url http://127.0.0.1:8000
python -m simulator.attack_sim tool_poisoning --url http://127.0.0.1:8000 --no-sleep
python -m simulator.attack_sim memory_poisoning --url http://127.0.0.1:8000 --no-sleep
python -m simulator.attack_sim identity_abuse --url http://127.0.0.1:8000 --no-sleep
python -m simulator.attack_sim chain --url http://127.0.0.1:8000 --no-sleep
python -m simulator.attack_sim adaptive --url http://127.0.0.1:8000 --no-sleep
python -m simulator.attack_sim objectives --url http://127.0.0.1:8000 --no-sleep
python -m simulator.attack_sim enumeration --url http://127.0.0.1:8000 --no-sleep
python -m simulator.attack_sim credential_harvest --url http://127.0.0.1:8000 --no-sleep
python -m simulator.attack_sim lateral_movement --url http://127.0.0.1:8000 --no-sleep
python -m simulator.attack_sim privilege_escalation --url http://127.0.0.1:8000 --no-sleep
python -m simulator.attack_sim persistence --url http://127.0.0.1:8000 --no-sleep
python -m simulator.attack_sim ad_killchain --url http://127.0.0.1:8000 --no-sleep
python -m simulator.attack_sim all --no-sleep --json
```

El servidor backend debe estar levantado localmente antes de ejecutar los escenarios.

Los escenarios adicionales modelan señales de riesgo sin realizar llamadas MCP/A2A,
lecturas de memoria, autenticación ni ejecución de herramientas. `chain` y `adaptive`
usan pasos y variantes finitos; el evaluador exige detección y cero recepción del canary.
`objectives` alcanza activos señuelo de usuarios/passwords, sesiones, API keys, datos,
privilegios y herramientas, pero solo dentro de `SyntheticTarget`; los valores nunca
se incluyen en telemetría ni ground truth.

Los escenarios AD-inspired usan identidad sintética `svc_account_demo`. El escenario
`lateral_movement` reutiliza el token ficticio `token_pass_the_hash_demo` en dos sesiones;
esto permite probar el grafo y la detección de movimiento lateral sin autenticación real.
