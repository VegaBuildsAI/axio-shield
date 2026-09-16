"""Matriz de cobertura (estilo `detection-findings.md` del AD lab).

Por cada técnica del vocabulario: quién es el defensor dueño, su mapeo OWASP/ATT&CK/ATLAS,
si existe una regla y si fue ejercida (vista en incidentes). Es el entregable
"atrapado vs. escapado" para el auditor del banco.
"""
from __future__ import annotations

from typing import Any

from app.detection.frameworks import frameworks_for
from app.detection.rules import RULE_WEIGHTS, map_owasp
from app.store import Store

# Qué agente defensor "posee" cada familia de técnica.
DEFENDER_OWNERSHIP: dict[str, str] = {
    "prompt_injection.instruction_override": "SENTINEL/ORACLE",
    "prompt_injection.role_hijack": "SENTINEL/ORACLE",
    "prompt_injection.exfil": "SENTINEL/ORACLE",
    "xss.script": "SENTINEL/ORACLE",
    "sqli": "SENTINEL/ORACLE",
    "ssrf": "SENTINEL/ORACLE",
    "ai_browser.ua": "SENTINEL/ORACLE",
    "automation.headless": "SENTINEL/ORACLE",
    "automation.client": "SENTINEL/ORACLE",
    "automation.timing": "SENTINEL/ORACLE",
    "agent_framework": "ORACLE",
    "swarm.deaddrop": "TRACKER",
    "agent.c2_migration": "TRACKER",
    "recon.enumeration": "TRACKER",
    "identity.lateral_movement": "TRACKER/SPECTER",
    "agent.tool_poisoning": "WARDEN",
    "agent.memory_poisoning": "WARDEN",
    "agent.scope_escape_attempt": "WARDEN",
    "tool.high_impact_call": "WARDEN",
    "identity.cross_tenant": "SPECTER",
    "identity.credential_access": "SPECTER",
    "identity.session_token_access": "SPECTER",
    "identity.api_key_access": "SPECTER",
    "identity.privilege_escalation": "SPECTER",
    "agent.a2a_spoof": "SPECTER",
    "persistence.rogue_rule": "SPECTER/WARDEN",
    "data.database_query_abuse": "ORACLE",
    "data.exfiltration_canary": "ORACLE/HERALD",
}


def coverage_matrix(store: Store) -> list[dict[str, Any]]:
    """Una fila por técnica conocida, con estado de cobertura y mapeo de frameworks."""
    exercised: set[str] = set()
    for inc in store.list_incidents(limit=1000):
        exercised.update(inc.matched_rules)

    rows: list[dict[str, Any]] = []
    for label in sorted(RULE_WEIGHTS):
        owasp, owasp_name = map_owasp([label])
        fw = frameworks_for([label])
        seen = label in exercised
        rows.append({
            "technique": label,
            "owasp": owasp,
            "owasp_name": owasp_name,
            "attack": fw["attack"],
            "atlas": fw["atlas"],
            "defender": DEFENDER_OWNERSHIP.get(label, "—"),
            "rule_exists": True,           # está en RULE_WEIGHTS => hay regla determinista
            "exercised": seen,
            "status": "detectado" if seen else "cubierto (no ejercido)",
        })
    return rows


def summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "tecnicas": len(rows),
        "con_regla": sum(1 for r in rows if r["rule_exists"]),
        "ejercidas_y_detectadas": sum(1 for r in rows if r["exercised"]),
    }


def to_markdown(rows: list[dict[str, Any]]) -> str:
    s = summary(rows)
    out = [
        "# AXIO Shield — Detection Findings (matriz de cobertura)",
        "",
        "> Generado automáticamente. Metodología purple-team: cada técnica se cruza contra el",
        "> defensor dueño y los frameworks OWASP ASI / MITRE ATT&CK / MITRE ATLAS.",
        "",
        f"**Técnicas con regla:** {s['con_regla']}/{s['tecnicas']} · "
        f"**Ejercidas y detectadas:** {s['ejercidas_y_detectadas']}",
        "",
        "| Técnica | Estado | Defensor | OWASP | MITRE ATT&CK | MITRE ATLAS |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        out.append(
            f"| `{r['technique']}` | {r['status']} | {r['defender']} | "
            f"{r['owasp']} {r['owasp_name']} | {'; '.join(r['attack']) or '—'} | "
            f"{'; '.join(r['atlas']) or '—'} |"
        )
    out += [
        "",
        "## Gaps conocidos (honestidad intelectual)",
        "",
        "- La detección basada en labels del SDK es un *hint*; el sensor server-side `/tap`",
        "  cierra el bypass del SDK con `server_matches` autoritativos.",
        "- Una técnica sin regla en `RULE_WEIGHTS` no se detecta — el catálogo se amplía por el",
        "  bucle purple-team (atacar → gap → regla nueva → re-test).",
    ]
    return "\n".join(out) + "\n"
