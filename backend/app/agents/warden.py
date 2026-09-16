"""WARDEN — Integrity / Provenance Defender.

Dueño de ASI04 (tool poisoning), ASI05 (scope escape) y ASI06 (memory poisoning).
No se limita a leer banderas `*_suspect`: mantiene un baseline de integridad de herramientas
y un registro de procedencia de memoria, y marca desviaciones. Enriquece el incidente con un
`integrity_verdict` y ajusta la urgencia. Cada análisis queda auditado (y enciende su avatar
en la Arena) vía `self.record`.
"""
from __future__ import annotations

import hashlib
from typing import Any

from app.core.base_agent import BaseDefenderAgent
from app.core.event_bus import EventBus
from app.models.events import Incident, Urgency


def _h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# Baseline de metadata de herramientas conocidas del portal (hash de su descripción legítima).
TOOL_BASELINE: dict[str, str] = {
    "transfer_lookup": _h("Looks up a verified transfer destination account"),
    "balance_read": _h("Reads the account balance for the current session"),
    "statement_export": _h("Exports the account statement as PDF"),
}


class Warden(BaseDefenderAgent):
    name = "WARDEN"

    def __init__(self, bus: EventBus, audit=None) -> None:
        super().__init__(bus, audit)
        # Procedencia de escritura en memoria por sesión (tokens legítimos observados).
        self._memory_provenance: dict[str, set[str]] = {}

    def _check_tool(self, extra: dict[str, Any], matched: set[str]) -> dict[str, Any] | None:
        tool = extra.get("tool_fixture")
        if "tool.high_impact_call" in matched:
            return {"type": "tool_high_impact", "tool": tool or "desconocida",
                    "status": "llamada_de_alto_impacto_no_autorizada"}
        if not tool and "agent.tool_poisoning" not in matched:
            return None
        # Si el evento declara una descripción, comparamos contra el baseline (integridad real).
        declared = extra.get("tool_description")
        expected = TOOL_BASELINE.get(str(tool)) if tool else None
        if declared is not None and expected is not None:
            if _h(str(declared)) != expected:
                return {"type": "tool_poisoning", "tool": tool, "status": "metadata_mutada",
                        "expected_hash": expected, "seen_hash": _h(str(declared))}
            return None
        # Sin descripción: la mutación declarada / el label es la evidencia disponible.
        if extra.get("mutation") or "agent.tool_poisoning" in matched:
            return {"type": "tool_poisoning", "tool": tool or "desconocida",
                    "status": "metadata_mutada", "mutation": extra.get("mutation", "declarada")}
        return None

    def _check_memory(self, session_id: str, extra: dict[str, Any],
                      matched: set[str]) -> dict[str, Any] | None:
        scope = str(extra.get("memory_scope", ""))
        if "agent.memory_poisoning" not in matched and not scope.startswith("shared"):
            return None
        seen = self._memory_provenance.setdefault(session_id, set())
        provenance = extra.get("provenance")
        if provenance and provenance in seen:
            return None  # escritura con procedencia conocida = legítima
        if provenance:
            seen.add(provenance)
        return {"type": "memory_poisoning", "scope": scope or "shared",
                "status": "escritura_sin_procedencia"}

    def _check_scope(self, matched: set[str]) -> dict[str, Any] | None:
        if "agent.scope_escape_attempt" in matched:
            return {"type": "scope_escape", "status": "intento_de_salir_del_sandbox"}
        return None

    async def enrich(self, incident: Incident) -> None:
        matched = set(incident.matched_rules)
        extra = (incident.evidence or {}).get("extra", {})
        findings = [f for f in (self._check_tool(extra, matched),
                                self._check_memory(incident.session_id, extra, matched),
                                self._check_scope(matched)) if f]
        if not findings:
            return
        incident.integrity_verdict = {"findings": findings, "by": self.name}
        if incident.urgency in (Urgency.INFO, Urgency.WATCH):
            incident.urgency = Urgency.CONTAIN
        incident.rationale += " | WARDEN: " + "; ".join(
            f["type"] + ":" + f["status"] for f in findings
        )
        await self.record("integrity_verdict", incident.id,
                          {"session": incident.session_id, "findings": findings})
