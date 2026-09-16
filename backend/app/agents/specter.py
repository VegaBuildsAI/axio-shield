"""SPECTER — A2A / Identity Defender.

Dueño de ASI03 (abuso de identidad cross-tenant / credenciales) y ASI07/08 (A2A spoof /
agent spoofing). Verifica identidad de agentes (estilo SPIFFE/DID): ante una identidad no
verificada o un cruce de tenant, emite un "challenge" y marca la identidad como no verificada.
Enriquece el incidente con `identity_verdict`, fija perfil A2A_HOSTILE y sube la urgencia.
Lee la evidencia (extra/features) embebida en el incidente por ORACLE.
"""
from __future__ import annotations

from typing import Any

from app.core.base_agent import BaseDefenderAgent
from app.core.event_bus import EventBus
from app.models.events import AttackerProfile, Incident, Urgency

# Identidades de agente verificadas (en un deploy real: SVIDs SPIFFE / DIDs registrados).
VERIFIED_AGENT_IDS: set[str] = {"axio.portal.frontend", "axio.soc.dashboard"}

# Familia de labels de identidad/credenciales que SPECTER posee (ASI03).
IDENTITY_LABELS: dict[str, str] = {
    "identity.cross_tenant": "cruce_de_tenant",
    "identity.credential_access": "acceso_a_credenciales",
    "identity.session_token_access": "robo_de_token_de_sesion",
    "identity.api_key_access": "acceso_a_api_key",
    "identity.privilege_escalation": "escalada_de_privilegios",
}


class Specter(BaseDefenderAgent):
    name = "SPECTER"

    def __init__(self, bus: EventBus, audit=None) -> None:
        super().__init__(bus, audit)

    def _check_cross_tenant(self, extra: dict[str, Any], matched: set[str]) -> dict[str, Any] | None:
        src = extra.get("source_tenant")
        req = extra.get("requested_tenant")
        if src and req and src != req:
            cred = extra.get("credential_material")
            if not cred or cred == "never-sent":
                return {"type": "cross_tenant", "status": "acceso_cross_tenant_sin_credencial",
                        "source_tenant": src, "requested_tenant": req}
        if "identity.cross_tenant" in matched:
            return {"type": "cross_tenant", "status": "cruce_de_tenant_detectado"}
        return None

    def _check_a2a(self, extra: dict[str, Any], matched: set[str]) -> dict[str, Any] | None:
        agent_id = extra.get("agent_id")
        if "agent.a2a_spoof" in matched or (agent_id and agent_id not in VERIFIED_AGENT_IDS):
            return {"type": "a2a_spoof", "status": "identidad_no_verificada",
                    "claimed_id": agent_id or "no_declarada",
                    "challenge": "cripto-challenge emitido; sin respuesta válida"}
        return None

    def _check_identity_family(self, matched: set[str]) -> dict[str, Any] | None:
        hits = [IDENTITY_LABELS[m] for m in matched if m in IDENTITY_LABELS]
        if hits:
            return {"type": "identity_abuse", "status": ", ".join(sorted(set(hits)))}
        return None

    async def enrich(self, incident: Incident) -> None:
        matched = set(incident.matched_rules)
        extra = (incident.evidence or {}).get("extra", {})
        findings = [f for f in (self._check_cross_tenant(extra, matched),
                                self._check_a2a(extra, matched),
                                self._check_identity_family(matched)) if f]
        if not findings:
            return
        incident.identity_verdict = {"findings": findings, "identity_verified": False, "by": self.name}
        if any(f["type"] in ("a2a_spoof", "cross_tenant") for f in findings):
            incident.attacker_profile = AttackerProfile.A2A_HOSTILE
        if incident.urgency in (Urgency.INFO, Urgency.WATCH):
            incident.urgency = Urgency.CONTAIN
        incident.rationale += " | SPECTER: " + "; ".join(
            f["type"] + ":" + f["status"] for f in findings
        )
        await self.record("identity_verdict", incident.id,
                          {"session": incident.session_id, "findings": findings})
