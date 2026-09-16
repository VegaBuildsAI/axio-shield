"""ORACLE — Classifier. Mapea la amenaza a OWASP Agentic Top 10 + perfil + urgencia.

Determinista primero (mapeo de reglas). Solo cuando SENTINEL marcó el caso como
ambiguo (`needs_llm`) se invoca a Claude Haiku para afinar — trabajando sobre labels
y features, nunca sobre contenido crudo.
"""
from __future__ import annotations

from app.core.base_agent import BaseDefenderAgent
from app.core.claude_client import ClaudeClient
from app.core.event_bus import TOPIC_CLASSIFIED, TOPIC_SIGNAL, EventBus
from app.detection.frameworks import frameworks_for
from app.detection.rules import detection_trust, map_owasp
from app.models.events import (
    AttackerProfile,
    IngestEvent,
    Incident,
    ThreatSignal,
    Urgency,
)
from app.store import Store

_SYSTEM = (
    "Eres ORACLE, clasificador de amenazas de AXIO Shield para portales bancarios. "
    "Recibes SOLO metadata: labels de reglas, user-agent y features estadísticas "
    "(nunca contenido de usuario). Clasifica según OWASP Agentic Top 10 (ASI01-ASI10). "
    'Responde SOLO JSON: {"owasp","owasp_name","attacker_profile","urgency","confidence","rationale"}. '
    "attacker_profile ∈ {HUMAN,HUMAN_AI,AUTONOMOUS,SWARM,A2A_HOSTILE,UNKNOWN}. "
    "urgency ∈ {INFO,WATCH,CONTAIN,ELIMINATE}. confidence ∈ [0,1]."
)


def _profile_from_rules(rules: list[str]) -> AttackerProfile:
    if "agent.a2a_spoof" in rules:
        return AttackerProfile.A2A_HOSTILE
    if "swarm.deaddrop" in rules:
        return AttackerProfile.SWARM
    autonomous_markers = {
        "agent_framework", "agent.tool_poisoning", "agent.memory_poisoning",
        "agent.scope_escape_attempt", "agent.c2_migration", "identity.cross_tenant",
    }
    if autonomous_markers.intersection(rules):
        return AttackerProfile.AUTONOMOUS
    if any(r.startswith("automation.") and r != "automation.timing" for r in rules):
        return AttackerProfile.AUTONOMOUS
    if "ai_browser.ua" in rules:
        return AttackerProfile.HUMAN_AI
    return AttackerProfile.HUMAN


def _urgency_from_score(score: float) -> Urgency:
    if score >= 0.9:
        return Urgency.ELIMINATE
    if score >= 0.7:
        return Urgency.CONTAIN
    if score >= 0.4:
        return Urgency.WATCH
    return Urgency.INFO


class Oracle(BaseDefenderAgent):
    name = "ORACLE"

    def __init__(self, bus: EventBus, store: Store, claude: ClaudeClient, audit=None) -> None:
        super().__init__(bus, audit)
        self.store = store
        self.claude = claude

    def register(self) -> None:
        self.bus.subscribe(TOPIC_SIGNAL, self._on_signal)

    def _rules_result(self, signal: ThreatSignal) -> dict:
        code, name = map_owasp(signal.matched_rules)
        return {
            "owasp": code,
            "owasp_name": name,
            "attacker_profile": _profile_from_rules(signal.matched_rules).value,
            "urgency": _urgency_from_score(signal.score).value,
            "confidence": signal.score,
            "rationale": f"Reglas disparadas: {', '.join(signal.matched_rules)}.",
        }

    async def _on_signal(self, payload: tuple[ThreatSignal, IngestEvent]) -> None:
        signal, event = payload
        rules_result = self._rules_result(signal)

        if signal.needs_llm:
            user = (
                f"rules={signal.matched_rules}\nua={event.ua!r}\n"
                f"features={event.features}\nscore={signal.score}\npath={event.path}"
            )
            result, engine = await self.claude.complete_json(
                tier="haiku", system=_SYSTEM, user=user, stub=lambda: rules_result
            )
        else:
            result, engine = rules_result, "rules"

        incident = Incident(
            session_id=signal.session_id,
            kind=event.kind,
            path=event.path,
            ua=event.ua,
            score=signal.score,
            matched_rules=signal.matched_rules,
            owasp=result.get("owasp", rules_result["owasp"]),
            owasp_name=result.get("owasp_name", rules_result["owasp_name"]),
            attacker_profile=AttackerProfile(result.get("attacker_profile", "UNKNOWN")),
            urgency=Urgency(result.get("urgency", "INFO")),
            confidence=float(result.get("confidence", signal.score)),
            rationale=result.get("rationale", ""),
            trust=detection_trust(event, signal.matched_rules),
            frameworks=frameworks_for(signal.matched_rules),
            evidence={"extra": event.extra or {}, "features": event.features or {}},
        )
        self.store.add_incident(incident)
        await self.record(
            "classified",
            incident.id,
            {
                "session": incident.session_id, "owasp": incident.owasp,
                "profile": incident.attacker_profile.value, "urgency": incident.urgency.value,
                "engine": engine, "trust": incident.trust,
            },
        )
        # Publica el incidente (con evidence embebido) al coordinador de enriquecimiento.
        self.bus.publish(TOPIC_CLASSIFIED, incident)
