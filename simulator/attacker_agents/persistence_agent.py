"""PERSISTENCE_AGENT: persistencia por regla señuelo, sin cambios reales."""
from __future__ import annotations

from simulator.attacker_agents.metadata_signal_agent import MetadataSignalAgent
from simulator.engine.state_machine import AttackPhase


class PersistenceAgent(MetadataSignalAgent):
    name = "PERSISTENCE_AGENT"

    def run(self, session_id: str) -> dict:
        return self.emit(
            session_id=session_id,
            action_suffix="persistence:rogue-rule",
            attacker_id=self.name,
            phase=AttackPhase.PERSISTENCE,
            fixture_id="persistence.golden_ticket.rogue_rule.v1",
            client_matches=["persistence.rogue_rule"],
            features={"rogue_rule_suspect": True},
            event_path="/portal/rules",
            extra={
                "phase": "persistence",
                "identity": "svc_account_demo",
                "target": "/portal/rules",
            },
        )
