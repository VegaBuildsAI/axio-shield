"""PRIVESC_AGENT: escalada de privilegios sobre una superficie señuelo."""
from __future__ import annotations

from simulator.attacker_agents.metadata_signal_agent import MetadataSignalAgent
from simulator.engine.state_machine import AttackPhase


class PrivescAgent(MetadataSignalAgent):
    name = "PRIVESC_AGENT"

    def run(self, session_id: str) -> dict:
        return self.emit(
            session_id=session_id,
            action_suffix="privesc:dcsync-acl",
            attacker_id=self.name,
            phase=AttackPhase.EXPLOITATION,
            fixture_id="privesc.dcsync_acl.v1",
            client_matches=["identity.privilege_escalation", "identity.api_key_access"],
            features={
                "privilege_escalation_attempt": True,
                "api_key_access_attempt": True,
            },
            event_path="/portal/admin",
            extra={
                "phase": "privilege_escalation",
                "identity": "svc_account_demo",
                "target": "/portal/admin",
            },
        )
