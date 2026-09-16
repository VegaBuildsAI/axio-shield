"""RECON_AGENT: enumeración sintética de identidades y permisos."""
from __future__ import annotations

from simulator.attacker_agents.metadata_signal_agent import MetadataSignalAgent
from simulator.engine.state_machine import AttackPhase


class ReconAgent(MetadataSignalAgent):
    name = "RECON_AGENT"

    def run(self, session_id: str) -> dict:
        return self.emit(
            session_id=session_id,
            action_suffix="recon:enumeration",
            attacker_id=self.name,
            phase=AttackPhase.RECON,
            fixture_id="recon.enumeration.bloodhound.v1",
            client_matches=["recon.enumeration"],
            features={"enumeration_suspect": True},
            event_path="/portal/directory",
            extra={
                "phase": "recon",
                "identity": "svc_account_demo",
                "target": "/portal/directory",
            },
        )
