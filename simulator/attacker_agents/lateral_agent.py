"""LATERAL_AGENT: reuso de un token ficticio entre dos sesiones."""
from __future__ import annotations

from simulator.attacker_agents.metadata_signal_agent import MetadataSignalAgent
from simulator.engine.state_machine import AttackPhase


class LateralAgent(MetadataSignalAgent):
    name = "LATERAL_AGENT"
    IDENTITY = "svc_account_demo"
    TOKEN = "token_pass_the_hash_demo"

    def run(self, session_id: str, peer_session_id: str | None = None) -> list[dict]:
        peer = peer_session_id or f"{session_id}_peer"
        steps = (
            (session_id, "wkstn1", "/portal/wkstn1", "lateral.pass_the_hash.wkstn1.v1"),
            (peer, "wkstn2", "/portal/wkstn2", "lateral.pass_the_hash.wkstn2.v1"),
        )
        return [
            self.emit(
                session_id=sid,
                action_suffix=f"lateral:{node}",
                attacker_id=self.name,
                phase=AttackPhase.EXPLOITATION,
                fixture_id=fixture_id,
                client_matches=["identity.lateral_movement"],
                features={"lateral_movement_suspect": True},
                event_path=target,
                extra={
                    "phase": "lateral_movement",
                    "identity": self.IDENTITY,
                    "token": self.TOKEN,
                    "target": target,
                    "workstation": node,
                },
            )
            for sid, node, target, fixture_id in steps
        ]
