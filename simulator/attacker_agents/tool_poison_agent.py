"""Tool poisoning local: cambio sintético de metadata de una herramienta."""
from __future__ import annotations

from simulator.attacker_agents.metadata_signal_agent import MetadataSignalAgent
from simulator.engine.state_machine import AttackPhase


class ToolPoisoningAgent(MetadataSignalAgent):
    name = "TOOL_POISONING_AGENT"

    def run(self, session_id: str) -> dict:
        return self.emit(
            session_id=session_id,
            action_suffix="tool-poisoning:registry-mutation",
            attacker_id=self.name,
            phase=AttackPhase.DELIVERY,
            fixture_id="tool_poisoning.registry_metadata.v1",
            features={"tool_poisoning_suspect": True},
            client_matches=["agent.tool_poisoning"],
            extra={"tool_fixture": "transfer_lookup", "mutation": "description_only"},
        )
