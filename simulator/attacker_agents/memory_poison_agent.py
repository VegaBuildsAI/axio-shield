"""Memory poisoning local: escritura sintética en contexto compartido de prueba."""
from __future__ import annotations

from simulator.attacker_agents.metadata_signal_agent import MetadataSignalAgent
from simulator.engine.state_machine import AttackPhase


class MemoryPoisoningAgent(MetadataSignalAgent):
    name = "MEMORY_POISONING_AGENT"

    def run(self, session_id: str) -> dict:
        return self.emit(
            session_id=session_id,
            action_suffix="memory-poisoning:shared-context",
            attacker_id=self.name,
            phase=AttackPhase.PERSISTENCE,
            fixture_id="memory_poisoning.shared_context.v1",
            features={"memory_poisoning_suspect": True},
            client_matches=["agent.memory_poisoning"],
            extra={"memory_scope": "shared-session-test", "write_type": "synthetic-marker"},
        )
