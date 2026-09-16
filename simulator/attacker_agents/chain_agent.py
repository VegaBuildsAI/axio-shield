"""Cadena multietapa segura: telemetría de TTPs, no ejecución de exploits."""
from __future__ import annotations

from simulator.attacker_agents.metadata_signal_agent import MetadataSignalAgent
from simulator.engine.state_machine import AttackPhase


class ChainAgent(MetadataSignalAgent):
    name = "CHAIN_AGENT"

    def run(self, session_id: str) -> list[dict]:
        steps = (
            ("recon", AttackPhase.RECON, "chain.recon.v1", {"scope_escape_attempt": True}, "agent.scope_escape_attempt"),
            ("tool", AttackPhase.DELIVERY, "chain.tool_poisoning.v1", {"tool_poisoning_suspect": True}, "agent.tool_poisoning"),
            ("memory", AttackPhase.PERSISTENCE, "chain.memory_poisoning.v1", {"memory_poisoning_suspect": True}, "agent.memory_poisoning"),
            ("identity", AttackPhase.EXPLOITATION, "chain.identity_abuse.v1", {"cross_tenant_suspect": True}, "agent.a2a_spoof"),
            ("c2", AttackPhase.COMMAND_AND_CONTROL, "chain.c2_migration.v1", {"c2_migration": True}, "agent.c2_migration"),
        )
        return [
            self.emit(
                session_id=session_id,
                action_suffix=f"chain:{suffix}",
                attacker_id=self.name,
                phase=phase,
                fixture_id=fixture_id,
                features=features,
                client_matches=[label],
                extra={"chain_step": index, "chain_id": self.context.scenario_id},
            )
            for index, (suffix, phase, fixture_id, features, label) in enumerate(steps, start=1)
        ]
