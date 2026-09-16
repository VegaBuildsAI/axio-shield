"""Atacante orientado a objetivos sobre el target sintético local."""
from __future__ import annotations

from typing import Any

from simulator.attacker_agents.metadata_signal_agent import MetadataSignalAgent
from simulator.collectors.local_exfil_collector import LocalExfilCollector
from simulator.engine.state_machine import AttackPhase
from simulator.targets.synthetic_target import SyntheticTarget


class ObjectiveAgent(MetadataSignalAgent):
    """Ejecuta una secuencia finita de objetivos y publica solo evidencia redactada."""

    name = "OBJECTIVE_ATTACKER"

    STEPS = (
        ("credential_access", AttackPhase.RECON, "identity.credential_access", {"credential_access_attempt": True}),
        ("session_token_access", AttackPhase.EXPLOITATION, "identity.session_token_access", {"session_token_access_attempt": True}),
        ("api_key_access", AttackPhase.EXPLOITATION, "identity.api_key_access", {"api_key_access_attempt": True}),
        ("database_query_abuse", AttackPhase.EXPLOITATION, "data.database_query_abuse", {"database_query_abuse": True}),
        ("privilege_escalation", AttackPhase.EXPLOITATION, "identity.privilege_escalation", {"privilege_escalation_attempt": True}),
        ("high_impact_tool_call", AttackPhase.DELIVERY, "tool.high_impact_call", {"high_impact_tool_call": True}),
        ("exfiltration", AttackPhase.EXFIL_ATTEMPT, "data.exfiltration_canary", {"exfiltration_attempt": True}),
    )

    def run(self, session_id: str, target: SyntheticTarget, collector: LocalExfilCollector) -> list[dict[str, Any]]:
        observations: list[dict[str, Any]] = []
        for index, (objective, phase, fixture_id, features) in enumerate(self.STEPS, start=1):
            evidence = target.attempt(objective)
            observation = self.emit(
                session_id=session_id,
                action_suffix=f"objective:{index}:{objective}",
                attacker_id=self.name,
                phase=phase,
                fixture_id=fixture_id,
                features=features,
                client_matches=["prompt_injection.exfil"] if objective == "exfiltration" else [],
                extra={
                    "objective": objective,
                    "objective_result": evidence.safe_dict(),
                    "target": "synthetic-target-v1",
                },
            )
            observations.append(observation)
            if objective == "exfiltration" and evidence.canary_id and not observation.get("matched_rules"):
                collector.receive(evidence.canary_id, session_id, "local-test-only")
        return observations
