"""Base para señales adversarias sintéticas, tipadas y metadata-only."""
from __future__ import annotations

from typing import Any

from simulator.attacker_agents.base_attacker import BaseAttacker
from simulator.engine.action_executor import AttackAction
from simulator.engine.state_machine import AttackPhase


class MetadataSignalAgent(BaseAttacker):
    """Publica una señal fixture sin transportar contenido, tokens ni instrucciones."""

    def emit(
        self,
        *,
        session_id: str,
        action_suffix: str,
        attacker_id: str,
        phase: AttackPhase,
        fixture_id: str,
        features: dict[str, Any],
        client_matches: list[str] | None = None,
        extra: dict[str, Any] | None = None,
        kind: str = "dom_anomaly",
        event_path: str = "/portal/",
    ) -> dict[str, Any]:
        action = AttackAction(
            action_id=f"{self.context.scenario_id}:{action_suffix}",
            attacker_id=attacker_id,
            session_id=session_id,
            phase=phase.value,
            action_type="emit_event",
            route="/ingest",
            fixture_id=fixture_id,
            scheduled_at=self.context.clock.tick(0.2),
            event={
                "session_id": session_id,
                "kind": kind,
                "path": event_path,
                "ua": "AXIO-Simulator/1.0 local-demo-only",
                "features": features,
                "client_matches": client_matches or [],
                "extra": {
                    "simulator": True,
                    "fixture_id": fixture_id,
                    **(extra or {}),
                },
            },
        )
        observation = self.context.executor.execute(action)
        safe_metadata = {}
        if extra and "objective_result" in extra:
            safe_metadata["objective_result"] = extra["objective_result"]
        for key in ("phase", "identity", "token", "target"):
            if extra and key in extra:
                safe_metadata[key] = extra[key]
        self.record(action, observation, metadata=safe_metadata)
        return observation
