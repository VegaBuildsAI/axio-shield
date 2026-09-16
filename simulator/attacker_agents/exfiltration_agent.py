"""Agente de exfiltracion: solo canarios y solo colector in-memory."""
from __future__ import annotations

from typing import Any

from simulator.attacker_agents.base_attacker import BaseAttacker
from simulator.collectors.local_exfil_collector import LocalExfilCollector
from simulator.engine.action_executor import AttackAction
from simulator.engine.state_machine import AttackPhase


class ExfiltrationAgent(BaseAttacker):
    name = "EXFILTRATION_AGENT"

    def run(self, session_id: str, collector: LocalExfilCollector) -> dict[str, Any]:
        ts = self.context.clock.tick(0.0)
        fixture_id = "exfil.url_canary.v1"
        action = AttackAction(
            action_id=f"{self.context.scenario_id}:exfil:1",
            attacker_id=self.name,
            session_id=session_id,
            phase=AttackPhase.EXFIL_ATTEMPT.value,
            action_type="emit_event",
            route="/ingest",
            fixture_id=fixture_id,
            scheduled_at=ts,
            event={
                "session_id": session_id,
                "kind": "xhr",
                "path": "/portal/",
                "ua": "Mozilla/5.0 Chrome/125 Safari/537.36",
                "client_matches": ["prompt_injection.exfil"],
                "features": {"form_fill_ms": 900, "field_count": 1},
                "extra": {"simulator": True, "fixture_id": fixture_id, "canary_id": "AXIO_CANARY_DOCUMENT_001"},
            },
        )
        observation = self.context.executor.execute(action)
        self.record(action, observation)
        # En el MVP, una señal de exfiltracion se considera contenida y no llega al colector.
        if "prompt_injection.exfil" not in observation.get("matched_rules", []):
            collector.receive("AXIO_CANARY_DOCUMENT_001", session_id, "local-test-only")
        return observation

