"""Agente de goal hijacking con fixtures de payload, no texto dinamico."""
from __future__ import annotations

from typing import Any

from simulator.attacker_agents.base_attacker import BaseAttacker
from simulator.engine.action_executor import AttackAction
from simulator.engine.state_machine import AttackPhase


class InjectionAgent(BaseAttacker):
    name = "INJECTION_AGENT"

    VARIANTS = (
        ("direct_visible", ("prompt_injection.instruction_override", "prompt_injection.exfil")),
        ("role_hijack", ("prompt_injection.role_hijack",)),
        ("indirect_document", ("prompt_injection.role_hijack", "prompt_injection.exfil")),
    )

    def run(self, session_id: str) -> dict[str, Any]:
        variant_id, labels = self.VARIANTS[0]
        ts = self.context.clock.tick(0.0)
        action = AttackAction(
            action_id=f"{self.context.scenario_id}:injection:{session_id}",
            attacker_id=self.name,
            session_id=session_id,
            phase=AttackPhase.DELIVERY.value,
            action_type="emit_event",
            route="/ingest",
            fixture_id=f"goal_hijack.{variant_id}.v1",
            scheduled_at=ts,
            event={
                "session_id": session_id,
                "kind": "form_submit",
                "path": "/portal/",
                "ua": "Mozilla/5.0 Chrome/125 Safari/537.36",
                "client_matches": list(labels),
                "features": {"form_fill_ms": 1500, "field_count": 3},
                "extra": {"simulator": True, "fixture_id": f"goal_hijack.{variant_id}.v1"},
            },
        )
        observation = self.context.executor.execute(action)
        self.record(action, observation)
        return observation
