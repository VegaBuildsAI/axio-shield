"""Agente que emula telemetria de navegador automatizado."""
from __future__ import annotations

from typing import Any

from simulator.attacker_agents.base_attacker import BaseAttacker
from simulator.engine.action_executor import AttackAction
from simulator.engine.state_machine import AttackPhase


class BrowserAgent(BaseAttacker):
    name = "BROWSER_AGENT"

    def run(self, session_id: str) -> list[dict[str, Any]]:
        observations: list[dict[str, Any]] = []
        ua = "Mozilla/5.0 (compatible; PerplexityBot/1.0)"
        events = (
            ("page_load", 0.0, {}, "browser.page_load.v1"),
            ("form_submit", 0.15, {"form_fill_ms": 120, "field_count": 3}, "browser.fast_form.v1"),
        )
        for index, (kind, delay, features, fixture_id) in enumerate(events, start=1):
            ts = self.context.clock.tick(delay)
            action = AttackAction(
                action_id=f"{self.context.scenario_id}:browser:{index}",
                attacker_id=self.name,
                session_id=session_id,
                phase=AttackPhase.DELIVERY.value,
                action_type="emit_event",
                route="/ingest",
                fixture_id=fixture_id,
                scheduled_at=ts,
                event={
                    "session_id": session_id,
                    "kind": kind,
                    "path": "/portal/",
                    "ua": ua,
                    "features": features,
                    "extra": {"simulator": True, "fixture_id": fixture_id},
                },
            )
            observation = self.context.executor.execute(action)
            self.record(action, observation)
            observations.append(observation)
        return observations

