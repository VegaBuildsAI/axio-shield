"""Contrato comun para agentes atacantes sin LLM ni acciones libres."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from simulator.engine.action_executor import ActionExecutor, AttackAction
from simulator.engine.deterministic_clock import DeterministicClock
from simulator.engine.state_machine import MachineState
from simulator.ground_truth.action_log import GroundTruthLog, GroundTruthRecord


@dataclass
class AttackerContext:
    scenario_id: str
    seed: int
    executor: ActionExecutor
    clock: DeterministicClock
    ground_truth: GroundTruthLog
    max_actions: int = 50


class BaseAttacker:
    name = "BASE_ATTACKER"

    def __init__(self, context: AttackerContext) -> None:
        self.context = context
        self.state = MachineState()

    def record(
        self,
        action: AttackAction,
        observation: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if self.state.action_count >= self.context.max_actions:
            raise RuntimeError("presupuesto de acciones del escenario agotado")
        self.state.action_count += 1
        self.context.ground_truth.append(
            GroundTruthRecord(
                action_id=action.action_id,
                scenario_id=self.context.scenario_id,
                attacker_id=action.attacker_id,
                session_id=action.session_id,
                phase=action.phase,
                fixture_id=action.fixture_id,
                observation=observation,
                metadata=metadata or {},
            )
        )
