"""Registro local de acciones y observaciones del simulador."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class GroundTruthRecord:
    action_id: str
    scenario_id: str
    attacker_id: str
    session_id: str
    phase: str
    fixture_id: str
    observation: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class GroundTruthLog:
    def __init__(self) -> None:
        self.records: list[GroundTruthRecord] = []

    def append(self, record: GroundTruthRecord) -> None:
        self.records.append(record)

    def export(self) -> list[dict[str, Any]]:
        return [asdict(record) for record in self.records]
