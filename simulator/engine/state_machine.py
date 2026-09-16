"""Maquina de estados finitos para un atacante reproducible."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AttackPhase(StrEnum):
    INIT = "INIT"
    RECON = "RECON"
    DELIVERY = "DELIVERY"
    EXPLOITATION = "EXPLOITATION"
    PERSISTENCE = "PERSISTENCE"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    EXFIL_ATTEMPT = "EXFIL_ATTEMPT"
    ADAPT = "ADAPT"
    STOP = "STOP"


@dataclass
class MachineState:
    phase: AttackPhase = AttackPhase.INIT
    action_count: int = 0
    variant_index: int = 0
    stop_reason: str = ""

    def transition(self, phase: AttackPhase, reason: str) -> None:
        self.phase = phase
        self.stop_reason = reason
