"""BaseDefenderAgent: ciclo de vida común, acceso al bus y audit automático.

Cada agente hereda de aquí. La idea: toda decisión relevante se registra en SCRIBE
(audit-first) antes/al momento de emitirse, para trazabilidad regulatoria.
"""
from __future__ import annotations

import logging
from typing import Any

from app.core.event_bus import EventBus

log = logging.getLogger("shield.agent")


class BaseDefenderAgent:
    name: str = "base"

    def __init__(self, bus: EventBus, audit=None) -> None:
        self.bus = bus
        self.audit = audit  # SCRIBE (o None en tests)

    async def record(self, action: str, subject_id: str, payload: dict[str, Any]) -> None:
        """Escribe una entrada de auditoría atribuida a este agente."""
        if self.audit is not None:
            await self.audit.write(agent=self.name, action=action, subject_id=subject_id, payload=payload)
        else:
            log.debug("[%s] %s %s", self.name, action, subject_id)

    def register(self) -> None:
        """Cada agente sobreescribe esto para suscribirse a sus topics."""
        raise NotImplementedError
