"""HERALD — Alert & Escalation. Notificación priorizada al equipo humano.

Escalación por urgencia:
  INFO      -> dashboard (sin interrupción)
  WATCH     -> notificación al analista
  CONTAIN   -> alerta urgente + acción sugerida (requiere aprobación humana)
  ELIMINATE -> alerta crítica + CISO + human-in-the-loop obligatorio
En este MVP la salida es: broadcast al dashboard (WebSocket) + webhook stub opcional.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from app.config import Settings
from app.core.base_agent import BaseDefenderAgent
from app.core.event_bus import TOPIC_INCIDENT, EventBus
from app.models.events import Incident, Urgency

log = logging.getLogger("shield.herald")

_CHANNEL = {
    Urgency.INFO: "dashboard",
    Urgency.WATCH: "analyst",
    Urgency.CONTAIN: "urgent+action",
    Urgency.ELIMINATE: "critical+ciso+hitl",
}

Broadcaster = Callable[[dict], Awaitable[None]]


class Herald(BaseDefenderAgent):
    name = "HERALD"

    def __init__(self, bus: EventBus, settings: Settings, audit=None,
                 broadcast: Broadcaster | None = None) -> None:
        super().__init__(bus, audit)
        self.settings = settings
        self.broadcast = broadcast

    def register(self) -> None:
        self.bus.subscribe(TOPIC_INCIDENT, self._on_incident)

    async def _on_incident(self, incident: Incident) -> None:
        channel = _CHANNEL.get(incident.urgency, "dashboard")
        await self.record(
            "alert",
            incident.id,
            {"channel": channel, "urgency": incident.urgency.value, "owasp": incident.owasp},
        )
        if self.broadcast is not None:
            await self.broadcast({"type": "incident", "channel": channel, "incident": incident.model_dump(mode="json")})
        if self.settings.webhook_url:
            await self._post_webhook(incident, channel)

    async def _post_webhook(self, incident: Incident, channel: str) -> None:
        try:
            import httpx

            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(
                    self.settings.webhook_url,
                    json={"channel": channel, "incident": incident.model_dump(mode="json")},
                )
        except Exception:  # noqa: BLE001 — fail-safe: el webhook no debe tumbar el pipeline
            log.warning("webhook falló (stub, ignorado)")
