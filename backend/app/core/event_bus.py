"""Event bus asíncrono (pub/sub) inter-agente.

Patrón simple sobre asyncio: los agentes se suscriben a un "topic" y publican en
otros. Desacopla SENTINEL -> ORACLE -> TRACKER -> HERALD/LOCKDOWN sin que se
conozcan entre sí. Cada handler corre en su propia task para no bloquear el bus.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

log = logging.getLogger("shield.bus")

Handler = Callable[[Any], Awaitable[None]]


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[str, list[Handler]] = {}
        self._tasks: set[asyncio.Task] = set()

    def subscribe(self, topic: str, handler: Handler) -> None:
        self._subs.setdefault(topic, []).append(handler)

    def publish(self, topic: str, message: Any) -> None:
        """Fire-and-forget: dispara cada handler como task independiente."""
        for handler in self._subs.get(topic, []):
            task = asyncio.create_task(self._run(handler, message, topic))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _run(self, handler: Handler, message: Any, topic: str) -> None:
        try:
            await handler(message)
        except Exception:  # noqa: BLE001 — fail-safe: un handler no tumba el bus
            log.exception("handler falló en topic=%s", topic)

    async def drain(self, idle_rounds: int = 2) -> None:
        """Espera a que se asiente la cascada de handlers (útil en tests).

        Solo espera tasks *pendientes* y cede el control con sleep(0) para que corran
        los done-callbacks y arranquen las tasks recién creadas. Termina cuando no se
        crean nuevas tasks durante `idle_rounds` iteraciones seguidas.
        """
        stable = 0
        while stable < idle_rounds:
            pending = [t for t in list(self._tasks) if not t.done()]
            if pending:
                stable = 0
                await asyncio.gather(*pending, return_exceptions=True)
            else:
                stable += 1
                await asyncio.sleep(0)


# Topics del pipeline defensivo
TOPIC_EVENT = "event.ingested"        # IngestEvent crudo -> SENTINEL
TOPIC_SIGNAL = "threat.signal"        # ThreatSignal -> ORACLE
TOPIC_CLASSIFIED = "threat.classified"  # (Incident) -> TRACKER + HERALD
TOPIC_INCIDENT = "incident.ready"     # Incident final -> HERALD / dashboard
