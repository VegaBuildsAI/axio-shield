"""Ensambla el swarm defensivo en proceso (sin HTTP) para los tests de integración.

Refleja el wiring de main.py: ORACLE publica el incidente en TOPIC_CLASSIFIED y un
coordinador corre TRACKER -> WARDEN -> SPECTER sobre el mismo incidente antes de emitirlo.
"""
from __future__ import annotations

import pytest

from app.agents.herald import Herald
from app.agents.lockdown import Lockdown
from app.agents.oracle import Oracle
from app.agents.scribe import Scribe
from app.agents.sentinel import Sentinel
from app.agents.specter import Specter
from app.agents.tracker import Tracker
from app.agents.warden import Warden
from app.config import Settings
from app.core.event_bus import TOPIC_CLASSIFIED, TOPIC_INCIDENT, EventBus
from app.core.claude_client import ClaudeClient
from app.store import Store


class System:
    def __init__(self, tmp_db: str) -> None:
        self.settings = Settings(force_stub=True, db_path=tmp_db)
        self.store = Store(self.settings.db_path, self.settings.swarm_window_seconds)
        self.bus = EventBus()
        self.broadcasts: list[dict] = []

        async def _broadcast(msg: dict) -> None:
            self.broadcasts.append(msg)

        self.scribe = Scribe(self.store, broadcast=_broadcast)
        self.claude = ClaudeClient(self.settings)

        self.sentinel = Sentinel(self.bus, self.store, self.settings, audit=self.scribe)
        self.oracle = Oracle(self.bus, self.store, self.claude, audit=self.scribe)
        self.tracker = Tracker(self.bus, self.store, self.claude, self.settings, audit=self.scribe)
        self.warden = Warden(self.bus, audit=self.scribe)
        self.specter = Specter(self.bus, audit=self.scribe)
        self.herald = Herald(self.bus, self.settings, audit=self.scribe, broadcast=_broadcast)
        self.lockdown = Lockdown(self.bus, self.store, audit=self.scribe)

        async def _enrich_and_emit(incident):
            await self.tracker.enrich(incident)
            await self.warden.enrich(incident)
            await self.specter.enrich(incident)
            self.store.update_incident(incident)
            self.bus.publish(TOPIC_INCIDENT, incident)

        self.bus.subscribe(TOPIC_CLASSIFIED, _enrich_and_emit)
        self.oracle.register()
        self.herald.register()


@pytest.fixture
def system(tmp_path):
    return System(str(tmp_path / "test.db"))
