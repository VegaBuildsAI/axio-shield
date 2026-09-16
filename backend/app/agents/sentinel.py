"""SENTINEL — Scanner. Primera línea, determinista.

Recibe el evento normalizado del SDK, lo puntúa con reglas (sin LLM), lo guarda para
correlación y — si hay anomalía — emite un ThreatSignal. Marca `needs_llm` cuando el
score es ambiguo, para que ORACLE decida si invoca a Claude (control de costo).
"""
from __future__ import annotations

from app.config import Settings
from app.core.base_agent import BaseDefenderAgent
from app.core.event_bus import TOPIC_SIGNAL, EventBus
from app.detection.rules import score_event
from app.models.events import IngestEvent, ThreatSignal
from app.store import Store


class Sentinel(BaseDefenderAgent):
    name = "SENTINEL"

    def __init__(self, bus: EventBus, store: Store, settings: Settings, audit=None) -> None:
        super().__init__(bus, audit)
        self.store = store
        self.settings = settings

    async def handle(self, event: IngestEvent) -> ThreatSignal:
        score, matched = score_event(event)
        self.store.add_event(event, matched, score)
        await self.record(
            "scored",
            event.event_id,
            {"session": event.session_id, "score": score, "rules": matched, "kind": event.kind},
        )

        needs_llm = self.settings.sentinel_llm_threshold <= score < self.settings.sentinel_certain
        signal = ThreatSignal(
            event_id=event.event_id,
            session_id=event.session_id,
            score=score,
            matched_rules=matched,
            needs_llm=needs_llm,
            note=event.path,
        )
        # Solo escala en el pipeline si hubo algo (score > 0). Baseline normal no genera incidente.
        if matched:
            self.bus.publish(TOPIC_SIGNAL, (signal, event))
        return signal
