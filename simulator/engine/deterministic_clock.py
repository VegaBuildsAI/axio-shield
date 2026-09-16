"""Reloj reproducible para escenarios ofensivos controlados."""
from __future__ import annotations

import time


class DeterministicClock:
    """Entrega timestamps monotonicos reproducibles y duerme solo en modo live."""

    def __init__(self, start: float = 1_700_000_000.0, live: bool = True) -> None:
        self.current = float(start)
        self.live = live

    def tick(self, delta_seconds: float = 0.0) -> float:
        delta = max(0.0, float(delta_seconds))
        if self.live and delta:
            time.sleep(delta)
        self.current = round(self.current + delta, 6)
        return self.current

