"""Colector in-memory: nunca abre un listener ni envia datos fuera del proceso."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CanaryReceipt:
    canary_id: str
    session_id: str
    channel: str


class LocalExfilCollector:
    def __init__(self) -> None:
        self.receipts: list[CanaryReceipt] = []

    def receive(self, canary_id: str, session_id: str, channel: str) -> CanaryReceipt:
        receipt = CanaryReceipt(canary_id, session_id, channel)
        self.receipts.append(receipt)
        return receipt

    def has_receipts(self) -> bool:
        return bool(self.receipts)

