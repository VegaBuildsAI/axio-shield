"""SCRIBE — Audit Logger inmutable con hash chaining.

Cada registro encadena el hash del anterior (estilo blockchain / Merkle chain):
    hash_n = sha256(prev_hash + seq + ts + agent + action + subject + payload)
Alterar cualquier registro rompe la cadena a partir de ahí -> `verify_chain` lo detecta.
Argumento de cumplimiento: EU AI Act Art. 12 (logging), DORA, PCI DSS.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from app.store import Store

log = logging.getLogger("shield.scribe")

GENESIS = "0" * 64


def _hash(prev_hash: str, seq: int, ts: float, agent: str, action: str,
          subject_id: str, payload: dict[str, Any]) -> str:
    body = json.dumps(
        {
            "prev": prev_hash, "seq": seq, "ts": ts, "agent": agent,
            "action": action, "subject": subject_id, "payload": payload,
        },
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class Scribe:
    name = "SCRIBE"

    def __init__(self, store: Store, broadcast: Callable[[dict], Awaitable[None]] | None = None) -> None:
        self.store = store
        self._lock = asyncio.Lock()
        # Broadcaster opcional: emite la actividad de cada agente defensor a la Arena en vivo.
        self.broadcast = broadcast

    async def write(self, *, agent: str, action: str, subject_id: str,
                    payload: dict[str, Any]) -> dict[str, Any]:
        async with self._lock:
            last = self.store.audit_last()
            prev_hash = last["hash"] if last else GENESIS
            seq = (last["seq"] + 1) if last else 1
            ts = time.time()
            h = _hash(prev_hash, seq, ts, agent, action, subject_id, payload)
            record = {
                "seq": seq, "ts": ts, "agent": agent, "action": action,
                "subject_id": subject_id, "payload": payload,
                "prev_hash": prev_hash, "hash": h,
            }
            self.store.audit_append(record)

        # Fuera del lock: telemetría de defensa para la Arena (SENTINEL/ORACLE/TRACKER/...).
        if self.broadcast is not None:
            try:
                await self.broadcast({
                    "type": "defense", "agent": agent, "action": action,
                    "subject_id": subject_id, "ts": ts, "payload": payload,
                })
            except Exception:  # noqa: BLE001 — fail-safe: la telemetría no rompe el audit
                log.debug("broadcast de defensa falló (ignorado)")
        return record

    def export(self) -> list[dict[str, Any]]:
        return self.store.audit_all()

    def verify_chain(self) -> tuple[bool, int | None]:
        """Recorre la cadena. Devuelve (ok, seq_donde_rompe|None)."""
        prev_hash = GENESIS
        for rec in self.store.audit_all():
            expected = _hash(
                prev_hash, rec["seq"], rec["ts"], rec["agent"],
                rec["action"], rec["subject_id"], rec["payload"],
            )
            if rec["prev_hash"] != prev_hash or rec["hash"] != expected:
                return False, rec["seq"]
            prev_hash = rec["hash"]
        return True, None
