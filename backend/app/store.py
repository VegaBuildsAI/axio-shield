"""Estado compartido: sesiones, ventana de eventos (para correlación), incidentes
y persistencia SQLite del audit log inmutable.

Escala de demo: estado vivo en memoria (para el dashboard) + SQLite para el audit
trail y los incidentes (sobreviven reinicios y se exportan para reguladores).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any

from app.models.events import Incident, IngestEvent


class Store:
    def __init__(self, db_path: str, swarm_window_seconds: int = 120) -> None:
        self.window = swarm_window_seconds
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

        # Estado vivo en memoria
        self.sessions: dict[str, dict[str, Any]] = {}
        self.event_window: list[dict[str, Any]] = []
        self.incidents: list[Incident] = []

    # ---------- SQLite ----------
    def _init_db(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY,
                ts REAL, agent TEXT, action TEXT, subject_id TEXT,
                payload TEXT, prev_hash TEXT, hash TEXT
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY, ts REAL, data TEXT
            );
            """
        )
        self._conn.commit()

    # ---------- Sesiones / ventana de eventos ----------
    def add_event(self, event: IngestEvent, matched_rules: list[str], score: float) -> None:
        extra = event.extra or {}
        phase = str(extra.get("phase", "")).lower()
        # Identidad usada (para detectar movimiento lateral: misma identidad/token en varias sesiones).
        identity = (extra.get("agent_id") or extra.get("identity")
                    or (f"token:{extra.get('token')}" if extra.get("token") else None))
        target = extra.get("target") or event.path
        with self._lock:
            s = self.sessions.setdefault(
                event.session_id,
                {"first_seen": event.ts, "event_count": 0, "paths": set(), "uas": set(),
                 "max_score": 0.0, "timeline": []},
            )
            s["last_seen"] = event.ts
            s["event_count"] += 1
            s["paths"].add(event.path)
            s["uas"].add(event.ua)
            s["max_score"] = max(s["max_score"], score)
            # Timeline por sesión: fase + técnicas (para kill-chain / evasión adaptativa).
            s.setdefault("timeline", []).append(
                {"ts": event.ts, "phase": phase, "rules": list(matched_rules), "score": score}
            )

            self.event_window.append(
                {
                    "ts": event.ts,
                    "session_id": event.session_id,
                    "path": event.path,
                    "matched_rules": matched_rules,
                    "features": event.features,
                    "score": score,
                    "identity": identity,
                    "target": target,
                    "phase": phase,
                }
            )
            cutoff = time.time() - self.window
            self.event_window = [e for e in self.event_window if e["ts"] >= cutoff]

    def recent_events(self) -> list[dict[str, Any]]:
        cutoff = time.time() - self.window
        with self._lock:
            return [e for e in self.event_window if e["ts"] >= cutoff]

    def session_timeline(self, session_id: str) -> list[dict[str, Any]]:
        with self._lock:
            s = self.sessions.get(session_id)
            return list(s.get("timeline", [])) if s else []

    # ---------- Incidentes ----------
    def add_incident(self, incident: Incident) -> None:
        with self._lock:
            self.incidents.append(incident)
            self.incidents = self.incidents[-500:]  # bound
            self._conn.execute(
                "INSERT OR REPLACE INTO incidents (id, ts, data) VALUES (?,?,?)",
                (incident.id, incident.ts, incident.model_dump_json()),
            )
            self._conn.commit()

    def get_incident(self, incident_id: str) -> Incident | None:
        for inc in reversed(self.incidents):
            if inc.id == incident_id:
                return inc
        return None

    def list_incidents(self, limit: int = 200) -> list[Incident]:
        with self._lock:
            return list(reversed(self.incidents[-limit:]))

    def update_incident(self, incident: Incident) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO incidents (id, ts, data) VALUES (?,?,?)",
                (incident.id, incident.ts, incident.model_dump_json()),
            )
            self._conn.commit()

    # ---------- Audit (usado por SCRIBE) ----------
    def audit_last(self) -> sqlite3.Row | None:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 1")
            return cur.fetchone()

    def audit_append(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit (seq, ts, agent, action, subject_id, payload, prev_hash, hash) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    record["seq"], record["ts"], record["agent"], record["action"],
                    record["subject_id"], json.dumps(record["payload"]),
                    record["prev_hash"], record["hash"],
                ),
            )
            self._conn.commit()

    def audit_all(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM audit ORDER BY seq ASC").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["payload"] = json.loads(d["payload"])
            out.append(d)
        return out

    def close(self) -> None:
        self._conn.close()
