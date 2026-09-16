"""Shield Backend — FastAPI.

Endpoints:
  GET  /health                      salud del servicio
  POST /ingest                      recibe eventos del SDK (entrada del pipeline)
  GET  /api/incidents               lista de incidentes (dashboard)
  GET  /api/sessions                resumen de sesiones (grafo)
  POST /api/incidents/{id}/action   human-gate -> LOCKDOWN (simulado)
  GET  /api/audit/export            exporta el audit log completo
  GET  /api/audit/verify            valida la integridad del hash chain
  WS   /ws                          stream de incidentes en vivo
Static:
  /portal, /dashboard, /sdk         portal-banco simulado, SOC y SDK JS
"""
from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import arena
from app.agents.herald import Herald
from app.agents.lockdown import Lockdown
from app.agents.oracle import Oracle
from app.agents.scribe import Scribe
from app.agents.sentinel import Sentinel
from app.agents.specter import Specter
from app.agents.tracker import Tracker
from app.agents.warden import Warden
from app.config import get_settings
from app.core.claude_client import ClaudeClient
from app.core.event_bus import TOPIC_CLASSIFIED, TOPIC_INCIDENT, EventBus
from app.models.events import IngestEvent
from app.reporting import coverage_matrix
from app.sensors import waf_tap
from app.store import Store

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("shield.main")

REPO_ROOT = Path(os.environ.get("SHIELD_STATIC_ROOT", Path(__file__).resolve().parents[2]))


class ConnectionManager:
    def __init__(self) -> None:
        self.active: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.active.discard(ws)

    async def broadcast(self, message: dict) -> None:
        dead = []
        for ws in list(self.active):
            try:
                await ws.send_json(message)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


class ActionRequest(BaseModel):
    action: str
    operator: str = "analyst"


class TapRequest(BaseModel):
    """Tráfico crudo interceptado por el WAF-tap (sin pasar por el SDK)."""

    path: str = "/"
    headers: dict[str, str] = {}
    body: str = ""
    session_id: str | None = None


class AttackEventIn(BaseModel):
    """Contrato de telemetría de ataque (para el simulador externo / Codex)."""

    attacker_id: str
    phase: str = "delivery"
    technique: str = ""
    session_id: str = ""
    scenario: str = ""
    source: str = "codex"


class ArenaLaunchIn(BaseModel):
    """El operador dispara un ataque desde la Arena."""

    scenario: str = "injection"   # baseline|injection|ai_browser|swarm|agentic|manual
    sessions: int = 3
    payload_labels: list[str] = []


def build_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store = Store(settings.db_path, settings.swarm_window_seconds)
        bus = EventBus()
        manager = ConnectionManager()
        # SCRIBE emite la actividad de cada agente defensor a la Arena en vivo.
        scribe = Scribe(store, broadcast=manager.broadcast)
        claude = ClaudeClient(settings)

        sentinel = Sentinel(bus, store, settings, audit=scribe)
        oracle = Oracle(bus, store, claude, audit=scribe)
        tracker = Tracker(bus, store, claude, settings, audit=scribe)
        warden = Warden(bus, audit=scribe)
        specter = Specter(bus, audit=scribe)
        herald = Herald(bus, settings, audit=scribe, broadcast=manager.broadcast)
        lockdown = Lockdown(bus, store, audit=scribe)

        # Coordinador de enriquecimiento: sobre el MISMO incidente corre, en orden,
        # TRACKER (swarm/kill-chain) -> WARDEN (integridad) -> SPECTER (identidad),
        # y publica UNA sola vez el incidente enriquecido para HERALD/dashboard/Arena.
        async def enrich_and_emit(incident):
            await tracker.enrich(incident)
            await warden.enrich(incident)
            await specter.enrich(incident)
            store.update_incident(incident)
            bus.publish(TOPIC_INCIDENT, incident)

        bus.subscribe(TOPIC_CLASSIFIED, enrich_and_emit)
        oracle.register()   # ORACLE se suscribe a TOPIC_SIGNAL
        herald.register()   # HERALD se suscribe a TOPIC_INCIDENT

        app.state.settings = settings
        app.state.store = store
        app.state.bus = bus
        app.state.manager = manager
        app.state.scribe = scribe
        app.state.sentinel = sentinel
        app.state.tracker = tracker
        app.state.lockdown = lockdown
        log.info("AXIO Shield backend listo (stub_mode=%s)", settings.use_stub)
        yield
        store.close()

    app = FastAPI(title="AXIO Shield Backend", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_list,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health():
        return {"status": "ok", "stub_mode": settings.use_stub}

    @app.post("/ingest")
    async def ingest(event: IngestEvent):
        # Si el evento viene de un agente atacante (propio o de Codex), pintarlo en la Arena.
        attacker = arena.infer_attacker(event)
        if attacker is not None:
            aid, phase = attacker
            await app.state.manager.broadcast({
                "type": "attack", "attacker_id": aid, "phase": phase,
                "technique": ", ".join(event.client_matches) or event.kind,
                "source": "codex", "session_id": event.session_id,
                "scenario": str((event.extra or {}).get("fixture_id", "")),
                "ts": event.ts,
            })
        signal = await app.state.sentinel.handle(event)
        return {
            "ok": True,
            "score": signal.score,
            "matched_rules": signal.matched_rules,
            "needs_llm": signal.needs_llm,
        }

    @app.post("/tap")
    async def tap(req: TapRequest):
        """WAF-tap: inspecciona tráfico CRUDO server-side (sin depender del SDK).

        Demuestra la resiliencia anti-bypass: un atacante que evita el SDK y pega directo
        igual es escaneado por el sensor server-side (server_matches autoritativo).
        """
        event = waf_tap.build_event_from_raw(
            path=req.path, headers=req.headers, body=req.body, session_id=req.session_id
        )
        if event.server_matches:
            await app.state.manager.broadcast({
                "type": "attack", "attacker_id": "SDK_BYPASS", "phase": "delivery",
                "technique": ", ".join(event.server_matches), "source": "tap",
                "session_id": event.session_id, "ts": event.ts,
            })
        signal = await app.state.sentinel.handle(event)
        return {"ok": True, "score": signal.score, "server_matches": event.server_matches,
                "matched_rules": signal.matched_rules}

    @app.get("/api/incidents")
    async def incidents():
        return [i.model_dump(mode="json") for i in app.state.store.list_incidents()]

    @app.get("/api/sessions")
    async def sessions():
        out = []
        for sid, s in app.state.store.sessions.items():
            out.append(
                {
                    "session_id": sid,
                    "first_seen": s["first_seen"],
                    "last_seen": s.get("last_seen", s["first_seen"]),
                    "event_count": s["event_count"],
                    "max_score": s["max_score"],
                    "paths": sorted(s["paths"]),
                }
            )
        return out

    @app.post("/api/incidents/{incident_id}/action")
    async def action(incident_id: str, req: ActionRequest):
        incident = await app.state.lockdown.apply(incident_id, req.action, req.operator)
        if incident is None:
            return {"ok": False, "error": "incidente o acción inválida"}
        await app.state.manager.broadcast(
            {"type": "update", "incident": incident.model_dump(mode="json")}
        )
        return {"ok": True, "incident": incident.model_dump(mode="json")}

    @app.get("/api/attack-graph")
    async def attack_graph():
        """Grafo de rutas de ataque (BloodHound-style) de la ventana actual."""
        return app.state.tracker.assess_attack_path().model_dump(mode="json")

    @app.get("/api/coverage")
    async def coverage():
        """Matriz de cobertura: técnica ↔ defensor ↔ OWASP/ATT&CK/ATLAS ↔ estado."""
        rows = coverage_matrix.coverage_matrix(app.state.store)
        return {"summary": coverage_matrix.summary(rows), "rows": rows}

    @app.get("/api/arena/roster")
    async def arena_roster():
        return {"attackers": arena.ATTACKER_ROSTER, "defenders": arena.DEFENDER_ROSTER}

    @app.post("/api/attack/event")
    async def attack_event(ev: AttackEventIn):
        """Telemetría de ataque desde el simulador externo (Codex). Solo pinta la Arena."""
        await app.state.manager.broadcast({"type": "attack", "ts": time.time(), **ev.model_dump()})
        return {"ok": True}

    @app.post("/api/arena/launch")
    async def arena_launch(req: ArenaLaunchIn):
        """El operador (atacante) dispara un escenario; se ve atacante y defensa en vivo."""
        n = await arena.run_scenario(
            req.scenario, app.state.sentinel, app.state.manager.broadcast,
            sessions=req.sessions, payload_labels=req.payload_labels,
        )
        return {"ok": True, "scenario": req.scenario, "steps": n}

    @app.get("/api/audit/export")
    async def audit_export():
        return app.state.scribe.export()

    @app.get("/api/audit/verify")
    async def audit_verify():
        ok, broken_at = app.state.scribe.verify_chain()
        return {"valid": ok, "broken_at_seq": broken_at}

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        await app.state.manager.connect(websocket)
        try:
            snapshot = [i.model_dump(mode="json") for i in app.state.store.list_incidents()]
            await websocket.send_json({"type": "snapshot", "incidents": snapshot})
            while True:
                await websocket.receive_text()  # mantener viva la conexión (pings del cliente)
        except WebSocketDisconnect:
            app.state.manager.disconnect(websocket)

    @app.get("/")
    async def root():
        return RedirectResponse(url="/portal/")

    # Static (portal, dashboard, sdk). html=True permite servir index.html en la raíz.
    for route, folder in (("/portal", "demo-portal"), ("/dashboard", "dashboard"),
                          ("/arena", "arena"), ("/sdk", "sdk/src"),
                          ("/marketing", "marketing")):
        path = REPO_ROOT / folder
        if path.is_dir():
            app.mount(route, StaticFiles(directory=str(path), html=True), name=folder)

    return app


app = build_app()
