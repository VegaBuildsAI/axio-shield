"""WAF-tap / reverse-proxy sensor (simulado).

Representa un tap delante del portal del cliente: ve el tráfico REAL (headers + body) y
deriva señales SERVER-SIDE, sin depender de que el SDK del navegador exista o coopere.
Así, un atacante que evita el SDK (pega directo a la API, headless sin script) igual es
inspeccionado. En un deploy real, aquí se enchufa ModSecurity/Cloudflare/API-gateway.
"""
from __future__ import annotations

import uuid
from typing import Any

from app.detection import server_scan
from app.models.events import IngestEvent


def build_event_from_raw(
    *, path: str, headers: dict[str, str], body: str, session_id: str | None = None
) -> IngestEvent:
    """Construye un IngestEvent AUTORITATIVO a partir de tráfico crudo interceptado."""
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    ua = headers.get("user-agent", "")
    sid = session_id or headers.get("x-session-id") or ("tap_" + uuid.uuid4().hex[:12])

    # El sensor ve el contenido real y lo escanea server-side (autoritativo).
    server_matches = server_scan.scan_text(body or "")

    features: dict[str, Any] = {"body_len": len(body or "")}
    return IngestEvent(
        session_id=sid,
        kind="xhr",
        path=path or "/",
        ua=ua,
        client_matches=[],            # el atacante no coopera: no hay hints del cliente
        server_matches=server_matches,  # lo que el sensor detectó por su cuenta
        features=features,
        extra={"source": "waf_tap"},
    )
