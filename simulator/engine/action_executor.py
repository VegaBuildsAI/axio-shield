"""Ejecutor de acciones tipadas. No contiene shell ni ejecucion arbitraria."""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Any

from simulator.engine.scope_guard import ScopeGuard
from simulator.engine.scope_guard import ScopeViolation


@dataclass(frozen=True)
class AttackAction:
    action_id: str
    attacker_id: str
    session_id: str
    phase: str
    action_type: str
    route: str
    event: dict[str, Any]
    fixture_id: str
    scheduled_at: float


class ActionExecutor:
    """Emite solo eventos JSON al endpoint local /ingest."""

    ALLOWED_ACTIONS = frozenset({"emit_event"})

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
            raise ScopeViolation("redireccion no permitida en local-demo-only")

    def __init__(self, base_url: str, scope: ScopeGuard | None = None, timeout: float = 5.0) -> None:
        self.scope = scope or ScopeGuard()
        self.base_url = self.scope.validate_base_url(base_url)
        self.timeout = timeout
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), self._NoRedirect()
        )

    def execute(self, action: AttackAction) -> dict[str, Any]:
        if action.action_type not in self.ALLOWED_ACTIONS:
            raise ValueError(f"accion no permitida: {action.action_type}")
        if action.route != "/ingest":
            raise ScopeViolation("el primer incremento solo publica eventos en /ingest")
        target = self.scope.validate_route(self.base_url, action.route)
        data = json.dumps(action.event, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            target,
            data=data,
            headers={"Content-Type": "application/json", "X-Axio-Simulator": "local-demo-only"},
            method="POST",
        )
        with self._opener.open(request, timeout=self.timeout) as response:
            body = response.read().decode("utf-8")
        return json.loads(body)
