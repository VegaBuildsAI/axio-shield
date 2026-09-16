"""LOCKDOWN — Containment (SIMULADO + human-gate).

IMPORTANTE: en este MVP LOCKDOWN NO toca infraestructura real. Registra la acción de
contención *recomendada* (rate-limit / bloqueo de sesión / revocación de token) que un
operador aprueba explícitamente desde el dashboard. Los bloqueos permanentes SIEMPRE
requieren aprobación humana (human-in-the-loop). En un deploy real, aquí se enchufa la
API del WAF/API-gateway del cliente.
"""
from __future__ import annotations

import time

from app.core.base_agent import BaseDefenderAgent
from app.core.event_bus import EventBus
from app.models.events import Incident
from app.store import Store

# Acciones soportadas -> descripción de lo que haría en producción
ACTIONS = {
    "rate_limit": "Rate-limiting dinámico de la sesión/IP",
    "block_session": "Sandboxing / bloqueo de la sesión sospechosa",
    "revoke_token": "Revocación del token JWT/API key",
    "dismiss": "Descartar (falso positivo)",
}


class Lockdown(BaseDefenderAgent):
    name = "LOCKDOWN"

    def __init__(self, bus: EventBus, store: Store, audit=None) -> None:
        super().__init__(bus, audit)
        self.store = store

    async def apply(self, incident_id: str, action: str, operator: str) -> Incident | None:
        """Aplica (simulado) una acción aprobada por un humano sobre un incidente."""
        incident = self.store.get_incident(incident_id)
        if incident is None or action not in ACTIONS:
            return None

        entry = {
            "action": action,
            "description": ACTIONS[action],
            "operator": operator,
            "ts": time.time(),
            "simulated": True,
        }
        incident.actions.append(entry)
        incident.status = "dismissed" if action == "dismiss" else "contained"
        self.store.update_incident(incident)

        await self.record(
            "human_gate_action",
            incident.id,
            {"action": action, "operator": operator, "new_status": incident.status},
        )
        return incident
