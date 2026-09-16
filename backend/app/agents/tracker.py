"""TRACKER — Swarm Intelligence + Kill-chain (TRACKER++).

Ve el patrón COLECTIVO, no la sesión individual:
  - Swarm cross-sesión: sesiones "independientes" coordinadas (dead-drops / TTP / timing).
  - Kill-chain por sesión: una sola sesión que escala por fases
    (recon→delivery→exploit→persistence→c2) = UNA campaña, con severidad creciente.
  - Evasión adaptativa: la sesión cambia de TTP DESPUÉS de ser detectada.

Ya no publica el incidente: es un `enrich(incident)` que el coordinador del pipeline invoca.
"""
from __future__ import annotations

from app.config import Settings
from app.core.base_agent import BaseDefenderAgent
from app.core.claude_client import ClaudeClient
from app.core.event_bus import EventBus
from app.core.event_bus import TOPIC_CLASSIFIED, TOPIC_INCIDENT
from app.models.events import (
    AttackerProfile,
    AttackPathAssessment,
    Incident,
    KillChainAssessment,
    SwarmAssessment,
    Urgency,
)

# Labels que representan alcanzar un objetivo de alto valor (= "compromiso").
HIGH_VALUE_LABELS = {
    "identity.privilege_escalation", "identity.api_key_access",
    "data.exfiltration_canary", "data.database_query_abuse",
}
from app.store import Store


class Tracker(BaseDefenderAgent):
    name = "TRACKER"

    def __init__(self, bus: EventBus, store: Store, claude: ClaudeClient,
                 settings: Settings, audit=None) -> None:
        super().__init__(bus, audit)
        self.store = store
        self.claude = claude
        self.settings = settings

    def register(self) -> None:
        """Compatibilidad con el arnés legacy; main.py usa enrich explícito."""
        self.bus.subscribe(TOPIC_CLASSIFIED, self._on_classified)

    async def _on_classified(self, payload) -> None:
        # ORACLE moderno publica (incident, event); el arnés legacy publicaba solo Incident.
        incident = payload[0] if isinstance(payload, tuple) else payload
        await self.enrich(incident)
        self.store.update_incident(incident)
        self.bus.publish(TOPIC_INCIDENT, incident)

    # ---------- Swarm cross-sesión (como antes) ----------
    def _assess_swarm(self) -> SwarmAssessment:
        recent = [e for e in self.store.recent_events() if e["score"] > 0]
        order: list[str] = []
        for e in recent:
            if e["session_id"] not in order:
                order.append(e["session_id"])

        min_s = self.settings.swarm_min_sessions
        deaddrop_sessions = {e["session_id"] for e in recent if "swarm.deaddrop" in e["matched_rules"]}
        label_sessions: dict[str, set[str]] = {}
        for e in recent:
            for lbl in e["matched_rules"]:
                label_sessions.setdefault(lbl, set()).add(e["session_id"])
        shared_ttp = {lbl for lbl, ss in label_sessions.items() if len(ss) >= 2}

        coordinated = len(order) >= min_s and (bool(deaddrop_sessions) or bool(shared_ttp))
        if not coordinated:
            return SwarmAssessment(session_ids=order, coordinated=False, confidence=0.0)

        counts: dict[str, int] = {}
        for e in recent:
            counts[e["session_id"]] = counts.get(e["session_id"], 0) + 1
        c2 = max(counts, key=counts.get)
        roles: dict[str, str] = {}
        for sid in order:
            if sid in deaddrop_sessions:
                roles[sid] = "exfiltrator"
            elif sid == order[0]:
                roles[sid] = "exploiter"
            elif sid == c2:
                roles[sid] = "C2_manager"
            else:
                roles[sid] = "recruiter"

        indicator = ("dead-drops en campos libres del portal" if deaddrop_sessions
                     else f"TTP compartido entre sesiones: {sorted(shared_ttp)}")
        return SwarmAssessment(
            session_ids=order, coordinated=True, roles=roles, c2_indicator=indicator,
            confidence=round(min(0.95, 0.5 + 0.1 * len(order)), 3),
            rationale=(f"{len(order)} sesiones coordinadas en ventana de "
                       f"{self.settings.swarm_window_seconds}s; "
                       f"{'dead-drops; ' if deaddrop_sessions else ''}"
                       f"{'TTP compartido; ' if shared_ttp else ''}"),
            engine="rules",
        )

    # ---------- Kill-chain por sesión (nuevo) ----------
    def _assess_killchain(self, session_id: str) -> KillChainAssessment:
        timeline = self.store.session_timeline(session_id)
        phases: list[str] = []
        for entry in timeline:
            p = entry.get("phase")
            if p and p not in phases:
                phases.append(p)
        techniques: list[str] = []
        for entry in timeline:
            for r in entry.get("rules", []):
                if r not in techniques:
                    techniques.append(r)

        # Evasión adaptativa: tras la primera detección, aparece una técnica nueva.
        adaptive = False
        seen: set[str] = set()
        detected_yet = False
        for entry in timeline:
            rules = set(entry.get("rules", []))
            if detected_yet and (rules - seen):
                adaptive = True
            if rules:
                detected_yet = True
            seen |= rules

        escalating = len(phases) >= 3
        return KillChainAssessment(
            session_id=session_id, phases=phases, techniques=techniques,
            escalating=escalating, adaptive_evasion=adaptive,
            confidence=round(min(0.95, 0.4 + 0.15 * len(phases)), 3),
            rationale=(f"sesión escaló por fases {phases}; "
                       f"{'evasión adaptativa (rotó TTP tras detección); ' if adaptive else ''}"),
        )

    # ---------- Grafo de rutas de ataque (BloodHound-style) ----------
    def assess_attack_path(self) -> AttackPathAssessment:
        recent = [e for e in self.store.recent_events() if e["score"] > 0]
        if not recent:
            return AttackPathAssessment()

        nodes: dict[str, dict] = {}
        edges: list[dict] = []

        def node(nid: str, kind: str, label: str) -> None:
            nodes.setdefault(nid, {"id": nid, "kind": kind, "label": label})

        identity_sessions: dict[str, set[str]] = {}
        compromise: set[str] = set()

        for e in recent:
            sid = "s:" + e["session_id"]
            node(sid, "session", e["session_id"][:12])
            tech = ",".join(e["matched_rules"])
            phase = e.get("phase", "")

            ident = e.get("identity")
            if ident:
                nid = "i:" + str(ident)
                node(nid, "identity", str(ident))
                edges.append({"src": nid, "dst": sid, "phase": phase, "technique": tech})
                identity_sessions.setdefault(str(ident), set()).add(sid)

            tgt = "t:" + str(e.get("target") or "/")
            node(tgt, "target", str(e.get("target") or "/"))
            edges.append({"src": sid, "dst": tgt, "phase": phase, "technique": tech})
            if HIGH_VALUE_LABELS.intersection(e["matched_rules"]):
                compromise.add(tgt)

        lateral = any(len(s) >= 2 for s in identity_sessions.values())
        reached = bool(compromise)
        shortest = self._shortest_path(edges, list(nodes), compromise) if reached else []

        return AttackPathAssessment(
            nodes=list(nodes.values()), edges=edges,
            lateral_movement=lateral, shortest_path=shortest, compromise_reached=reached,
            rationale=(f"{len(nodes)} nodos; "
                       f"{'movimiento lateral (identidad reusada entre sesiones); ' if lateral else ''}"
                       f"{'ruta a objetivo de alto valor detectada; ' if reached else ''}"),
        )

    @staticmethod
    def _shortest_path(edges: list[dict], node_ids: list[str], targets: set[str]) -> list[str]:
        """BFS desde un nodo de identidad (o sesión) hasta el objetivo comprometido."""
        adj: dict[str, list[str]] = {}
        for ed in edges:
            adj.setdefault(ed["src"], []).append(ed["dst"])
        starts = [n for n in node_ids if n.startswith("i:")] or [n for n in node_ids if n.startswith("s:")]
        for start in starts:
            queue: list[list[str]] = [[start]]
            seen = {start}
            while queue:
                path = queue.pop(0)
                if path[-1] in targets:
                    return path
                for nxt in adj.get(path[-1], []):
                    if nxt not in seen:
                        seen.add(nxt)
                        queue.append(path + [nxt])
        return []

    async def enrich(self, incident: Incident) -> None:
        swarm = self._assess_swarm()
        if swarm.coordinated:
            incident.swarm = swarm
            incident.attacker_profile = AttackerProfile.SWARM
            if incident.urgency in (Urgency.INFO, Urgency.WATCH):
                incident.urgency = Urgency.CONTAIN
            incident.rationale += f" | TRACKER(swarm): {swarm.rationale}"
            await self.record("swarm_detected", incident.id,
                              {"sessions": swarm.session_ids, "roles": swarm.roles,
                               "c2": swarm.c2_indicator, "confidence": swarm.confidence})

        kc = self._assess_killchain(incident.session_id)
        if kc.escalating or kc.adaptive_evasion:
            incident.killchain = kc
            if kc.adaptive_evasion and kc.escalating:
                incident.urgency = Urgency.ELIMINATE
            elif incident.urgency in (Urgency.INFO, Urgency.WATCH):
                incident.urgency = Urgency.CONTAIN
            if incident.attacker_profile in (AttackerProfile.HUMAN, AttackerProfile.UNKNOWN):
                incident.attacker_profile = AttackerProfile.AUTONOMOUS
            incident.rationale += f" | TRACKER(kill-chain): {kc.rationale}"
            await self.record("killchain_detected", incident.id,
                              {"session": kc.session_id, "phases": kc.phases,
                               "adaptive_evasion": kc.adaptive_evasion, "confidence": kc.confidence})

        path = self.assess_attack_path()
        if path.lateral_movement or path.compromise_reached:
            incident.attack_path = path
            if incident.urgency in (Urgency.INFO, Urgency.WATCH):
                incident.urgency = Urgency.CONTAIN
            if path.compromise_reached:
                incident.urgency = Urgency.ELIMINATE
            incident.rationale += f" | TRACKER(attack-path): {path.rationale}"
            await self.record("attack_path_detected", incident.id,
                              {"lateral_movement": path.lateral_movement,
                               "compromise_reached": path.compromise_reached,
                               "shortest_path": path.shortest_path})
