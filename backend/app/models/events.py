"""Esquemas de datos (pydantic v2) que fluyen por el swarm defensivo.

PRIVACIDAD: el SDK envía SOLO metadata y etiquetas de reglas — nunca el contenido
crudo de los inputs del usuario. `client_matches` son nombres de patrones (labels),
no el texto que los disparó. `features` son señales estadísticas derivadas.
"""
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> float:
    return time.time()


class Urgency(str, Enum):
    INFO = "INFO"
    WATCH = "WATCH"
    CONTAIN = "CONTAIN"
    ELIMINATE = "ELIMINATE"


class AttackerProfile(str, Enum):
    HUMAN = "HUMAN"                 # usuario legítimo o humano manual
    HUMAN_AI = "HUMAN_AI"           # humano + AI browser (Operator, Comet, etc.)
    AUTONOMOUS = "AUTONOMOUS"       # agente autónomo individual (nivel GTG-1002)
    SWARM = "SWARM"                 # swarm coordinado (patrón HuggingFace/OpenAI)
    A2A_HOSTILE = "A2A_HOSTILE"     # agente hostil en ecosistema A2A
    UNKNOWN = "UNKNOWN"


class IngestEvent(BaseModel):
    """Evento normalizado enviado por el SDK JS embebido en el portal del cliente."""

    event_id: str = Field(default_factory=_uuid)
    session_id: str
    ts: float = Field(default_factory=_now)
    kind: str = "dom_event"          # page_load | form_submit | xhr | dom_anomaly
    path: str = "/"                  # ruta del portal donde ocurrió
    ua: str = ""                     # user-agent
    features: dict[str, Any] = Field(default_factory=dict)
    client_matches: list[str] = Field(default_factory=list)   # HINTS no confiables (los manda el cliente)
    server_matches: list[str] = Field(default_factory=list)   # AUTORITATIVO: derivado server-side (sensor /tap)
    client_score: float = 0.0
    extra: dict[str, Any] = Field(default_factory=dict)


class ThreatSignal(BaseModel):
    """Salida de SENTINEL: hay o no anomalía y con qué confianza."""

    event_id: str
    session_id: str
    ts: float = Field(default_factory=_now)
    score: float = 0.0
    matched_rules: list[str] = Field(default_factory=list)
    needs_llm: bool = False
    note: str = ""


class Classification(BaseModel):
    """Salida de ORACLE: mapeo a OWASP Agentic Top 10 + perfil + urgencia."""

    event_id: str
    session_id: str
    ts: float = Field(default_factory=_now)
    owasp: str = "N/A"               # ej. "ASI02"
    owasp_name: str = ""
    attacker_profile: AttackerProfile = AttackerProfile.UNKNOWN
    urgency: Urgency = Urgency.INFO
    confidence: float = 0.0
    rationale: str = ""
    engine: str = "stub"             # "stub" | "haiku" | "rules"


class SwarmAssessment(BaseModel):
    """Salida de TRACKER: ¿estas sesiones son un swarm coordinado?"""

    cluster_id: str = Field(default_factory=_uuid)
    session_ids: list[str] = Field(default_factory=list)
    coordinated: bool = False
    roles: dict[str, str] = Field(default_factory=dict)   # session_id -> rol
    c2_indicator: str | None = None
    confidence: float = 0.0
    rationale: str = ""
    engine: str = "rules"            # "rules" | "sonnet"


class KillChainAssessment(BaseModel):
    """Salida de TRACKER++: ¿una sola sesión escala por fases (una campaña)?"""

    session_id: str
    phases: list[str] = Field(default_factory=list)     # fases distintas observadas, en orden
    techniques: list[str] = Field(default_factory=list)  # técnicas vistas en la sesión
    escalating: bool = False
    adaptive_evasion: bool = False                        # cambió de TTP tras ser detectado
    confidence: float = 0.0
    rationale: str = ""


class AttackPathAssessment(BaseModel):
    """Salida de TRACKER++: grafo de rutas de ataque (estilo BloodHound).

    Nodos = identidades/sesiones/objetivos; aristas = relaciones observadas por fase.
    `shortest_path` es la ruta más corta hacia un objetivo de "compromiso total".
    """

    nodes: list[dict[str, Any]] = Field(default_factory=list)   # {id, kind, label}
    edges: list[dict[str, Any]] = Field(default_factory=list)   # {src, dst, phase, technique}
    lateral_movement: bool = False
    shortest_path: list[str] = Field(default_factory=list)      # ids de nodos
    compromise_reached: bool = False
    rationale: str = ""


class Incident(BaseModel):
    """Incidente agregado que ve el operador en el dashboard."""

    id: str = Field(default_factory=_uuid)
    ts: float = Field(default_factory=_now)
    session_id: str
    kind: str
    path: str = "/"
    ua: str = ""
    score: float = 0.0
    matched_rules: list[str] = Field(default_factory=list)
    owasp: str = "N/A"
    owasp_name: str = ""
    attacker_profile: AttackerProfile = AttackerProfile.UNKNOWN
    urgency: Urgency = Urgency.INFO
    confidence: float = 0.0
    rationale: str = ""
    trust: str = "server"            # "server" (autoritativo) | "client_hint" (solo el cliente lo dijo)
    frameworks: dict[str, list[str]] = Field(default_factory=dict)  # {attack:[...], atlas:[...]}
    evidence: dict[str, Any] = Field(default_factory=dict)  # extra+features del evento (para enrichers)
    swarm: SwarmAssessment | None = None
    killchain: KillChainAssessment | None = None
    attack_path: AttackPathAssessment | None = None
    integrity_verdict: dict[str, Any] | None = None   # WARDEN (tool/memory/scope)
    identity_verdict: dict[str, Any] | None = None     # SPECTER (cross-tenant / a2a)
    status: str = "open"             # open | contained | dismissed
    actions: list[dict[str, Any]] = Field(default_factory=list)


class AuditRecord(BaseModel):
    """Registro inmutable (hash-chained) escrito por SCRIBE."""

    seq: int
    ts: float
    agent: str
    action: str
    subject_id: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str
