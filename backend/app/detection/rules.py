"""Reglas deterministas server-side + mapeo a OWASP Agentic Top 10.

Determinista antes que LLM: esto resuelve la mayoría de los casos en microsegundos.
El vocabulario de labels es COMPARTIDO con el SDK (sdk/src/rules.js) para que cliente
y servidor hablen el mismo idioma. El servidor NO ve el texto crudo del usuario: puntúa
a partir de los labels que el cliente ya detectó + el user-agent + features estadísticas.
"""
from __future__ import annotations

from app.models.events import IngestEvent

# --- Firmas de AI browsers y bots (se evalúan sobre el user-agent, visible server-side) ---
UA_SIGNATURES: dict[str, list[str]] = {
    "ai_browser.ua": [
        "gptbot", "chatgpt-user", "oai-searchbot", "operator",
        "perplexitybot", "perplexity-user", "claudebot", "claude-user",
        "anthropic", "google-extended", "ccbot", "bytespider",
    ],
    "automation.headless": [
        "headlesschrome", "phantomjs", "puppeteer", "playwright", "selenium",
    ],
    "automation.client": [
        "python-requests", "python-httpx", "curl/", "wget/", "go-http-client",
        "node-fetch", "axios/", "aiohttp",
    ],
    "agent_framework": [
        "langchain", "crewai", "browser-use", "autogpt", "llamaindex", "openai-agents",
    ],
}

# --- Peso de cada label al score [0..1] ---
RULE_WEIGHTS: dict[str, float] = {
    "prompt_injection.instruction_override": 0.85,
    "prompt_injection.role_hijack": 0.80,
    "prompt_injection.exfil": 0.80,
    "xss.script": 0.80,
    "sqli": 0.80,
    "ssrf": 0.75,
    "swarm.deaddrop": 0.55,
    "ai_browser.ua": 0.50,
    "automation.headless": 0.55,
    "automation.client": 0.45,
    "agent_framework": 0.65,
    "automation.timing": 0.40,
    "agent.tool_poisoning": 0.80,
    "agent.memory_poisoning": 0.75,
    "identity.cross_tenant": 0.90,
    "agent.scope_escape_attempt": 0.90,
    "agent.c2_migration": 0.65,
    "agent.a2a_spoof": 0.80,
    "identity.credential_access": 0.85,
    "identity.session_token_access": 0.90,
    "identity.api_key_access": 0.90,
    "data.database_query_abuse": 0.85,
    "identity.privilege_escalation": 0.90,
    "tool.high_impact_call": 0.80,
    "data.exfiltration_canary": 0.90,
    # Fase 6 — familias AD-inspiradas
    "recon.enumeration": 0.50,
    "identity.lateral_movement": 0.85,
    "persistence.rogue_rule": 0.80,
}

# --- label (o prefijo) -> (código OWASP ASI, nombre) ---
OWASP_MAP: list[tuple[str, str, str]] = [
    ("prompt_injection.instruction_override", "ASI02", "Prompt Injection directa"),
    ("prompt_injection.role_hijack", "ASI01", "Goal Hijacking"),
    ("prompt_injection.exfil", "ASI07", "Data Exfiltration"),
    ("swarm.deaddrop", "ASI08", "Agent Spoofing / Coordinación covert"),
    ("agent_framework", "ASI10", "Rogue Agent Autonomy"),
    ("ssrf", "ASI04", "Tool Hijacking"),
    ("sqli", "ASI06", "Privilege Escalation"),
    ("xss.script", "ASI03", "Indirect Prompt Injection"),
    ("ai_browser.ua", "ASI02", "Prompt Injection directa"),
    ("automation.headless", "ASI02", "Prompt Injection directa"),
    ("automation.client", "ASI02", "Prompt Injection directa"),
    ("automation.timing", "ASI02", "Prompt Injection directa"),
    ("agent.scope_escape_attempt", "ASI05", "Ejecución inesperada de código"),
    ("identity.cross_tenant", "ASI03", "Abuso de identidad y privilegios"),
    ("agent.tool_poisoning", "ASI04", "Tool Hijacking"),
    ("agent.memory_poisoning", "ASI06", "Memory & Context Poisoning"),
    ("agent.a2a_spoof", "ASI07", "Comunicación inter-agente insegura"),
    ("agent.c2_migration", "ASI07", "Comunicación inter-agente insegura"),
    ("identity.session_token_access", "ASI03", "Abuso de identidad y privilegios"),
    ("identity.api_key_access", "ASI03", "Abuso de identidad y privilegios"),
    ("identity.credential_access", "ASI03", "Abuso de identidad y privilegios"),
    ("identity.privilege_escalation", "ASI03", "Abuso de identidad y privilegios"),
    ("data.database_query_abuse", "ASI06", "Acceso indebido a datos"),
    ("data.exfiltration_canary", "ASI07", "Data Exfiltration"),
    ("tool.high_impact_call", "ASI04", "Tool Hijacking"),
    ("identity.lateral_movement", "ASI03", "Abuso de identidad y privilegios"),
    ("persistence.rogue_rule", "ASI03", "Abuso de identidad y privilegios"),
    ("recon.enumeration", "ASI10", "Reconocimiento / mapeo de superficie"),
]


def ua_matches(user_agent: str) -> list[str]:
    """Labels que dispara el user-agent."""
    ua = (user_agent or "").lower()
    hits: list[str] = []
    for label, needles in UA_SIGNATURES.items():
        if any(n in ua for n in needles):
            hits.append(label)
    return hits


def feature_matches(features: dict) -> list[str]:
    """Labels que disparan las señales estadísticas (sin ver contenido)."""
    hits: list[str] = []
    # Relleno de formulario demasiado rápido para un humano.
    fill_ms = features.get("form_fill_ms")
    if isinstance(fill_ms, (int, float)) and 0 < fill_ms < 350:
        hits.append("automation.timing")
    # Campo libre con entropía/estructura anómala -> posible dead-drop.
    if features.get("deaddrop_suspect") is True:
        hits.append("swarm.deaddrop")
    if features.get("tool_poisoning_suspect") is True:
        hits.append("agent.tool_poisoning")
    if features.get("memory_poisoning_suspect") is True:
        hits.append("agent.memory_poisoning")
    if features.get("cross_tenant_suspect") is True:
        hits.append("identity.cross_tenant")
    if features.get("scope_escape_attempt") is True:
        hits.append("agent.scope_escape_attempt")
    if features.get("c2_migration") is True:
        hits.append("agent.c2_migration")
    if features.get("a2a_spoof_suspect") is True:
        hits.append("agent.a2a_spoof")
    for feature, label in (
        ("credential_access_attempt", "identity.credential_access"),
        ("session_token_access_attempt", "identity.session_token_access"),
        ("api_key_access_attempt", "identity.api_key_access"),
        ("database_query_abuse", "data.database_query_abuse"),
        ("privilege_escalation_attempt", "identity.privilege_escalation"),
        ("high_impact_tool_call", "tool.high_impact_call"),
        ("exfiltration_attempt", "data.exfiltration_canary"),
        # Fase 6 — familias AD-inspiradas
        ("enumeration_suspect", "recon.enumeration"),
        ("lateral_movement_suspect", "identity.lateral_movement"),
        ("rogue_rule_suspect", "persistence.rogue_rule"),
    ):
        if features.get(feature) is True:
            hits.append(label)
    return hits


def score_event(event: IngestEvent) -> tuple[float, list[str]]:
    """Combina labels autoritativos + UA + features en un score [0..1] y la lista de reglas.

    server_matches (derivados server-side por el sensor /tap) y UA/features son autoritativos.
    client_matches son solo HINTS del cliente: cuentan para el score pero el `trust` del
    incidente los marca como no confiables si fueron la única fuente.
    """
    matched: list[str] = []
    matched.extend(m for m in getattr(event, "server_matches", []) if m in RULE_WEIGHTS)
    matched.extend(m for m in event.client_matches if m in RULE_WEIGHTS)
    matched.extend(ua_matches(event.ua))
    matched.extend(feature_matches(event.features))
    matched = sorted(set(matched))

    if not matched:
        return 0.0, []

    # Score: combinación probabilística (1 - producto de complementos) — satura hacia 1.
    complement = 1.0
    for label in matched:
        complement *= 1.0 - RULE_WEIGHTS.get(label, 0.3)
    score = round(1.0 - complement, 3)
    return score, matched


def detection_trust(event: IngestEvent, matched: list[str]) -> str:
    """'server' si algo autoritativo lo confirma; 'client_hint' si solo lo dijo el cliente."""
    authoritative = set(getattr(event, "server_matches", []))
    authoritative |= set(ua_matches(event.ua))
    authoritative |= set(feature_matches(event.features))
    return "server" if authoritative else "client_hint"


def map_owasp(matched_rules: list[str]) -> tuple[str, str]:
    """Devuelve (código ASI, nombre) del label de mayor severidad presente."""
    for label, code, name in OWASP_MAP:  # OWASP_MAP está en orden de prioridad
        if label in matched_rules:
            return code, name
    return "N/A", "Sin clasificación"
