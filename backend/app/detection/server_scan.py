"""Escaneo de contenido SERVER-SIDE (independiente del SDK).

Gemelo Python de `sdk/src/rules.js`: mismas familias de patrones y el MISMO vocabulario de
labels. La diferencia clave: esto corre en el servidor sobre el payload REAL, así que detecta
aunque el atacante evite el SDK (pega directo a la API) y NO mande `client_matches`.

Se usa en el sensor `/tap` (WAF-tap / reverse-proxy simulado). Determinista, sin LLM.
"""
from __future__ import annotations

import re

# label -> lista de regex (mismo vocabulario que rules.js / rules.py)
_PATTERNS: list[tuple[str, list[re.Pattern]]] = [
    ("prompt_injection.instruction_override", [
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above)", re.I),
        re.compile(r"disregard\s+(the\s+)?(above|previous|prior)", re.I),
        re.compile(r"forget\s+(everything|all\s+previous)", re.I),
        re.compile(r"new\s+instructions?\s*[:\-]", re.I),
    ]),
    ("prompt_injection.role_hijack", [
        re.compile(r"you\s+are\s+now", re.I),
        re.compile(r"system\s+prompt", re.I),
        re.compile(r"\bact\s+as\s+(an?|the)\b", re.I),
        re.compile(r"pretend\s+to\s+be", re.I),
    ]),
    ("prompt_injection.exfil", [
        re.compile(r"(reveal|print|show|repeat|dump)[^.]{0,25}"
                   r"(system|prompt|instructions?|api[_\s-]?key|password|secret|token|env)", re.I),
        re.compile(r"environment\s+variables?", re.I),
    ]),
    ("xss.script", [
        re.compile(r"<script\b", re.I),
        re.compile(r"on(error|load|click)\s*=", re.I),
        re.compile(r"javascript:", re.I),
    ]),
    ("sqli", [
        re.compile(r"'\s*or\s*'?1'?\s*=\s*'?1", re.I),
        re.compile(r"union\s+select", re.I),
        re.compile(r";\s*drop\s+table", re.I),
        re.compile(r"--\s"),
    ]),
    ("ssrf", [
        re.compile(r"169\.254\.169\.254"),
        re.compile(r"file://", re.I),
        re.compile(r"https?://(localhost|127\.0\.0\.1)", re.I),
        re.compile(r"metadata\.(google|internal)", re.I),
    ]),
    ("swarm.deaddrop", [
        re.compile(r"remote\s+confirmed", re.I),
        re.compile(r"exposing?\s+creds?", re.I),
        re.compile(r"join\s+the\s+swarm", re.I),
        re.compile(r"\brecruit(ing)?\b", re.I),
        re.compile(r"^[A-Za-z0-9+/=]{48,}$"),   # blob base64 largo
    ]),
]


def scan_text(text: str) -> list[str]:
    """Labels que dispara el contenido crudo (que aquí SÍ vemos, en el borde server-side)."""
    if not text:
        return []
    hits: list[str] = []
    for label, regexes in _PATTERNS:
        if any(rx.search(text) for rx in regexes):
            hits.append(label)
    return sorted(set(hits))
