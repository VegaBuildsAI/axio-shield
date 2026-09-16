"""Cliente Claude con routing Haiku/Sonnet y MODO STUB.

- Haiku (volumen): clasificación rápida en ORACLE / desambiguación en SENTINEL.
- Sonnet (razonamiento complejo): correlación de swarms en TRACKER.

MODO STUB: si no hay API key (o SHIELD_FORCE_STUB=1), NO se llama a la red. Cada
agente provee una función `stub` que produce un resultado determinista. Así la demo
corre offline, reproducible y sin gastar tokens — clave para reuniones en vivo.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from app.config import Settings

log = logging.getLogger("shield.claude")

StubFn = Callable[[], dict[str, Any]]


def _extract_json(text: str) -> dict[str, Any]:
    """Extrae el primer objeto JSON de la respuesta del modelo (tolera fences)."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1:
        text = text[start : end + 1]
    return json.loads(text)


class ClaudeClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._client = None
        if not settings.use_stub:
            try:
                from anthropic import AsyncAnthropic

                self._client = AsyncAnthropic(api_key=settings.anthropic_api_key)
            except Exception:  # noqa: BLE001
                log.warning("anthropic SDK no disponible; cayendo a modo stub")
                self._client = None

    @property
    def stub(self) -> bool:
        return self._client is None

    def _model(self, tier: str) -> str:
        return self.settings.model_sonnet if tier == "sonnet" else self.settings.model_haiku

    async def complete_json(
        self,
        *,
        tier: str,
        system: str,
        user: str,
        stub: StubFn,
        max_tokens: int = 512,
    ) -> tuple[dict[str, Any], str]:
        """Devuelve (resultado_dict, engine). engine = 'stub' | 'haiku' | 'sonnet'."""
        if self._client is None:
            return stub(), "stub"
        try:
            resp = await self._client.messages.create(
                model=self._model(tier),
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            text = "".join(
                block.text for block in resp.content if getattr(block, "type", "") == "text"
            )
            return _extract_json(text), tier
        except Exception:  # noqa: BLE001 — fail-safe: si Claude falla, usa el stub
            log.exception("llamada a Claude falló; usando stub")
            return stub(), "stub"
