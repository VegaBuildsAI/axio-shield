"""Configuración del Shield Backend (env + defaults).

Todo es configurable por variable de entorno para que el mismo build corra local
(Docker) y desplegado en una URL pública sin cambiar código.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SHIELD_", env_file=".env", extra="ignore"
    )

    # --- Servidor ---
    host: str = "0.0.0.0"
    port: int = 8000
    # Orígenes permitidos para CORS (portal + dashboard). "*" en dev.
    cors_origins: str = "*"

    # --- Claude API ---
    # Si no hay API key -> el claude_client corre en MODO STUB (determinista, sin red).
    anthropic_api_key: str = ""
    model_haiku: str = "claude-haiku-4-5-20251001"
    model_sonnet: str = "claude-sonnet-5"
    # Fuerza modo stub aunque haya key (útil para demos offline reproducibles).
    force_stub: bool = False

    # --- Almacenamiento ---
    db_path: str = "shield.db"

    # --- Umbrales de detección ---
    # score >= sentinel_llm_threshold pero < sentinel_certain -> caso ambiguo -> LLM
    sentinel_certain: float = 0.85
    sentinel_llm_threshold: float = 0.35
    # Ventana (segundos) para correlación de swarm en TRACKER.
    swarm_window_seconds: int = 120
    # Mínimo de sesiones coordinadas para levantar alerta de swarm.
    swarm_min_sessions: int = 2

    # --- Alertas ---
    webhook_url: str = ""  # stub: si se define, HERALD hace POST del incidente

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def use_stub(self) -> bool:
        return self.force_stub or not self.anthropic_api_key


@lru_cache
def get_settings() -> Settings:
    return Settings()
