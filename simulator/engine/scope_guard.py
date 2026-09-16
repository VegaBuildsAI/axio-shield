"""Guardas de alcance: el simulador solo puede hablar con el demo local."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


class ScopeViolation(RuntimeError):
    """La accion intento salir del perfil local autorizado."""


@dataclass(frozen=True)
class ScopePolicy:
    target_profile: str = "local-demo-only"
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost")
    allowed_schemes: tuple[str, ...] = ("http",)


class ScopeGuard:
    def __init__(self, policy: ScopePolicy | None = None) -> None:
        self.policy = policy or ScopePolicy()

    def validate_base_url(self, base_url: str) -> str:
        parsed = urlparse(base_url)
        if self.policy.target_profile != "local-demo-only":
            raise ScopeViolation("el unico perfil permitido es local-demo-only")
        if parsed.scheme not in self.policy.allowed_schemes:
            raise ScopeViolation("solo se permite HTTP local en el laboratorio")
        if parsed.hostname not in self.policy.allowed_hosts:
            raise ScopeViolation("el destino no pertenece al portal local autorizado")
        if parsed.username or parsed.password:
            raise ScopeViolation("no se permiten credenciales embebidas en la URL")
        return base_url.rstrip("/")

    def validate_route(self, base_url: str, route: str) -> str:
        root = self.validate_base_url(base_url)
        if not route.startswith("/") or ".." in route or "\\" in route:
            raise ScopeViolation("ruta fuera del perfil local")
        return root + route

