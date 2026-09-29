"""Настройка HTTP-транспорта и доступа к MCP-серверу."""

import hmac
import os
from dataclasses import dataclass, field
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


class BearerAuthMiddleware:
    """Общий секрет для личного MCP-клиента с поддержкой HTTP headers."""

    def __init__(self, app: ASGIApp, token: str):
        self.app = app
        self.expected = f"Bearer {token}".encode("utf-8")

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] == "http":
            authorization = Headers(scope=scope).get("authorization", "")
            if not hmac.compare_digest(authorization.encode("utf-8"), self.expected):
                response = JSONResponse(
                    {"error": "Требуется корректный MCP_ACCESS_TOKEN."},
                    status_code=401, headers={"WWW-Authenticate": "Bearer"},
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


@dataclass
class Settings:
    host: str = "127.0.0.1"
    port: int = 8001
    access_token: str = field(default="", repr=False)
    allowed_hosts: list[str] = field(default_factory=lambda: [
        "localhost", "localhost:*", "127.0.0.1", "127.0.0.1:*", "[::1]", "[::1]:*",
    ])
    allowed_origins: list[str] = field(default_factory=list)

    @classmethod
    def from_env(cls):
        load_dotenv(Path(__file__).with_name(".env"))
        settings = cls(
            host=os.getenv("MCP_HOST", "127.0.0.1").strip(),
            port=int(os.getenv("MCP_PORT", str(cls.port))),
            access_token=os.getenv("MCP_ACCESS_TOKEN", "").strip(),
        )
        for attribute in ("allowed_hosts", "allowed_origins"):
            value = os.getenv(f"MCP_{attribute.upper()}")
            if value is not None:
                setattr(settings, attribute, [item.strip() for item in value.split(",") if item.strip()])
        settings.validate()
        return settings

    def validate(self):
        if not self.host or not 1 <= self.port <= 65535:
            raise ValueError("Задайте MCP_HOST и MCP_PORT в диапазоне 1–65535.")
        if not self.allowed_hosts:
            raise ValueError("MCP_ALLOWED_HOSTS не должен быть пустым.")
        if self.host not in {"127.0.0.1", "localhost", "::1"} and not self.access_token:
            raise ValueError("Для сетевого доступа задайте отдельный MCP_ACCESS_TOKEN.")


def create_app(mcp: MCPServer, settings: Settings):
    settings.validate()
    app = mcp.streamable_http_app(
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            allowed_hosts=settings.allowed_hosts,
            allowed_origins=settings.allowed_origins,
        ),
    )
    if settings.access_token:
        app.add_middleware(BearerAuthMiddleware, token=settings.access_token)
    return app


def run(mcp: MCPServer):
    settings = Settings.from_env()
    uvicorn.run(create_app(mcp, settings), host=settings.host, port=settings.port)
