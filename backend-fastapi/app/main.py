import logging
import time

import httpx
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .logging_utils import log_event
from .routes.key_bundles import router as users_router
from .websocket_manager import ConnectionManager

logging.basicConfig(level=logging.INFO, format="%(levelname)s:     %(message)s")

ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

fastapi_app = FastAPI(title="Secure Messenger API", version="0.1.0")
app = fastapi_app


async def _upstream_unavailable_handler(request: Request, exc: Exception) -> JSONResponse:
    log_event(f"Upstream HTTPS error: {type(exc).__name__}: {exc}")
    return JSONResponse(
        status_code=503,
        content={
            "detail": (
                "Backend could not reach Supabase over HTTPS (timeout or connection error). "
                "For auth, set SUPABASE_JWT_SECRET in backend-fastapi/.env. "
                "If database calls also fail, fix firewall/VPN/antivirus or outbound TLS to *.supabase.co."
            ),
            "type": type(exc).__name__,
        },
    )


for _exc_type in (
    httpx.ConnectTimeout,
    httpx.ConnectError,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
):
    fastapi_app.add_exception_handler(_exc_type, _upstream_unavailable_handler)

fastapi_app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,
)


@fastapi_app.middleware("http")
async def log_http_requests(request: Request, call_next):
    started_at = time.perf_counter()
    log_event(f"HTTP {request.method} {request.url.path}")
    try:
        response = await call_next(request)
    except Exception as exc:
        duration_ms = (time.perf_counter() - started_at) * 1000
        log_event(f"HTTP {request.method} {request.url.path} -> ERROR {type(exc).__name__} {duration_ms:.1f}ms")
        raise

    duration_ms = (time.perf_counter() - started_at) * 1000
    log_event(f"HTTP {request.method} {request.url.path} -> {response.status_code} {duration_ms:.1f}ms")
    return response


fastapi_app.include_router(users_router)

manager = ConnectionManager()


@fastapi_app.on_event("startup")
async def log_startup() -> None:
    log_event("FastAPI server started. Request logging is active.")


@fastapi_app.get("/health")
def health() -> dict[str, str]:
    log_event("Health check received")
    return {"status": "ok"}


@fastapi_app.websocket("/ws/chat/{client_id}")
async def websocket_chat(websocket: WebSocket, client_id: str) -> None:
    await manager.connect(client_id=client_id, websocket=websocket)
    await manager.broadcast_presence()

    try:
        while True:
            payload = await websocket.receive_json()
            recipient_id = payload.get("recipient_id")
            message = {
                "type": "chat",
                "sender_id": client_id,
                "recipient_id": recipient_id,
                "content": payload.get("content", ""),
                "client_message_id": payload.get("client_message_id"),
                "encryption_header": payload.get("encryption_header"),
            }
            delivered = False
            if recipient_id:
                delivered = await manager.send_to_client(recipient_id, message)
            await manager.send_to_client(client_id, {**message, "echo": True, "delivered": delivered})
    except WebSocketDisconnect:
        manager.disconnect(client_id=client_id)
        await manager.broadcast_presence()


class RequestLoggingASGIWrapper:
    def __init__(self, wrapped_app):
        self.wrapped_app = wrapped_app

    def __getattr__(self, name):
        return getattr(self.wrapped_app, name)

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            log_event(f"ASGI HTTP {scope.get('method')} {scope.get('path')}")
        await self.wrapped_app(scope, receive, send)


app = RequestLoggingASGIWrapper(fastapi_app)
