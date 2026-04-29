import os

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .database import Base, engine
from .routes.key_bundles import router as users_router
from .websocket_manager import ConnectionManager

FRONTEND_ORIGINS = [
    origin.strip()
    for origin in os.getenv("FRONTEND_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]

app = FastAPI(title="Secure Messenger API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

app.include_router(users_router)

manager = ConnectionManager()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.websocket("/ws/chat/{client_id}")
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
            }
            delivered = False
            if recipient_id:
                delivered = await manager.send_to_client(recipient_id, message)
            await manager.send_to_client(client_id, {**message, "echo": True, "delivered": delivered})
    except WebSocketDisconnect:
        manager.disconnect(client_id=client_id)
        await manager.broadcast_presence()
