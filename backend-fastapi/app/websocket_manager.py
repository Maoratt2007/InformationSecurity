from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, client_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections[client_id] = websocket

    def disconnect(self, client_id: str) -> None:
        self.active_connections.pop(client_id, None)

    async def send_to_client(self, client_id: str, message: dict) -> bool:
        connection = self.active_connections.get(client_id)
        if connection is None:
            return False
        await connection.send_json(message)
        return True

    async def broadcast_presence(self) -> None:
        online_users = sorted(self.active_connections.keys())
        for websocket in self.active_connections.values():
            await websocket.send_json({"type": "presence", "online_clients": online_users})
