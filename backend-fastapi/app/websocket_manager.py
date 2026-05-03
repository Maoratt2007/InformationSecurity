from fastapi import WebSocket


class ConnectionManager:
    """Tracks WebSockets per authenticated user. Multiple browser tabs share one client_id."""

    def __init__(self) -> None:
        self.active_connections: dict[str, list[WebSocket]] = {}

    async def connect(self, client_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        bucket = self.active_connections.setdefault(client_id, [])
        bucket.append(websocket)

    def disconnect(self, client_id: str, websocket: WebSocket) -> None:
        bucket = self.active_connections.get(client_id)
        if not bucket:
            return
        try:
            bucket.remove(websocket)
        except ValueError:
            return
        if not bucket:
            self.active_connections.pop(client_id, None)

    async def send_to_client(self, client_id: str, message: dict) -> bool:
        connections = self.active_connections.get(client_id)
        if not connections:
            return False
        any_ok = False
        # Copy so disconnect mutations during iteration are safe
        for connection in list(connections):
            try:
                await connection.send_json(message)
                any_ok = True
            except Exception:
                self.disconnect(client_id, connection)
        return any_ok

    async def broadcast_presence(self) -> None:
        online_users = sorted(cid for cid, sockets in self.active_connections.items() if sockets)
        payload = {"type": "presence", "online_clients": online_users}
        targets: list[tuple[str, WebSocket]] = []
        for cid, sockets in self.active_connections.items():
            for ws in sockets:
                targets.append((cid, ws))
        for cid, websocket in targets:
            try:
                await websocket.send_json(payload)
            except Exception:
                self.disconnect(cid, websocket)
