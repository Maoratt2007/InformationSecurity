"""HTTP API for loading persisted chat messages."""

from fastapi import APIRouter, Header, HTTPException, Query, status

from ..database import SignalProtocolRepository
from ..logging_utils import log_event
from ..repositories.messages import MessageRepository
from .key_bundles import get_authorized_user_id

router = APIRouter(prefix="/api/conversations", tags=["messages"])


@router.get("/{peer_id}/messages")
def list_conversation_messages(
    peer_id: str,
    limit: int = Query(default=50, ge=1, le=100),
    authorization: str | None = Header(default=None),
) -> list[dict]:
    """Return recent messages between the authenticated user and ``peer_id``."""
    auth_repo = SignalProtocolRepository()
    current_user_id = get_authorized_user_id(auth_repo, authorization)
    if peer_id == current_user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot list a conversation with yourself",
        )

    log_event(f"Conversation history fetch user={current_user_id} peer={peer_id} limit={limit}")
    rows = MessageRepository().fetch_conversation(
        user_a=current_user_id,
        user_b=peer_id,
        limit=limit,
    )
    return [
        {
            "message_id": row["id"],
            "sender_id": row["sender_id"],
            "recipient_id": row["recipient_id"],
            "content": row["ciphertext"],
            "encryption_header": row.get("encrypted_header"),
            "created_at": row["created_at"],
        }
        for row in rows
    ]
