"""Chat message persistence in Supabase `signal_protocol.messages`."""

from __future__ import annotations

from typing import Any

from supabase import Client

from ..database import SUPABASE_SIGNAL_SCHEMA, get_supabase_client


class MessageRepository:
    def __init__(self, client: Client | None = None) -> None:
        self.client = client or get_supabase_client()

    def persist_chat_message(
        self,
        *,
        sender_id: str,
        recipient_id: str,
        content: str,
        encryption_header: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Insert into signal_protocol.messages.

        DB schema: sender_id / recipient_id uuid FK to signal_protocol.users,
        ciphertext text NOT NULL, encrypted_header jsonb NOT NULL,
        plus DB-generated id / created_at / delivered_at.

        Plaintext passthrough: store message body in ``ciphertext``; use ``{}`` for
        ``encrypted_header`` when no Signal header was supplied.
        """
        payload: dict[str, Any] = {
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "ciphertext": content,
            "encrypted_header": encryption_header or {},
        }
        response = (
            self.client.schema(SUPABASE_SIGNAL_SCHEMA)
            .table("messages")
            .insert(payload)
            .execute()
        )
        rows = response.data or []
        if not rows:
            raise RuntimeError("Insert returned no rows")
        return rows[0]
