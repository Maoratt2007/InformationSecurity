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

    def fetch_conversation(
        self,
        *,
        user_a: str,
        user_b: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return the last ``limit`` messages between two users, oldest first."""
        cap = max(1, min(limit, 100))
        # PostgREST: (A->B) OR (B->A)
        or_filter = (
            f"and(sender_id.eq.{user_a},recipient_id.eq.{user_b}),"
            f"and(sender_id.eq.{user_b},recipient_id.eq.{user_a})"
        )
        response = (
            self.client.schema(SUPABASE_SIGNAL_SCHEMA)
            .table("messages")
            .select("id, sender_id, recipient_id, ciphertext, encrypted_header, created_at")
            .or_(or_filter)
            .order("created_at", desc=True)
            .limit(cap)
            .execute()
        )
        rows = response.data or []
        return list(reversed(rows))
