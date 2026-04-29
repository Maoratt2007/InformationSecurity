from collections.abc import Generator
import os
from typing import Any

from dotenv import load_dotenv
from postgrest.exceptions import APIError
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from supabase import Client, ClientOptions, create_client


load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./messenger.db")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SIGNAL_SCHEMA = "signal_protocol"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_supabase_client() -> Client:
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        raise RuntimeError("SUPABASE_URL and SUPABASE_ANON_KEY must be configured in backend-fastapi/.env")

    return create_client(
        SUPABASE_URL,
        SUPABASE_ANON_KEY,
        options=ClientOptions(schema=SUPABASE_SIGNAL_SCHEMA),
    )


class SignalProtocolRepository:
    def __init__(self, client: Client | None = None) -> None:
        self.client = client or get_supabase_client()

    def test_connection(self, table_name: str = "users") -> dict[str, Any]:
        try:
            response = self.client.table(table_name).select("*").limit(1).execute()
            return {
                "ok": True,
                "schema": SUPABASE_SIGNAL_SCHEMA,
                "table": table_name,
                "row_count": len(response.data or []),
            }
        except APIError as exc:
            message = str(exc)
            if "schema" in message.lower():
                return {
                    "ok": False,
                    "schema": SUPABASE_SIGNAL_SCHEMA,
                    "table": table_name,
                    "error": "Schema not found or not exposed through the Supabase API.",
                    "detail": message,
                }
            return {
                "ok": False,
                "schema": SUPABASE_SIGNAL_SCHEMA,
                "table": table_name,
                "error": "Supabase query failed.",
                "detail": message,
            }

    def register_identity_key(
        self,
        *,
        user_id: str,
        identity_key_public: str,
        device_id: str | None = None,
    ) -> list[dict[str, Any]]:
        # The Identity Key is long-lived public authentication material for X3DH.
        # Private identity keys must remain on the client device.
        payload = {
            "user_id": user_id,
            "identity_key_public": identity_key_public,
        }

        response = (
            self.client.table("identity_keys")
            .upsert(payload, on_conflict="user_id")
            .execute()
        )
        return response.data or []

    def register_pre_keys(
        self,
        *,
        user_id: str,
        identity_key_public: str,
        signed_pre_key_public: str,
        signed_pre_key_signature: str,
        signed_pre_key_id: int = 1,
        one_time_pre_keys: list[dict[str, Any]] | None = None,
        device_id: str | None = None,
    ) -> list[dict[str, Any]]:
        # Signed pre-keys are authenticated by the Identity Key and can be reused for many X3DH starts.
        # One-time pre-keys are stored as separate rows so each can be consumed exactly once.
        self.register_identity_key(
            user_id=user_id,
            identity_key_public=identity_key_public,
            device_id=device_id,
        )

        signed_pre_key_payload = {
            "user_id": user_id,
            "signed_pre_key_id": signed_pre_key_id,
            "signed_pre_key_public": signed_pre_key_public,
            "signed_pre_key_signature": signed_pre_key_signature,
            "signature": signed_pre_key_signature,
        }

        signed_pre_key_response = (
            self.client.table("pre_keys")
            .upsert(signed_pre_key_payload, on_conflict="user_id")
            .execute()
        )

        one_time_pre_key_payloads = [
            {
                "user_id": user_id,
                "key_id": int(pre_key["key_id"]),
                "public_key": pre_key["public_key"],
            }
            for pre_key in one_time_pre_keys or []
        ]

        if one_time_pre_key_payloads:
            self.client.table("one_time_pre_keys").upsert(
                one_time_pre_key_payloads,
                on_conflict="user_id,key_id",
            ).execute()

        return signed_pre_key_response.data or []

    def consume_one_time_pre_key(self, *, user_id: str) -> dict[str, Any] | None:
        # X3DH requires a one-time pre-key to be deleted as soon as it is assigned to an initiator.
        # The database function performs selection and deletion atomically to avoid duplicate use.
        response = self.client.rpc(
            "consume_one_time_pre_key",
            {"target_user_id": user_id},
        ).execute()
        rows = response.data or []
        return rows[0] if rows else None

    def save_session_state(
        self,
        *,
        user_id: str,
        contact_id: str,
        ratchet_key_id: str,
        root_key: str,
        chain_key: str,
        last_received_index: int,
    ) -> list[dict[str, Any]]:
        # Double Ratchet state is scoped to one local user and one contact.
        # The encoded keys represent current client-derived ratchet state, not plaintext messages.
        payload = {
            "user_id": user_id,
            "contact_id": contact_id,
            "ratchet_key_id": ratchet_key_id,
            "root_key": root_key,
            "chain_key": chain_key,
            "last_received_index": last_received_index,
        }

        response = (
            self.client.table("sessions")
            .upsert(payload, on_conflict="user_id,contact_id")
            .execute()
        )
        return response.data or []

    def get_session_state(self, *, user_id: str, contact_id: str) -> dict[str, Any] | None:
        response = (
            self.client.table("sessions")
            .select("*")
            .eq("user_id", user_id)
            .eq("contact_id", contact_id)
            .limit(1)
            .execute()
        )
        rows = response.data or []
        return rows[0] if rows else None
