from pathlib import Path
import os
from uuid import uuid4

from dotenv import load_dotenv

OPK_COUNT = 5

load_dotenv(Path(__file__).resolve().parents[1] / "frontend-next" / ".env", override=False)

from app.database import SignalProtocolRepository


def make_key(label: str) -> str:
    return (label + "_base64url_test_value").ljust(48, "x")


def main() -> None:
    repo = SignalProtocolRepository()
    auth_response = repo.client.auth.sign_in_with_password(
        {
            "email": os.getenv("TEST_SUPABASE_EMAIL", "alice@university.edu"),
            "password": os.getenv("TEST_SUPABASE_PASSWORD", "Alice123456!"),
        }
    )
    if not auth_response.session:
        raise RuntimeError("A confirmed Supabase Auth test user is required for registration verification.")

    repo.client.postgrest.auth(auth_response.session.access_token)
    user_id = str(uuid4())

    repo.client.table("users").insert({
        "id": user_id,
        "username": f"X3DH Test User {user_id[:8]}",
        "email": f"x3dh-{user_id[:8]}@test.local",
    }).execute()

    one_time_pre_keys = [
        {"key_id": str(index), "public_key": make_key(f"opk_{index}")}
        for index in range(1, OPK_COUNT + 1)
    ]

    repo.register_pre_keys(
        user_id=user_id,
        identity_key_public=make_key("identity_public"),
        signed_pre_key_id=1,
        signed_pre_key_public=make_key("signed_pre_key_public"),
        signed_pre_key_signature=make_key("signed_pre_key_signature"),
        one_time_pre_keys=one_time_pre_keys,
    )

    identity = (
        repo.client.table("identity_keys")
        .select("*")
        .eq("user_id", user_id)
        .single()
        .execute()
        .data
    )

    signed_pre_key = (
        repo.client.table("pre_keys")
        .select("*")
        .eq("user_id", user_id)
        .single()
        .execute()
        .data
    )

    opks = (
        repo.client.table("one_time_pre_keys")
        .select("*")
        .eq("user_id", user_id)
        .execute()
        .data
    )

    assert identity["identity_key_public"]
    assert signed_pre_key["signed_pre_key_public"]
    assert signed_pre_key["signed_pre_key_signature"]
    assert len(opks) == OPK_COUNT

    print("Registration flow verified")
    print({"user_id": user_id, "one_time_pre_key_count": len(opks)})


if __name__ == "__main__":
    main()