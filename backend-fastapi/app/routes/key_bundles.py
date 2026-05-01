import httpx
from fastapi import APIRouter, Header, HTTPException, status

from ..database import SignalProtocolRepository
from ..logging_utils import log_event
from ..schemas import KeyBundleCreate, KeyBundleOut, UserCreate, UserOut
from ..supabase_jwt import get_user_id_from_access_token

router = APIRouter(prefix="/api/users", tags=["users", "key-bundles"])


def get_authorized_user_id(repository: SignalProtocolRepository, authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Supabase access token is required")

    token = authorization.split(" ", 1)[1].strip()
    repository.client.postgrest.auth(token)

    user_id_local = get_user_id_from_access_token(token)
    if user_id_local:
        return user_id_local

    try:
        user_response = repository.client.auth.get_user(token)
    except (
        httpx.ConnectTimeout,
        httpx.ConnectError,
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.PoolTimeout,
    ) as exc:
        log_event(
            "Supabase Auth unreachable from backend (JWT local verify failed or JWT secret unset). "
            f"{type(exc).__name__}: {exc}"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Cannot reach Supabase Auth from this server (network/TLS timeout). "
                "Add SUPABASE_JWT_SECRET from Supabase Dashboard (Settings -> API -> JWT Secret) "
                "to backend-fastapi/.env so tokens are verified locally without calling Supabase over HTTPS."
            ),
        ) from exc

    if not user_response.user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Supabase access token")
    return user_response.user.id


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, authorization: str | None = Header(default=None)) -> dict:
    log_event(f"Profile upsert received user_id={payload.id} email={payload.email}")
    repository = SignalProtocolRepository()
    authorized_user_id = get_authorized_user_id(repository, authorization)
    if authorized_user_id != payload.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot create another user's profile")
    response = (
        repository.client.table("users")
        .upsert(
            {
                "id": payload.id,
                "email": payload.email,
                "username": payload.display_name,
            },
            on_conflict="id",
        )
        .select("id, email, username, created_at")
        .execute()
    )
    rows = response.data or []
    if not rows:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User was not saved")

    row = rows[0]
    return {
        "id": row["id"],
        "email": row["email"],
        "display_name": row["username"],
        "created_at": row["created_at"],
    }


@router.post("/{user_id}/key-bundle", response_model=KeyBundleOut, status_code=status.HTTP_201_CREATED)
def upsert_key_bundle(
    user_id: str,
    payload: KeyBundleCreate,
    authorization: str | None = Header(default=None),
) -> dict:
    log_event(
        f"Key-bundle upload received user_id={user_id} "
        f"device_id={payload.device_id} one_time_pre_keys={len(payload.one_time_pre_keys)}"
    )
    repository = SignalProtocolRepository()
    authorized_user_id = get_authorized_user_id(repository, authorization)
    if authorized_user_id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot upload another user's key bundle")
    user_response = repository.client.table("users").select("id").eq("id", user_id).limit(1).execute()
    if not user_response.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    repository.register_pre_keys(
        user_id=user_id,
        device_id=payload.device_id,
        identity_key_public=payload.identity_key_public,
        signed_pre_key_id=payload.signed_pre_key_id,
        signed_pre_key_public=payload.signed_pre_key_public,
        signed_pre_key_signature=payload.signed_pre_key_signature,
        one_time_pre_keys=[key.model_dump() for key in payload.one_time_pre_keys],
    )

    bundle = repository.get_public_key_bundle(user_id=user_id)
    if not bundle:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Key bundle was not saved")
    log_event(f"Key-bundle upload saved user_id={user_id} device_id={payload.device_id}")
    return bundle


@router.get("/{user_id}/key-bundle", response_model=KeyBundleOut)
def get_key_bundle(
    user_id: str,
    device_id: str = "primary",
    authorization: str | None = Header(default=None),
) -> dict:
    log_event(f"Key-bundle fetch received user_id={user_id} device_id={device_id}")
    repository = SignalProtocolRepository()
    get_authorized_user_id(repository, authorization)
    bundle = repository.get_public_key_bundle(user_id=user_id, consume_one_time_pre_key=True)
    if not bundle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key bundle not found")
    log_event(
        f"Key-bundle fetch served user_id={user_id} "
        f"opk_consumed={bool(bundle.get('one_time_pre_key'))}"
    )
    return bundle
