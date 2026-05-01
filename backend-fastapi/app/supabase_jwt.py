"""
Verify Supabase HS256 access tokens locally so the backend can authorize requests
without calling `auth/v1/user` (avoids TLS timeouts to Supabase from some Windows/Python setups).

Add to backend-fastapi/.env:
  SUPABASE_JWT_SECRET=<Dashboard -> Project Settings -> API -> JWT Secret>

If your project uses asymmetric signing (ES256 / JWKS only), local verification here
will not apply — fix outbound HTTPS to Supabase or configure a legacy symmetric secret.
"""

from __future__ import annotations

import os

import jwt

_SYMMETRIC_ALGS = frozenset({"HS256", "HS384", "HS512"})


def _jwt_secret() -> str:
    return (
        os.getenv("SUPABASE_JWT_SECRET", "").strip()
        or os.getenv("JWT_SECRET", "").strip()
        or ""
    )


def get_user_id_from_access_token(access_token: str) -> str | None:
    """
    Return the user UUID from claim `sub`, or None if unset / unsupported algorithm / invalid token.
    """
    secret = _jwt_secret()
    if not secret:
        return None

    try:
        alg = jwt.get_unverified_header(access_token).get("alg") or "HS256"
    except (jwt.DecodeError, jwt.InvalidTokenError, ValueError, KeyError):
        return None

    if alg not in _SYMMETRIC_ALGS:
        return None

    try:
        claims = jwt.decode(
            access_token,
            secret,
            algorithms=[alg],
            options={"verify_aud": False, "verify_iss": False},
        )
    except jwt.InvalidTokenError:
        return None

    sub = claims.get("sub")
    role = claims.get("role")

    if role in ("anon", "service_role"):
        return None

    if not isinstance(sub, str) or len(sub) < 10:
        return None

    return sub
