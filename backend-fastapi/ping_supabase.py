"""
Quick connectivity check from this machine to Supabase (same env as FastAPI).

Usage (from backend-fastapi directory):
  python ping_supabase.py

Reads SUPABASE_URL from .env next to this file or from the environment.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

# Load backend-fastapi/.env when run from repo root or from backend-fastapi/
_here = Path(__file__).resolve().parent
load_dotenv(_here / ".env")
load_dotenv(Path.cwd() / ".env")

SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").strip().rstrip("/")

TIMEOUT = httpx.Timeout(15.0, connect=10.0)


def main() -> int:
    if not SUPABASE_URL:
        print("SUPABASE_URL is missing or empty. Set it in .env or the environment.", file=sys.stderr)
        return 1

    print(f"SUPABASE_URL (normalized): {SUPABASE_URL}")

    # Minimal GET — proves DNS + TLS + TCP to Supabase edge (no secrets sent).
    health = f"{SUPABASE_URL}/auth/v1/health"

    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
            r = client.get(health)
        print(f"GET {health}")
        print(f"  status: {r.status_code}")
        print(f"  body (first 500 chars): {r.text[:500]!r}")
        print("OK: host is reachable from this environment.")
        return 0
    except httpx.ConnectTimeout as exc:
        print(f"FAIL: ConnectTimeout — cannot establish TCP/TLS within timeout.\n  {exc}", file=sys.stderr)
        print("Likely: firewall/VPN/proxy blocking outbound HTTPS, or wrong host.", file=sys.stderr)
        return 2
    except httpx.ConnectError as exc:
        print(f"FAIL: ConnectError — DNS or network refused.\n  {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
