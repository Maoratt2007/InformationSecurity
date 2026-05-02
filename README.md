# InformationSecurity

Secure instant messaging scaffold for an Information Security course project. The architecture is split between a FastAPI transport and key-bundle API, and a Next.js academic dashboard prepared for client-side Signal protocol work.

## Folder Structure

```text
backend-fastapi/
  app/
    database.py
    main.py
    models.py
    schemas.py
    websocket_manager.py
    routes/
      key_bundles.py
  requirements.txt

frontend-next/
  app/
    layout.tsx
    page.tsx
    chat/page.tsx
  components/
    auth/
    chat/
  hooks/
  lib/supabase/
  types/
```

## Backend

```bash
cd backend-fastapi
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

The backend exposes `/health`, `/api/users`, `/api/users/{user_id}/key-bundle`, and `/ws/chat/{client_id}`.

## Frontend

```bash
cd frontend-next
npm install
npm run dev
```

Copy `frontend-next/.env.local.example` to `frontend-next/.env.local` and set your Supabase project values before using authentication.

## X3DH verification (dev)

After opening the chat page, compare shared secrets across two browsers:

1. Clear `sessionStorage` on both, refresh, and **log in again** (restores the local private key bundle).
2. Sender sends the first message (lazy `initiateX3DH`); receiver derives via message header only.
3. In each browser DevTools console: `window.__signalSession("<the other user UUID>")` — the returned **masterSecret** strings must be identical on both sides.

If you only cleared `sessionStorage` without logging in again, X3DH cannot run (no private bundle).
