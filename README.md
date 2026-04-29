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
