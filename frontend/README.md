# IPsec VPN Analyzer — Dashboard

Vite + React + Tailwind v4 dashboard, a thin client over the FastAPI backend
in `../backend` (see `../API-SPEC.md` for the full contract this app reads
from). No analysis logic lives here — every number and finding on screen
came from the backend.

## Run

```bash
# backend, in another terminal (see ../backend/README or the repo root docs)
cd ../backend && source .venv/bin/activate && uvicorn app.main:app --reload

# this app
npm install
npm run dev
```

Opens at `http://localhost:5173`. The API base URL is configurable from the
sidebar (bottom-left field, defaults to `http://localhost:8000`) and
persisted in `localStorage`.

## Pages

- `/sessions` — list + `/sessions/upload` to add a capture
- `/sessions/:id` — the main view: IKE handshake table, ESP flow
  classification, security score + threat matrix, Observer Profile
  findings, and the technical/executive report viewer
- `/tunnels`, `/tunnels/:tunnelId` — multi-session correlation once 2+
  sessions share a `tunnel_id` (set from a session's detail page)
- `/policies` — upload and inspect custom scoring policies
- `/reports` — quick links into each session's report

## Build

```bash
npm run build   # outputs to dist/
npm run preview # serve the production build locally
```

The backend has permissive CORS enabled for local dev (see
`backend/app/main.py`) so this can run on a different port without a proxy.
