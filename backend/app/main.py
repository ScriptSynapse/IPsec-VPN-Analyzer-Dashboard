from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api import routes_agents, routes_analysis, routes_capture, routes_observer, routes_reports, routes_scoring
from app.core.config import settings
from app.core.db import get_db, init_db
from app.core.schemas import HealthResponse


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)

# Permissive CORS for local dev -- this API has no auth model yet and is
# meant to be hit from a locally-run dashboard (frontend/) on a different
# port. Tighten this before ever exposing the API beyond localhost.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes_capture.router)
app.include_router(routes_analysis.router)
app.include_router(routes_scoring.router)
app.include_router(routes_reports.router)
app.include_router(routes_observer.router)
app.include_router(routes_agents.router)


@app.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    try:
        db.execute(text("SELECT 1"))
        database_connected = True
    except Exception:
        database_connected = False

    return HealthResponse(
        status="ok" if database_connected else "degraded",
        app_name=settings.app_name,
        database_connected=database_connected,
    )
