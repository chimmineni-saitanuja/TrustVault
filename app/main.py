"""TrustVault FastAPI application entry point.

Provides root metadata and database health-check endpoints.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
import os
import time
from typing import Any, Dict

from fastapi import Depends, FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import __version__
from app.config import settings
from app.database import get_db
from app.routers import activity as activity_router
from app.routers import auth as auth_router
from app.routers import documents as documents_router
from app.routers import users as users_router

logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("trustvault")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown hooks."""
    logger.info("Initializing TrustVault v%s (Environment: %s)", __version__, settings.APP_ENV)
    # Ensure private storage directory exists
    os.makedirs(settings.STORAGE_DIR, exist_ok=True)
    yield
    logger.info("Shutting down TrustVault service.")


app = FastAPI(
    title=settings.APP_NAME,
    version=__version__,
    description="Secure document sharing platform with document-level permissions and audit trail.",
    lifespan=lifespan,
)

app.include_router(auth_router.router, prefix="/auth", tags=["Authentication"])
app.include_router(activity_router.router, prefix="/activity", tags=["Activity"])
app.include_router(documents_router.router, prefix="/documents", tags=["Documents"])
app.include_router(users_router.router, prefix="/users", tags=["Users"])

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["System"])
def root_info() -> Dict[str, Any]:
    """Root metadata endpoint providing service status and version information."""
    return {
        "service": settings.APP_NAME,
        "version": __version__,
        "status": "operational",
        "environment": settings.APP_ENV,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "docs_url": "/docs",
    }


@app.get("/health", tags=["System"])
def health_check(db: Session = Depends(get_db)) -> JSONResponse:
    """System health check endpoint.
    
    Verifies application liveness and executes a live query against the database.
    Accurately returns HTTP 200 if connected, or HTTP 503 if the database is unreachable,
    without leaking database credentials.
    """
    start_time = time.perf_counter()
    db_connected = False
    db_error = None

    try:
        # Live ping to test database connectivity
        db.execute(text("SELECT 1"))
        db_connected = True
    except Exception as exc:
        logger.error("Health check database probe failed: %s", exc)
        db_error = "Database connectivity check failed"

    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    payload = {
        "status": "healthy" if db_connected else "unhealthy",
        "service": settings.APP_NAME,
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": "connected" if db_connected else "disconnected",
        "db_latency_ms": latency_ms if db_connected else None,
    }

    if not db_connected:
        payload["error"] = db_error
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=payload)

    return JSONResponse(status_code=status.HTTP_200_OK, content=payload)
