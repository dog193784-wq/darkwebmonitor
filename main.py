"""Application entrypoint for the credential exposure monitoring backend."""

from fastapi import FastAPI

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.db.session import create_db_and_tables

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    debug=settings.debug,
    version="1.0.0",
)


@app.on_event("startup")
def on_startup() -> None:
    """Initialize persistent resources needed for API operation."""

    create_db_and_tables()


app.include_router(api_router)
