"""Database engine and session management for SQLModel.

This module centralizes engine initialization to keep infrastructure concerns out of
routers and services, matching Clean Architecture boundaries.
"""

from collections.abc import Generator

from sqlmodel import Session, SQLModel, create_engine

from app.core.config import get_settings

settings = get_settings()

engine = create_engine(
    settings.database_url,
    echo=settings.debug,
    pool_pre_ping=True,
)


def create_db_and_tables() -> None:
    """Create SQLModel tables.

    In this thesis prototype, automatic table creation simplifies reproducibility.
    Production deployments can replace this with migration tooling.
    """

    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    """Provide a transaction-capable database session per request."""

    with Session(engine) as session:
        yield session
