"""SQLAlchemy engine and session factory.

Uses SQLite for the MVP. The connection string is configurable via
DATABASE_URL environment variable, making it trivial to switch to
PostgreSQL later (PRD §10).
"""

from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def _sqlite_pragma_on_connect(dbapi_conn, _connection_record):
    """Enable WAL mode and foreign keys for SQLite connections."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def build_engine(url: str | None = None):
    """Create a SQLAlchemy engine from the configured URL."""
    db_url = url or settings.database_url
    connect_args = {}
    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    engine = create_engine(db_url, connect_args=connect_args, echo=settings.debug)

    if db_url.startswith("sqlite"):
        event.listen(engine, "connect", _sqlite_pragma_on_connect)

    return engine


engine = build_engine()

SessionLocal = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)


def init_db() -> None:
    """Create all tables. Called at app startup."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Dependency that yields a database session and closes it after use."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
