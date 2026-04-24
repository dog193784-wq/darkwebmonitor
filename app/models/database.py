"""SQLModel table definitions.

The data model intentionally excludes plaintext passwords to satisfy the project's
privacy-preserving data-minimization requirements.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlmodel import Field, SQLModel


class ScanLog(SQLModel, table=True):
    """Audit record for password exposure checks.

    Notes:
    - ``user_email`` is a generic string field to match the requested schema.
      To align with privacy constraints, the application layer should persist a
      hashed user identifier value instead of raw email text.
    - No password material is stored.
    """

    __tablename__ = "scan_logs"

    id: UUID = Field(default_factory=uuid4, primary_key=True, index=True)
    user_email: str = Field(index=True, max_length=320)
    scan_type: str = Field(default="password", max_length=50, index=True)
    is_breached: bool = Field(index=True)
    occurrence_count: int = Field(default=0, ge=0)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )
