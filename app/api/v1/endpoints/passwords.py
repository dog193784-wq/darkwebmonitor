"""Password scanning API endpoints.

These endpoints apply privacy-aware orchestration rules:
- plaintext passwords are transient request data only;
- persisted audit data stores hashed user identifiers;
- side effects (email alerts) are delegated to background workers.
"""

from __future__ import annotations

import logging
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session, select

from app.core.security import hash_user_identifier
from app.db.session import get_session
from app.models.database import ScanLog
from app.services.hibp_service import HIBPServiceError, check_password_breach
from app.tasks.celery_worker import send_breach_alert_task

logger = logging.getLogger("app.security.audit")

router = APIRouter(prefix="/scan", tags=["Password Exposure Monitoring"])


class PasswordScanRequest(BaseModel):
    """Inbound payload for password breach scanning."""

    user_email: EmailStr
    password: str = Field(min_length=1, max_length=1024)


class PasswordScanResponse(BaseModel):
    """Response payload for password breach scan operations."""

    breached: bool
    occurrence_count: int
    timestamp: datetime


class ScanHistoryItem(BaseModel):
    """Serialized view of a persisted scan log record."""

    id: UUID
    user_identifier: str
    scan_type: str
    is_breached: bool
    occurrence_count: int
    timestamp: datetime


@router.post("/password", response_model=PasswordScanResponse, status_code=status.HTTP_200_OK)
async def scan_password(
    payload: PasswordScanRequest,
    session: Session = Depends(get_session),
) -> PasswordScanResponse:
    """Scan a password via HIBP k-anonymity and persist a minimal audit record.

    Error handling strategy:
    - HIBP/HTTP failures return HTTP 503 (temporary dependency issue).
    - Database failures return HTTP 500 with rollback to preserve consistency.
    """

    hashed_user = hash_user_identifier(str(payload.user_email))

    try:
        breach_result = await check_password_breach(payload.password)
    except HIBPServiceError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Breach intelligence provider is temporarily unavailable.",
        ) from exc

    occurrence_count = int(breach_result["count"])
    is_breached = bool(breach_result["breached"])

    log_record = ScanLog(
        user_email=hashed_user,
        scan_type="password",
        is_breached=is_breached,
        occurrence_count=occurrence_count,
    )

    try:
        session.add(log_record)
        session.commit()
        session.refresh(log_record)
    except SQLAlchemyError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database operation failed while recording scan result.",
        ) from exc

    logger.info(
        "scan_completed user_id_hash=%s breached=%s",
        hashed_user,
        is_breached,
    )

    if is_breached:
        send_breach_alert_task.delay(str(payload.user_email), occurrence_count)

    return PasswordScanResponse(
        breached=is_breached,
        occurrence_count=occurrence_count,
        timestamp=log_record.timestamp,
    )


@router.get("/history/{user_email}", response_model=list[ScanHistoryItem], status_code=status.HTTP_200_OK)
def get_scan_history(
    user_email: EmailStr,
    session: Session = Depends(get_session),
) -> list[ScanHistoryItem]:
    """Return scan history for a user by hashing query identity locally."""

    hashed_user = hash_user_identifier(str(user_email))
    statement = (
        select(ScanLog)
        .where(ScanLog.user_email == hashed_user)
        .order_by(ScanLog.timestamp.desc())
    )

    try:
        records = session.exec(statement).all()
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database operation failed while reading scan history.",
        ) from exc

    if not records:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No scan history found.")

    return [
        ScanHistoryItem(
            id=row.id,
            user_identifier=row.user_email,
            scan_type=row.scan_type,
            is_breached=row.is_breached,
            occurrence_count=row.occurrence_count,
            timestamp=row.timestamp,
        )
        for row in records
    ]
