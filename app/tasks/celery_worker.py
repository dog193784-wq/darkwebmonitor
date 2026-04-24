"""Celery worker and asynchronous notification tasks.

Background processing is used to decouple user-facing scan latency from
non-critical operations like email alert delivery.
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage

from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "darkwebmonitor",
    broker=settings.redis_url,
    backend=settings.redis_url,
)


@celery_app.task(name="send_breach_alert_task")
def send_breach_alert_task(user_email: str, occurrence_count: int) -> None:
    """Send a plain-text breach warning email.

    Privacy note:
    This task accepts only the recipient identity and breach count. It never
    accepts or transmits plaintext password material.
    """

    subject = "Security Alert: Exposed Credential Detected"
    body = (
        "Dear user,\n\n"
        "Our privacy-aware credential exposure monitoring service detected that "
        "your scanned password appears in known breach corpora.\n"
        f"Observed breach occurrence count: {occurrence_count}\n\n"
        "Recommended actions:\n"
        "1) Change this password immediately.\n"
        "2) Avoid reusing passwords across services.\n"
        "3) Enable multi-factor authentication (MFA).\n\n"
        "Regards,\n"
        "Credential Exposure Monitoring System"
    )

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from_email
    message["To"] = user_email
    message.set_content(body)

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        if settings.smtp_use_tls:
            smtp.starttls()
        smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)
