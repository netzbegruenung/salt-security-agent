from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from agent.config import SmtpConfig

logger = logging.getLogger(__name__)

VALID_SEVERITIES = {"critical", "high"}


def send_alert(
    minion: str,
    severity: str,
    title: str,
    details: str,
    smtp_cfg: SmtpConfig | None = None,
) -> str:
    """Emit a security alert. Logs always; sends e-mail when SMTP is configured."""
    severity = severity.lower().strip()
    if severity not in VALID_SEVERITIES:
        severity = "high"

    logger.critical(
        "ALERT [%s] minion=%s title=%s\n%s",
        severity.upper(),
        minion,
        title,
        details,
    )
    print(
        f"\n!!! ALERT [{severity.upper()}] {minion}: {title}\n{details}\n",
        flush=True,
    )

    mail_status = "no SMTP configured"
    if smtp_cfg is not None:
        try:
            _send_mail(smtp_cfg, minion, severity, title, details)
            mail_status = f"e-mail sent to {smtp_cfg.to_address}"
        except Exception as exc:
            logger.exception("Failed to send alert e-mail for minion %s", minion)
            mail_status = f"e-mail delivery failed: {exc}"

    return f"Alert dispatched (severity={severity}, {mail_status})."


def _send_mail(
    cfg: SmtpConfig,
    minion: str,
    severity: str,
    title: str,
    details: str,
) -> None:
    msg = EmailMessage()
    msg["Subject"] = f"[{severity.upper()}] {minion}: {title}"
    msg["From"] = cfg.from_address
    msg["To"] = cfg.to_address
    msg.set_content(
        f"Severity: {severity.upper()}\n"
        f"Minion:   {minion}\n"
        f"Title:    {title}\n\n"
        f"{details}\n"
    )

    if cfg.use_tls:
        with smtplib.SMTP(cfg.host, cfg.port, timeout=30) as client:
            client.starttls()
            client.login(cfg.username, cfg.password)
            client.send_message(msg)
    else:
        with smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=30) as client:
            client.login(cfg.username, cfg.password)
            client.send_message(msg)
