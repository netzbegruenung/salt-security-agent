from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

VALID_SEVERITIES = {"critical", "high"}


def send_alert(minion: str, severity: str, title: str, details: str) -> str:
    """Emit a security alert. Currently logs only; hook in mail delivery here later."""
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
    return f"Alert dispatched (severity={severity})."
