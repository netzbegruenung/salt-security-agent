from __future__ import annotations

import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

SERVER_ERROR_BACKOFF_SECONDS = 300
SERVER_ERROR_MAX_RETRIES = 5


def wrap_untrusted(content: str, nonce: str) -> str:
    return (
        f"⟦UNTRUSTED-DATA:{nonce}⟧\n"
        f"{content}\n"
        f"⟦END-UNTRUSTED-DATA:{nonce}⟧"
    )


def post_with_retry(
    client: httpx.Client,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    label: str,
) -> httpx.Response:
    """POST to the LLM API, retrying transport errors and 5xx responses with backoff.

    `label` identifies the caller (minion, or minion plus sub-agent) in log messages.
    """
    for attempt in range(SERVER_ERROR_MAX_RETRIES + 1):
        try:
            response = client.post(url, headers=headers, json=payload)
        except (httpx.TimeoutException, httpx.RemoteProtocolError, httpx.NetworkError) as exc:
            if attempt >= SERVER_ERROR_MAX_RETRIES:
                raise
            logger.warning(
                "LLM request for %s raised %s: %s; backing off %d seconds before retry %d/%d.",
                label,
                type(exc).__name__,
                exc,
                SERVER_ERROR_BACKOFF_SECONDS,
                attempt + 1,
                SERVER_ERROR_MAX_RETRIES,
            )
            time.sleep(SERVER_ERROR_BACKOFF_SECONDS)
            continue
        if response.status_code < 500:
            response.raise_for_status()
            return response
        if attempt >= SERVER_ERROR_MAX_RETRIES:
            response.raise_for_status()
        logger.warning(
            "LLM request for %s returned %d; backing off %d seconds before retry %d/%d.",
            label,
            response.status_code,
            SERVER_ERROR_BACKOFF_SECONDS,
            attempt + 1,
            SERVER_ERROR_MAX_RETRIES,
        )
        time.sleep(SERVER_ERROR_BACKOFF_SECONDS)
    response.raise_for_status()
    return response
