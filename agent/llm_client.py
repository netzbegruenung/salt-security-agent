from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING, Any, Callable

import httpx

if TYPE_CHECKING:
    from agent.config import LLMConfig

logger = logging.getLogger(__name__)

SERVER_ERROR_BACKOFF_SECONDS = 300
SERVER_ERROR_MAX_RETRIES = 5

COMPACTION_KEEP_HEAD = 2
COMPACTION_KEEP_TAIL = 6

COMPACTION_REQUEST = (
    "Summarize the security investigation so far in concise prose. Cover: "
    "tools called and what they returned, files/paths inspected, hypotheses "
    "confirmed or ruled out, suspected findings with their evidence, and what "
    "still needs to be checked. Do not call any tools — respond with plain "
    "text only."
)


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


def _merge_tool_call_delta(slots: dict[int, dict[str, Any]], delta: dict[str, Any]) -> None:
    """Fold one streamed tool-call delta into the per-index accumulator."""
    for item in delta.get("tool_calls") or []:
        index = item.get("index", 0)
        slot = slots.setdefault(
            index,
            {"id": "", "type": "function", "function": {"name": "", "arguments": ""}},
        )
        if item.get("id"):
            slot["id"] = item["id"]
        function = item.get("function") or {}
        if function.get("name"):
            slot["function"]["name"] = function["name"]
        if function.get("arguments"):
            slot["function"]["arguments"] += function["arguments"]


def stream_chat_completion(
    client: httpx.Client,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    label: str,
    on_text: Callable[[str], None],
) -> tuple[dict[str, Any], str]:
    """Stream one chat completion, returning the assembled message and finish reason.

    `on_text` is called with each content fragment as it arrives. Transport errors and
    5xx responses are retried with backoff, but only while nothing has been emitted —
    once the caller has seen output, a retry would duplicate it, so the error is raised.
    """
    request = dict(payload)
    request["stream"] = True

    for attempt in range(SERVER_ERROR_MAX_RETRIES + 1):
        content_parts: list[str] = []
        tool_call_slots: dict[int, dict[str, Any]] = {}
        finish_reason = ""
        emitted = False
        try:
            with client.stream("POST", url, headers=headers, json=request) as response:
                if response.status_code >= 400:
                    response.read()
                    if response.status_code < 500 or attempt >= SERVER_ERROR_MAX_RETRIES:
                        response.raise_for_status()
                    logger.warning(
                        "Streaming request for %s returned %d; backing off %d seconds "
                        "before retry %d/%d.",
                        label,
                        response.status_code,
                        SERVER_ERROR_BACKOFF_SECONDS,
                        attempt + 1,
                        SERVER_ERROR_MAX_RETRIES,
                    )
                    time.sleep(SERVER_ERROR_BACKOFF_SECONDS)
                    continue

                for line in response.iter_lines():
                    line = line.strip()
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[len("data:") :].strip()
                    if data == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data)
                    except json.JSONDecodeError:
                        logger.warning("Discarding unparsable stream chunk for %s.", label)
                        continue
                    choices = chunk.get("choices") or []
                    if not choices:
                        continue
                    choice = choices[0]
                    delta = choice.get("delta") or {}
                    text = delta.get("content")
                    if text:
                        content_parts.append(text)
                        emitted = True
                        on_text(text)
                    if delta.get("tool_calls"):
                        _merge_tool_call_delta(tool_call_slots, delta)
                    if choice.get("finish_reason"):
                        finish_reason = choice["finish_reason"]
        except (httpx.TimeoutException, httpx.RemoteProtocolError, httpx.NetworkError) as exc:
            if emitted or attempt >= SERVER_ERROR_MAX_RETRIES:
                raise
            logger.warning(
                "Streaming request for %s raised %s: %s; backing off %d seconds before "
                "retry %d/%d.",
                label,
                type(exc).__name__,
                exc,
                SERVER_ERROR_BACKOFF_SECONDS,
                attempt + 1,
                SERVER_ERROR_MAX_RETRIES,
            )
            time.sleep(SERVER_ERROR_BACKOFF_SECONDS)
            continue

        message: dict[str, Any] = {
            "role": "assistant",
            "content": "".join(content_parts),
        }
        if tool_call_slots:
            message["tool_calls"] = [tool_call_slots[i] for i in sorted(tool_call_slots)]
            finish_reason = finish_reason or "tool_calls"
        return message, finish_reason or "stop"

    raise RuntimeError(f"Streaming request for {label} exhausted all retries")


def compact_history(
    client: httpx.Client,
    messages: list[dict[str, Any]],
    headers: dict[str, str],
    llm_cfg: "LLMConfig",
    label: str,
    continuation: str,
    keep_head: int = COMPACTION_KEEP_HEAD,
    keep_tail: int = COMPACTION_KEEP_TAIL,
) -> list[dict[str, Any]]:
    """Replace the middle of a conversation with an LLM-written summary.

    The first `keep_head` and last `keep_tail` messages survive verbatim; `continuation`
    tells the model how to pick the conversation back up. Returns `messages` unchanged
    when there is nothing worth compacting.
    """
    tail_start = max(keep_head, len(messages) - keep_tail)
    while tail_start < len(messages) and messages[tail_start].get("role") == "tool":
        tail_start += 1
    if tail_start <= keep_head or tail_start >= len(messages):
        return messages

    summarization_request = list(messages[:tail_start]) + [
        {"role": "user", "content": COMPACTION_REQUEST}
    ]

    before_chars = len(json.dumps(messages))
    before_count = len(messages)

    response = post_with_retry(
        client,
        f"{llm_cfg.url}/chat/completions",
        headers,
        {
            "model": llm_cfg.model,
            "messages": summarization_request,
        },
        f"{label} (compaction)",
    )
    summary = (response.json()["choices"][0]["message"].get("content") or "").strip()
    if not summary:
        raise RuntimeError(f"Compaction returned empty summary for {label}")

    compacted = (
        list(messages[:keep_head])
        + [
            {
                "role": "user",
                "content": (
                    "# Investigation So Far (Compacted)\n\n"
                    f"{summary}\n\n"
                    f"{continuation}"
                ),
            }
        ]
        + list(messages[tail_start:])
    )

    logger.info(
        "Compacted history for %s: %d -> %d chars, %d -> %d messages.",
        label,
        before_chars,
        len(json.dumps(compacted)),
        before_count,
        len(compacted),
    )
    return compacted
