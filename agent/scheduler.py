from __future__ import annotations

import json
import subprocess
import time
from urllib.parse import parse_qsl, urlencode, urlparse

import redis

SCANNED_KEY = "salt:scanned"
FIRST_SEEN_KEY = "salt:first_seen"
IN_PROGRESS_PREFIX = "salt:in_progress:"
IN_PROGRESS_TTL = 14400  # seconds (4 hours)


def _to_redis_py_url(broker_url: str) -> str:
    # Celery/kombu uses "redis+socket://" for Unix sockets; redis-py uses "unix://".
    # Translate so a single broker_url works for both. urlunparse drops "//" for
    # schemes outside uses_netloc, so build the unix:// URL explicitly.
    if not broker_url.startswith("redis+socket://"):
        return broker_url
    parsed = urlparse(broker_url)
    query = urlencode(
        [("db" if k == "virtual_host" else k, v) for k, v in parse_qsl(parsed.query)]
    )
    url = f"unix://{parsed.path}"
    if query:
        url = f"{url}?{query}"
    return url


def _redis_client(broker_url: str) -> redis.Redis:
    return redis.Redis.from_url(_to_redis_py_url(broker_url), decode_responses=True)


def _in_progress_key(minion: str) -> str:
    return f"{IN_PROGRESS_PREFIX}{minion}"


def _list_accepted_minions() -> list[str]:
    result = subprocess.run(
        ["salt-key", "-L", "--out=json"],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(result.stdout)
    return data.get("minions", [])


def pick_next_minion(
    broker_url: str, scan_period_seconds: int, initial_delay_seconds: int
) -> str | None:
    """Return the oldest-scanned minion whose last scan is older than the period.

    Minions that have never been scanned are eligible only once they have been
    observed for at least initial_delay_seconds, so a freshly accepted minion is
    given time to finish setup before its first scan. Minions currently being
    scanned are excluded.
    """
    r = _redis_client(broker_url)
    minions = _list_accepted_minions()
    if not minions:
        return None

    now = time.time()
    pipe = r.pipeline()
    for m in minions:
        pipe.zadd(FIRST_SEEN_KEY, {m: now}, nx=True)
    for m in minions:
        pipe.exists(_in_progress_key(m))
    results = pipe.execute()
    in_progress_flags = results[len(minions):]

    candidates = [m for m, flag in zip(minions, in_progress_flags) if not flag]
    if not candidates:
        return None

    scores = r.zmscore(SCANNED_KEY, candidates)
    first_seen_scores = r.zmscore(FIRST_SEEN_KEY, candidates)
    cutoff = now - scan_period_seconds
    delay_cutoff = now - initial_delay_seconds
    overdue: list[tuple[str, float]] = []
    for m, scan_score, first_seen in zip(candidates, scores, first_seen_scores):
        if scan_score is None:
            if first_seen is not None and first_seen <= delay_cutoff:
                overdue.append((m, 0.0))
        elif scan_score < cutoff:
            overdue.append((m, scan_score))
    if not overdue:
        return None
    overdue.sort(key=lambda x: x[1])

    for minion, _ in overdue:
        acquired = r.set(_in_progress_key(minion), "1", nx=True, ex=IN_PROGRESS_TTL)
        if acquired:
            return minion
    return None


def mark_scanned(broker_url: str, minion: str) -> None:
    r = _redis_client(broker_url)
    r.zadd(SCANNED_KEY, {minion: time.time()})
    r.delete(_in_progress_key(minion))


def refresh_in_progress(broker_url: str, minion: str) -> None:
    """Reset the in-progress lock TTL so it covers actual scan execution, not just queue dwell time."""
    r = _redis_client(broker_url)
    r.set(_in_progress_key(minion), "1", ex=IN_PROGRESS_TTL)
