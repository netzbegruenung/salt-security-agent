from __future__ import annotations

import json
import subprocess
import time

import redis

SCANNED_KEY = "salt:scanned"
IN_PROGRESS_PREFIX = "salt:in_progress:"
IN_PROGRESS_TTL = 14400  # seconds (4 hours)


def _redis_client(broker_url: str) -> redis.Redis:
    return redis.Redis.from_url(broker_url, decode_responses=True)


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


def pick_next_minion(broker_url: str, scan_period_seconds: int) -> str | None:
    """Return the oldest-scanned minion whose last scan is older than the period.

    Minions that have never been scanned are always eligible. Minions currently
    being scanned are excluded.
    """
    r = _redis_client(broker_url)
    minions = _list_accepted_minions()
    if not minions:
        return None

    pipe = r.pipeline()
    for m in minions:
        pipe.exists(_in_progress_key(m))
    in_progress_flags = pipe.execute()

    candidates = [m for m, flag in zip(minions, in_progress_flags) if not flag]
    if not candidates:
        return None

    scores = r.zmscore(SCANNED_KEY, candidates)
    cutoff = time.time() - scan_period_seconds
    overdue = [
        (m, s if s is not None else 0.0)
        for m, s in zip(candidates, scores)
        if s is None or s < cutoff
    ]
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
