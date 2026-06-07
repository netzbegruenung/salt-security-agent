from __future__ import annotations

import json
import subprocess
import time

import redis

SCANNED_KEY = "salt:scanned"
IN_PROGRESS_KEY = "salt:in_progress"
IN_PROGRESS_TTL = 3600  # seconds


def _redis_client(broker_url: str) -> redis.Redis:
    return redis.Redis.from_url(broker_url, decode_responses=True)


def _list_accepted_minions() -> list[str]:
    result = subprocess.run(
        ["salt-key", "-L", "--out=json"],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(result.stdout)
    return data.get("minions", [])


def pick_next_minion(broker_url: str) -> str | None:
    """Return the minion with the oldest (or absent) scan timestamp that is not in progress."""
    r = _redis_client(broker_url)
    minions = _list_accepted_minions()
    if not minions:
        return None

    in_progress = r.smembers(IN_PROGRESS_KEY)

    candidates = [m for m in minions if m not in in_progress]
    if not candidates:
        return None

    scores = r.zmscore(SCANNED_KEY, candidates)
    # pair each candidate with its score (None = never scanned → treat as 0)
    paired = [(m, s if s is not None else 0.0) for m, s in zip(candidates, scores)]
    paired.sort(key=lambda x: x[1])

    chosen = paired[0][0]
    r.sadd(IN_PROGRESS_KEY, chosen)
    r.expire(IN_PROGRESS_KEY, IN_PROGRESS_TTL)
    return chosen


def mark_scanned(broker_url: str, minion: str) -> None:
    r = _redis_client(broker_url)
    r.zadd(SCANNED_KEY, {minion: time.time()})
    r.srem(IN_PROGRESS_KEY, minion)


def release_minion(broker_url: str, minion: str) -> None:
    """Remove in-progress lock without updating scan timestamp (used on failure)."""
    r = _redis_client(broker_url)
    r.srem(IN_PROGRESS_KEY, minion)
