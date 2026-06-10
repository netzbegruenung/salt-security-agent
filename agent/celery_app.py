from __future__ import annotations

from celery import Celery
from celery.schedules import schedule

from agent.config import load_config

cfg = load_config()

app = Celery("salt-security-agent")

app.conf.update(
    broker_url=cfg.celery.broker_url,
    result_backend=cfg.celery.result_backend,
    worker_concurrency=cfg.scanning.parallel_hosts,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    beat_schedule={
        "dispatch-scans": {
            "task": "agent.tasks.dispatch_scans",
            "schedule": schedule(run_every=300),
        },
    },
)

app.autodiscover_tasks(["agent"])
