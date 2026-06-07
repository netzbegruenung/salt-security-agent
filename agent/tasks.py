from __future__ import annotations

import logging
from datetime import date

from agent.celery_app import app, cfg
from agent.llm_agent import run_agent
from agent.scheduler import mark_scanned, pick_next_minion, release_minion
from agent.tools.salt_tools import get_processes

logger = logging.getLogger(__name__)


@app.task(name="agent.tasks.dispatch_scans")
def dispatch_scans() -> None:
    minion = pick_next_minion(cfg.celery.broker_url, cfg.scanning.scan_period_seconds)
    if minion is None:
        logger.info("No minion available to scan (none overdue, all in progress, or none accepted).")
        return
    logger.info("Dispatching scan for minion: %s", minion)
    scan_minion.delay(minion)


@app.task(name="agent.tasks.scan_minion", bind=True, max_retries=2)
def scan_minion(self, minion: str) -> str:
    logger.info("Starting scan of minion: %s", minion)
    try:
        processes = get_processes(minion)
        report = run_agent(
            minion=minion,
            processes=processes,
            llm_cfg=cfg.llm,
            salt_cfg=cfg.salt,
            smtp_cfg=cfg.smtp,
        )
        mark_scanned(cfg.celery.broker_url, minion)
        logger.info("Scan complete for minion %s.", minion)
        if cfg.scanning.report_directory is not None:
            report_path = cfg.scanning.report_directory / date.today().isoformat() / minion
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(report, encoding="utf-8")
            logger.info("Wrote report for minion %s to %s.", minion, report_path)
        else:
            print(f"\n--- Report: {minion} ---\n\n{report}\n", flush=True)
        return report
    except Exception as exc:
        release_minion(cfg.celery.broker_url, minion)
        logger.exception("Scan failed for minion %s: %s", minion, exc)
        raise self.retry(exc=exc, countdown=60)
