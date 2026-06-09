from __future__ import annotations

import os
import subprocess
import sys

import click

from agent.config import CONFIG_PATH_ENV_VAR, DEFAULT_CONFIG_PATH


@click.group()
def cli() -> None:
    """Salt Security Agent — LLM-powered security scanning for Saltstack environments."""


@cli.command()
@click.option("--config", default=DEFAULT_CONFIG_PATH, show_default=True, help="Path to config file.")
@click.option("--loglevel", default="INFO", show_default=True, help="Log level.")
def worker(config: str, loglevel: str) -> None:
    """Start the Celery worker."""
    os.environ[CONFIG_PATH_ENV_VAR] = config
    from agent.config import load_config  # noqa: F401 — side-effect: validates config early
    load_config()

    cmd = [
        sys.executable, "-m", "celery",
        "-A", "agent.celery_app.app",
        "worker",
        f"--loglevel={loglevel}",
    ]
    subprocess.run(cmd, check=True)


@cli.command()
@click.option("--config", default=DEFAULT_CONFIG_PATH, show_default=True, help="Path to config file.")
@click.option("--loglevel", default="INFO", show_default=True, help="Log level.")
def beat(config: str, loglevel: str) -> None:
    """Start the Celery Beat scheduler."""
    os.environ[CONFIG_PATH_ENV_VAR] = config
    from agent.config import load_config  # noqa: F401
    load_config()

    cmd = [
        sys.executable, "-m", "celery",
        "-A", "agent.celery_app.app",
        "beat",
        f"--loglevel={loglevel}",
    ]
    subprocess.run(cmd, check=True)


@cli.command()
@click.argument("minion")
@click.option("--config", default=DEFAULT_CONFIG_PATH, show_default=True, help="Path to config file.")
def scan(minion: str, config: str) -> None:
    """Scan a specific MINION immediately (enqueued via Celery)."""
    os.environ[CONFIG_PATH_ENV_VAR] = config

    from agent.tasks import scan_minion
    result = scan_minion.delay(minion)
    click.echo(f"Task enqueued. ID: {result.id}")


@cli.command("flush-queue")
@click.option("--config", default=DEFAULT_CONFIG_PATH, show_default=True, help="Path to config file.")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
def flush_queue(config: str, yes: bool) -> None:
    """Discard all queued tasks from the Celery broker."""
    os.environ[CONFIG_PATH_ENV_VAR] = config

    from agent.celery_app import app

    if not yes:
        click.confirm("Discard all queued tasks?", abort=True)

    purged = app.control.purge()
    click.echo(f"Purged {purged} task(s) from the queue.")
