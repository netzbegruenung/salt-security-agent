from __future__ import annotations

import subprocess
import sys

import click


@click.group()
def cli() -> None:
    """Salt Security Agent — LLM-powered security scanning for Saltstack environments."""


@cli.command()
@click.option("--config", default="config.toml", show_default=True, help="Path to config file.")
@click.option("--loglevel", default="INFO", show_default=True, help="Log level.")
def worker(config: str, loglevel: str) -> None:
    """Start the Celery worker."""
    from agent.config import load_config  # noqa: F401 — side-effect: validates config early
    load_config(config)

    cmd = [
        sys.executable, "-m", "celery",
        "-A", "agent.celery_app.app",
        "worker",
        f"--loglevel={loglevel}",
    ]
    subprocess.run(cmd, check=True)


@cli.command()
@click.option("--config", default="config.toml", show_default=True, help="Path to config file.")
@click.option("--loglevel", default="INFO", show_default=True, help="Log level.")
def beat(config: str, loglevel: str) -> None:
    """Start the Celery Beat scheduler."""
    from agent.config import load_config  # noqa: F401
    load_config(config)

    cmd = [
        sys.executable, "-m", "celery",
        "-A", "agent.celery_app.app",
        "beat",
        f"--loglevel={loglevel}",
    ]
    subprocess.run(cmd, check=True)
