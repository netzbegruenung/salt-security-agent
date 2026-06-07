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


@cli.command()
@click.argument("minion")
@click.option("--config", default="config.toml", show_default=True, help="Path to config file.")
@click.option("--background", is_flag=True, default=False, help="Enqueue via Celery instead of running inline.")
def scan(minion: str, config: str, background: bool) -> None:
    """Scan a specific MINION immediately."""
    from agent.config import load_config
    cfg = load_config(config)

    if background:
        from agent.tasks import scan_minion
        result = scan_minion.delay(minion)
        click.echo(f"Task enqueued. ID: {result.id}")
        return

    from agent.llm_agent import run_agent
    from agent.tools.salt_tools import get_processes

    click.echo(f"Fetching processes from {minion}...")
    processes = get_processes(minion)

    click.echo("Running LLM agent...")
    report = run_agent(
        minion=minion,
        processes=processes,
        llm_cfg=cfg.llm,
        salt_cfg=cfg.salt,
    )
    click.echo("\n--- Report ---\n")
    click.echo(report)
