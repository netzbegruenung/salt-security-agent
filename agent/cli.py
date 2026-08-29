from __future__ import annotations

import logging
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
@click.argument("minion", required=False)
@click.option("--all", "scan_all", is_flag=True, help="Scan all accepted minions.")
@click.option("--config", default=DEFAULT_CONFIG_PATH, show_default=True, help="Path to config file.")
def scan(minion: str | None, scan_all: bool, config: str) -> None:
    """Scan a specific MINION immediately (enqueued via Celery)."""
    os.environ[CONFIG_PATH_ENV_VAR] = config

    if scan_all and minion:
        raise click.UsageError("Pass either MINION or --all, not both.")
    if not scan_all and not minion:
        raise click.UsageError("Provide a MINION argument or use --all.")

    from agent.tasks import scan_minion
    from agent.scheduler import _list_accepted_minions

    minions = _list_accepted_minions()

    if scan_all:
        if not minions:
            click.echo("No accepted minions found.")
            return
        for m in minions:
            result = scan_minion.delay(m)
            click.echo(f"{m}: enqueued (task ID: {result.id})")
        click.echo(f"Enqueued {len(minions)} scan task(s).")
        return

    if minion not in minions:
        raise click.BadParameter(
            f"Minion '{minion}' is not in the list of accepted minions.",
            param_hint="MINION",
        )

    result = scan_minion.delay(minion)
    click.echo(f"Task enqueued. ID: {result.id}")


@cli.command()
@click.argument("minion")
@click.option("--config", default=DEFAULT_CONFIG_PATH, show_default=True, help="Path to config file.")
@click.option("--log-file", default=None, help="Write agent logs here instead of discarding them.")
@click.option("--skip-key-check", is_flag=True, help="Do not check MINION against salt-key.")
def chat(minion: str, config: str, log_file: str | None, skip_key_check: bool) -> None:
    """Investigate MINION interactively in a terminal chat.

    Unlike a scan, this session can read arbitrary files from the minion — every such
    call has to be approved by you before it runs.
    """
    os.environ[CONFIG_PATH_ENV_VAR] = config

    from agent.config import load_config

    cfg = load_config()

    if not skip_key_check:
        from agent.scheduler import _list_accepted_minions

        accepted = _list_accepted_minions()
        if minion not in accepted:
            raise click.BadParameter(
                f"Minion '{minion}' is not in the list of accepted minions.",
                param_hint="MINION",
            )

    # curses owns the screen: anything logged to stderr would corrupt it.
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    if log_file:
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        root.addHandler(handler)
        root.setLevel(logging.INFO)
    else:
        root.addHandler(logging.NullHandler())

    from agent.chat import ChatSession
    from agent.chat_ui import run_chat_ui

    session = ChatSession(minion=minion, llm_cfg=cfg.llm, salt_cfg=cfg.salt)
    run_chat_ui(session)


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
