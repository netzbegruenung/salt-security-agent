from __future__ import annotations

import subprocess


def _salt_run(minion: str, command: str) -> str:
    result = subprocess.run(
        ["salt", minion, "cmd.run", command, "--out=txt"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0 and result.stderr:
        return f"ERROR: {result.stderr.strip()}"
    return result.stdout.strip()


def ls_minion(minion: str, path: str) -> str:
    """Run 'ls -la <path>' on the given Salt minion."""
    return _salt_run(minion, f"ls -la {path}")


def get_processes(minion: str) -> str:
    """Return running process list from the given Salt minion."""
    return _salt_run(minion, "ps aux")
