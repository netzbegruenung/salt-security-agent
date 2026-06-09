from __future__ import annotations

import subprocess

from agent.tools.salt_tools import (
    SALT_CLI_TIMEOUT,
    SUBPROCESS_TIMEOUT,
    _salt_run,
    _validate_minion,
)


def get_os_info(minion: str) -> str:
    """Return parsed /etc/os-release contents (OS name, version, ID)."""
    return _salt_run(minion, "cat /etc/os-release")


def get_listening_ports(minion: str) -> str:
    """Return TCP and UDP listening sockets with associated processes (ss -tulpen)."""
    return _salt_run(minion, "ss -tulpen")


def get_running_services(minion: str) -> str:
    """List currently running systemd services."""
    return _salt_run(
        minion,
        "systemctl list-units --type=service --state=running --no-pager --plain",
    )


def get_failed_services(minion: str) -> str:
    """List failed systemd units."""
    return _salt_run(
        minion,
        "systemctl list-units --type=service --state=failed --no-pager --plain",
    )


def get_suid_files(minion: str) -> str:
    """Return SUID binaries under common system paths (/usr /bin /sbin /opt)."""
    return _salt_run(
        minion,
        "find /usr /bin /sbin /opt -perm -4000 -type f 2>/dev/null",
    )


def get_users(minion: str) -> str:
    """Return user accounts from /etc/passwd (username:uid:gid:home:shell)."""
    return _salt_run(
        minion,
        "awk -F: '{print $1\":\"$3\":\"$4\":\"$6\":\"$7}' /etc/passwd",
    )


def get_cron_jobs(minion: str) -> str:
    """Return root's crontab and a listing of cron.* directories."""
    return _salt_run(
        minion,
        "echo '--- root crontab ---'; crontab -l 2>/dev/null; "
        "for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do "
        "echo \"--- $d ---\"; ls -la \"$d\" 2>/dev/null; done",
    )


def get_last_logins(minion: str) -> str:
    """Return the last 20 login records (last -n 20)."""
    return _salt_run(minion, "last -n 20")


def get_containers(minion: str) -> str:
    """List running Docker, Podman, and LXC containers on the minion.

    Missing runtimes are reported as such rather than failing the call. Output is
    grouped under `--- docker ---`, `--- podman ---`, and `--- lxc ---` sections.
    """
    return _salt_run(
        minion,
        "echo '--- docker ---'; "
        "if command -v docker >/dev/null 2>&1; then "
        "docker ps --format 'table {{.ID}}\\t{{.Image}}\\t{{.Status}}\\t{{.Names}}\\t{{.Ports}}' 2>&1; "
        "else echo '(docker not installed)'; fi; "
        "echo; echo '--- podman ---'; "
        "if command -v podman >/dev/null 2>&1; then "
        "podman ps --format 'table {{.ID}}\\t{{.Image}}\\t{{.Status}}\\t{{.Names}}\\t{{.Ports}}' 2>&1; "
        "else echo '(podman not installed)'; fi; "
        "echo; echo '--- lxc ---'; "
        "if command -v lxc-ls >/dev/null 2>&1; then lxc-ls --running -f 2>&1; "
        "else echo '(lxc-ls not installed)'; fi",
    )


def get_salt_grains(minion: str) -> str:
    """Return Salt grains (system metadata) for the minion."""
    _validate_minion(minion)
    result = subprocess.run(
        ["salt", "-t", str(SALT_CLI_TIMEOUT), minion, "grains.items", "--out=yaml"],
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
    )
    if result.returncode != 0 and result.stderr:
        return f"ERROR: {result.stderr.strip()}"
    return result.stdout.strip()
