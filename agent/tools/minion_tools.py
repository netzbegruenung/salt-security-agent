from __future__ import annotations

import re
import shlex
import subprocess

_MINION_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_MAX_MINION_LEN = 253

SALT_CLI_TIMEOUT = 45
SUBPROCESS_TIMEOUT = 90


def validate_minion(minion: str) -> str:
    if (
        not isinstance(minion, str)
        or len(minion) > _MAX_MINION_LEN
        or not _MINION_ID_RE.fullmatch(minion)
    ):
        raise ValueError(f"Invalid minion id: {minion!r}")
    return minion


def salt_run(minion: str, command: str) -> str:
    validate_minion(minion)
    result = subprocess.run(
        ["salt", "-t", str(SALT_CLI_TIMEOUT), minion, "cmd.run", command, "--out=txt"],
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
    )
    if result.returncode != 0 and result.stderr:
        return f"ERROR: {result.stderr.strip()}"
    return result.stdout.strip()


def ls_minion(minion: str, path: str) -> str:
    """Run 'ls -la <path>' on the given Salt minion."""
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    return salt_run(minion, f"ls -la {shlex.quote(path)}")


def file_minion(minion: str, path: str) -> str:
    """Run 'file <path>' on the given Salt minion to identify the file type."""
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    return salt_run(minion, f"file {shlex.quote(path)}")


def get_os_info(minion: str) -> str:
    """Return parsed /etc/os-release contents (OS name, version, ID)."""
    return salt_run(minion, "cat /etc/os-release")


def get_salt_grains(minion: str) -> str:
    """Return Salt grains (system metadata) for the minion."""
    validate_minion(minion)
    result = subprocess.run(
        ["salt", "-t", str(SALT_CLI_TIMEOUT), minion, "grains.items", "--out=yaml"],
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
    )
    if result.returncode != 0 and result.stderr:
        return f"ERROR: {result.stderr.strip()}"
    return result.stdout.strip()


def get_processes(minion: str) -> str:
    """Return host process list from the minion, excluding processes inside containers.

    Filters out any PID whose /proc/<pid>/cgroup matches a known container runtime
    (Docker, Podman, CRI-O, containerd/Kubernetes, LXC) so that processes from
    `docker compose` and similar do not appear as host-level installed applications.
    """
    awk = (
        "NR==1{print;next}"
        "{pid=$2;cg=\"/proc/\" pid \"/cgroup\";skip=0;"
        "while((getline l<cg)>0)"
        "if(l~/(docker|libpod|crio|cri-containerd)-[0-9a-f]{6,}|\\/docker\\/[0-9a-f]|kubepods|\\/lxc\\/|lxc\\.payload/)"
        "{skip=1;break}"
        "close(cg);if(!skip)print}"
    )
    return salt_run(minion, f"ps aux | awk '{awk}'")


def get_running_services(minion: str) -> str:
    """List currently running systemd services."""
    return salt_run(
        minion,
        "systemctl list-units --type=service --state=running --no-pager --plain",
    )


def get_failed_services(minion: str) -> str:
    """List failed systemd units."""
    return salt_run(
        minion,
        "systemctl list-units --type=service --state=failed --no-pager --plain",
    )


def get_listening_ports(minion: str) -> str:
    """Return TCP and UDP listening sockets with associated processes (ss -tulpen)."""
    return salt_run(minion, "ss -tulpen")


def get_suid_files(minion: str) -> str:
    """Return SUID binaries under common system paths (/usr /bin /sbin /opt)."""
    return salt_run(
        minion,
        "find /usr /bin /sbin /opt -perm -4000 -type f 2>/dev/null",
    )


def get_users(minion: str) -> str:
    """Return user accounts from /etc/passwd (username:uid:gid:home:shell)."""
    return salt_run(
        minion,
        "awk -F: '{print $1\":\"$3\":\"$4\":\"$6\":\"$7}' /etc/passwd",
    )


def get_cron_jobs(minion: str) -> str:
    """Return root's crontab and a listing of cron.* directories."""
    return salt_run(
        minion,
        "echo '--- root crontab ---'; crontab -l 2>/dev/null; "
        "for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do "
        "echo \"--- $d ---\"; ls -la \"$d\" 2>/dev/null; done",
    )


def get_last_logins(minion: str) -> str:
    """Return the last 20 login records (last -n 20)."""
    return salt_run(minion, "last -n 20")


def get_support_status(minion: str) -> str:
    """Run `check-support-status` on the minion (Debian only).

    Lists installed packages whose security support has ended or is limited.
    """
    return salt_run(minion, "check-support-status")


def get_containers(minion: str) -> str:
    """List running Docker, Podman, and LXC containers on the minion.

    Missing runtimes are reported as such rather than failing the call. Output is
    grouped under `--- docker ---`, `--- podman ---`, and `--- lxc ---` sections.
    """
    return salt_run(
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
