from __future__ import annotations

import re
import shlex
import subprocess

_MINION_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_MAX_MINION_LEN = 253


def _validate_minion(minion: str) -> str:
    if (
        not isinstance(minion, str)
        or len(minion) > _MAX_MINION_LEN
        or not _MINION_ID_RE.fullmatch(minion)
    ):
        raise ValueError(f"Invalid minion id: {minion!r}")
    return minion


def _salt_run(minion: str, command: str) -> str:
    _validate_minion(minion)
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
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    return _salt_run(minion, f"ls -la {shlex.quote(path)}")


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
    return _salt_run(minion, f"ps aux | awk '{awk}'")
