from __future__ import annotations

import re
import shlex
import subprocess

_MINION_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_MAX_MINION_LEN = 253

# The salt CLI turns any single-line argument that looks like `name=value` into a
# keyword argument (salt.utils.args.KWARG_REGEX). A script opening with a shell
# variable assignment would therefore be swallowed whole as a kwarg, leaving
# cmd.run without its positional `cmd`, so prefix such commands with a no-op.
_SALT_KWARG_LEADER = re.compile(r"^[^\d\W][\w.-]*=")

SALT_CLI_TIMEOUT = 45
SUBPROCESS_TIMEOUT = 90

# Paging limits for `read_file_minion`, which is chat-only and operator-approved.
DEFAULT_READ_LINES = 300
MAX_READ_LINES = 2000
MAX_READ_CHARS = 200_000

# Result limits for `grep_file_minion`.
DEFAULT_GREP_MATCHES = 100
MAX_GREP_MATCHES = 500
GREP_EXCLUDED_DIRS = (".git", "node_modules", "__pycache__", "proc", "sys", "dev")


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
    if _SALT_KWARG_LEADER.match(command):
        command = f":; {command}"
    result = subprocess.run(
        ["salt", "-t", str(SALT_CLI_TIMEOUT), minion, "cmd.run", command, "--out=txt"],
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
    )
    # Salt passes the remote exit code through, so a non-zero return says nothing
    # about whether the command produced usable output -- `find`, `grep` and
    # friends routinely exit non-zero with a perfectly good result on stdout.
    # Salt's own failures (no response, auth errors) also land on stdout and are
    # more informative than the generic stderr line.
    output = result.stdout.strip()
    if output:
        return output
    if result.returncode != 0 and result.stderr:
        return f"ERROR: {result.stderr.strip()}"
    return output


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


def _truncate(output: str, limit: int, what: str) -> str:
    if len(output) <= limit:
        return output
    return f"{output[:limit]}\n... [{what} truncated at {limit} characters]"


def read_file_minion(
    minion: str,
    path: str,
    offset: int = 1,
    limit: int | None = None,
) -> str:
    """Read a page of a text file on the minion, prefixed with absolute line numbers.

    Chat-only and operator-approved: this is the one tool that can pull arbitrary
    file contents off a minion, so it never appears in the unattended scan toolset.
    Reads at most MAX_READ_LINES lines starting at `offset` (1-based); binary files
    are refused rather than dumped.
    """
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    if offset is None:
        start = 1
    else:
        try:
            start = max(1, int(offset))
        except (TypeError, ValueError):
            raise ValueError(f"offset must be an integer line number, got {offset!r}")
    if limit is None:
        count = DEFAULT_READ_LINES
    else:
        try:
            count = int(limit)
        except (TypeError, ValueError):
            raise ValueError(f"limit must be an integer, got {limit!r}")
        count = max(1, min(count, MAX_READ_LINES))
    end = start + count - 1

    script = (
        f"p={shlex.quote(path)}; "
        '[ -e "$p" ] || { echo "ERROR: no such path: $p"; exit 0; }; '
        '[ -f "$p" ] || { echo "ERROR: not a regular file: $p"; exit 0; }; '
        '[ -r "$p" ] || { echo "ERROR: not readable by the salt minion user: $p"; exit 0; }; '
        'n=$(head -c 8192 "$p" | wc -c); m=$(head -c 8192 "$p" | tr -d "\\000" | wc -c); '
        '[ "$n" = "$m" ] || '
        '{ echo "ERROR: file looks binary (NUL bytes); use file_minion instead: $p"; exit 0; }; '
        'total=$(awk "END{print NR}" "$p"); '
        f'echo "--- $p (lines {start}-{end} of $total) ---"; '
        f"awk -v s={start} -v e={end} "
        "'NR>=s&&NR<=e{printf \"%6d| %s\\n\", NR, substr($0,1,1000)} NR>e{exit}' \"$p\""
    )
    output = salt_run(minion, script)
    if not output:
        return f"(no output; {path} may be empty or unreadable)"
    return _truncate(output, MAX_READ_CHARS, "file read")


def grep_file_minion(
    minion: str,
    pattern: str,
    path: str,
    max_matches: int | None = None,
) -> str:
    """Recursively grep a path on the minion for an extended regular expression.

    Chat-only and operator-approved, like `read_file_minion`. Binary files are
    skipped, long lines are cut, and the match count is capped so a broad pattern
    cannot flood the context.
    """
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("pattern must be a non-empty string")
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    if max_matches is None:
        cap = DEFAULT_GREP_MATCHES
    else:
        try:
            cap = int(max_matches)
        except (TypeError, ValueError):
            raise ValueError(f"max_matches must be an integer, got {max_matches!r}")
        cap = max(1, min(cap, MAX_GREP_MATCHES))

    excludes = " ".join(f"--exclude-dir={d}" for d in GREP_EXCLUDED_DIRS)
    script = (
        f"p={shlex.quote(path)}; "
        '[ -e "$p" ] || { echo "ERROR: no such path: $p"; exit 0; }; '
        f"grep -rnIE {excludes} -e {shlex.quote(pattern)} -- \"$p\" 2>/dev/null "
        f"| cut -c1-500 | head -n {cap}"
    )
    output = salt_run(minion, script)
    if not output:
        return f"No matches for pattern {pattern!r} under {path}"
    # `--out=txt` prefixes every line with `<minion>: `, so the in-band guards
    # from the script arrive prefixed while salt_run's own errors do not.
    first_line = output.split("\n", 1)[0]
    if first_line.startswith(("ERROR:", f"{minion}: ERROR:")):
        return output
    matches = output.count("\n") + 1
    if matches >= cap:
        output += f"\n... [stopped at {cap} matches; narrow the pattern or the path]"
    return _truncate(output, MAX_READ_CHARS, "grep output")


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
