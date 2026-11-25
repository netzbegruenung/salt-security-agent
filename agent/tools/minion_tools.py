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

# Limits on model-supplied paths and patterns. Short enough that the operator can
# read a whole approval prompt, which shows these values in full.
MAX_PATH_LEN = 1024
MAX_PATTERN_LEN = 512


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


def validate_path(path: object) -> str:
    """Check a model-supplied minion path and return it unchanged.

    Only plain absolute paths pass: a leading `/` keeps the value from ever being
    parsed as a command-line option (`file -f<path>` dumps file contents), and
    rejecting `..` and non-printable characters means the path the operator sees
    in an approval prompt is the path that is opened.
    """
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    if len(path) > MAX_PATH_LEN:
        raise ValueError(f"path is longer than {MAX_PATH_LEN} characters")
    if not path.startswith("/"):
        raise ValueError(f"path must be absolute (start with '/'): {path!r}")
    if not path.isprintable():
        raise ValueError(f"path contains non-printable characters: {path!r}")
    if ".." in path.split("/"):
        raise ValueError(f"path must not contain '..' components: {path!r}")
    return path


def _strip_salt_prefix(minion: str, line: str) -> str:
    """Drop the `<minion>: ` prefix that `--out=txt` puts on every output line."""
    prefix = f"{minion}: "
    return line[len(prefix):] if line.startswith(prefix) else line


def ls_minion(minion: str, path: str) -> str:
    """Run 'ls -la <path>' on the given Salt minion."""
    validate_path(path)
    return salt_run(minion, f"ls -la -- {shlex.quote(path)}")


def file_minion(minion: str, path: str) -> str:
    """Run 'file <path>' on the given Salt minion to identify the file type."""
    validate_path(path)
    return salt_run(minion, f"file -- {shlex.quote(path)}")


def resolve_path_minion(minion: str, path: str) -> str:
    """Return the canonical path of an existing regular file on the minion.

    Symlinks are followed here, before the operator is asked, so that the approval
    prompt can name the file that will really be opened. The result goes through
    `validate_path` as well: a target whose name cannot be displayed faithfully is
    refused rather than shown in a misleading form.
    """
    validate_path(path)
    script = (
        f"p={shlex.quote(path)}; "
        'r=$(realpath -e -- "$p" 2>/dev/null) || { echo "ERROR: no such path: $p"; exit 0; }; '
        '[ -f "$r" ] || { echo "ERROR: not a regular file: $r"; exit 0; }; '
        'printf "RESOLVED:%s\n" "$r"'
    )
    output = salt_run(minion, script)
    lines = [_strip_salt_prefix(minion, line) for line in output.splitlines()]
    if len(lines) != 1 or not lines[0].startswith("RESOLVED:"):
        detail = lines[0] if len(lines) == 1 else "unexpected output from the minion"
        raise ValueError(f"could not resolve {path!r}: {detail}")
    return validate_path(lines[0][len("RESOLVED:"):])


# Shell guard shared by the operator-approved file tools. `$p` must already be the
# canonical path the operator approved; if it is (or has since become) a symlink,
# or any directory above it has, the call is refused instead of following it.
_CANONICAL_FILE_GUARD = (
    '[ -e "$p" ] || { echo "ERROR: no such path: $p"; exit 0; }; '
    '[ "$(realpath -e -- "$p" 2>/dev/null)" = "$p" ] || '
    '{ echo "ERROR: not a canonical path (symlink, or changed since approval): $p"; exit 0; }; '
    '[ -f "$p" ] || { echo "ERROR: not a regular file: $p"; exit 0; }; '
)


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
    are refused rather than dumped. `path` must be canonical (see
    `resolve_path_minion`): symlinks are refused, not followed.
    """
    validate_path(path)
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
        + _CANONICAL_FILE_GUARD
        + '[ -r "$p" ] || { echo "ERROR: not readable by the salt minion user: $p"; exit 0; }; '
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
    """Grep one regular file on the minion for an extended regular expression.

    Chat-only and operator-approved, like `read_file_minion`. Deliberately not
    recursive: one approval covers exactly one file. `path` must be canonical
    (see `resolve_path_minion`). Binary files are skipped, long lines are cut, and
    the match count is capped so a broad pattern cannot flood the context.
    """
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("pattern must be a non-empty string")
    if len(pattern) > MAX_PATTERN_LEN:
        raise ValueError(f"pattern is longer than {MAX_PATTERN_LEN} characters")
    if not pattern.isprintable():
        raise ValueError("pattern contains non-printable characters")
    validate_path(path)
    if max_matches is None:
        cap = DEFAULT_GREP_MATCHES
    else:
        try:
            cap = int(max_matches)
        except (TypeError, ValueError):
            raise ValueError(f"max_matches must be an integer, got {max_matches!r}")
        cap = max(1, min(cap, MAX_GREP_MATCHES))

    script = (
        f"p={shlex.quote(path)}; "
        + _CANONICAL_FILE_GUARD
        + f"grep -nIE -e {shlex.quote(pattern)} -- \"$p\" 2>/dev/null "
        f"| cut -c1-500 | head -n {cap}"
    )
    output = salt_run(minion, script)
    if not output:
        return f"No matches for pattern {pattern!r} in {path}"
    # `--out=txt` prefixes every line with `<minion>: `, so the in-band guards
    # from the script arrive prefixed while salt_run's own errors do not.
    first_line = output.split("\n", 1)[0]
    if first_line.startswith(("ERROR:", f"{minion}: ERROR:")):
        return output
    matches = output.count("\n") + 1
    if matches >= cap:
        output += f"\n... [stopped at {cap} matches; narrow the pattern]"
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
    """Return TCP and UDP listening sockets with associated processes (ss -tulpen).

    Each row gets a SCOPE column derived from the owning PID's cgroup, because a
    container that binds 0.0.0.0 inside its own namespace is not the same risk as
    a host daemon on all host interfaces, and raw `ss` output cannot tell them
    apart.
    """
    awk = (
        'NR==1{print $0"  SCOPE";next}'
        'function classify(l){'
        'if(match(l,/(docker|libpod|crio|cri-containerd)-[0-9a-f]{6,}/))'
        '{id=substr(l,RSTART,RLENGTH);sub(/^[a-z-]+-/,"",id);'
        'return "container:" substr(id,1,12)}'
        'if(l~/kubepods|\\/lxc\\/|lxc\\.payload|\\/docker\\/[0-9a-f]/)return "container";'
        'return ""}'
        '{scope="";comm="";'
        'if(match($0,/"[^"]+"/))comm=substr($0,RSTART+1,RLENGTH-2);'
        'if(match($0,/cgroup:[^ ]+/))scope=classify(substr($0,RSTART,RLENGTH));'
        'if(scope==""&&match($0,/pid=[0-9]+/)){'
        'pid=substr($0,RSTART+4,RLENGTH-4);cg="/proc/" pid "/cgroup";'
        'while((getline l<cg)>0){scope=classify(l);if(scope!="")break}'
        'close(cg)}'
        'if(scope=="")scope=($0~/cgroup:|pid=/)?"host":"unknown";'
        'if(scope=="host"&&(comm=="docker-proxy"||comm=="rootlesskit"||comm=="slirp4netns"))'
        'scope="host-portmap->container";'
        'print $0"  "scope}'
    )
    legend = (
        "echo '--- legend: SCOPE column ---'; "
        "echo 'host                  = process runs directly on the host; "
        "a 0.0.0.0 bind really is exposed on every host interface'; "
        "echo 'container:<id>        = process runs inside that container; "
        "a 0.0.0.0 bind is inside the container network namespace, not the host'; "
        "echo 'host-portmap->container = port-forwarding helper (docker-proxy/rootlesskit); "
        "the listen address shown is the host-side publish address chosen by the "
        "container runtime -- check get_containers for the mapping'; "
        "echo 'unknown               = no owning PID visible (ss lacked permission)'; "
        "echo; "
    )
    return salt_run(minion, f"{legend}ss -tulpen | awk '{awk}'")


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


def get_cron_jobs(minion: str, include_root_crontab: bool = False) -> str:
    """Return a listing of the cron.* directories, plus root's crontab if allowed.

    The crontab is file content, so it is only included when the operator has
    consented to that read (config pre-approval, or a per-call approval in chat).
    """
    crontab = (
        "crontab -l 2>/dev/null; "
        if include_root_crontab
        else "echo '(not shown: reading root crontab has not been approved by the operator)'; "
    )
    return salt_run(
        minion,
        f"echo '--- root crontab ---'; {crontab}"
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
