# Salt Security Agent

An LLM-powered security scanning agent for Saltstack-managed environments. The agent
periodically selects Salt minions, fetches their running process list via the Salt CLI,
and runs an LLM-driven investigation that can inspect filesystem paths on the minion and
compare them against the Salt repository.

## Architecture

```
Celery Beat ──► dispatch_scans (task)
                    │
                    ▼
              pick_next_minion (Redis sorted set)
                    │
                    ▼
              scan_minion (task, runs on worker)
                    │
                    ├─ get_processes  ──► salt <minion> cmd.run 'ps aux' (container PIDs filtered)
                    │
                    └─ run_agent (LLM tool-calling loop)
                            │
                            ├─ ls_minion(path)       → salt <minion> cmd.run 'ls -la <path>'
                            ├─ list_repo_files(path) → os.scandir(repo_path / path)
                            ├─ read_repo_file(path)  → open(repo_path / path)
                            └─ spawn_subagent(task)  → run_subagent (optional; own tool loop,
                                                       same read-only tools, returns a summary)
```

- **Broker & state**: Redis
- **Scheduling**: Celery Beat ticks `dispatch_scans` once a minute; each tick scans the
  oldest minion whose last scan is older than the configured `scan_period`. Worker
  concurrency limits parallel scans.
- **Minion selection**: Redis sorted set (`salt:scanned`) tracks last-scan timestamps.
  The oldest-scanned minion whose timestamp is older than the scan period is selected;
  never-scanned minions are always eligible.
- **LLM communication**: Raw HTTP via `httpx` to any OpenAI-compatible chat completions
  endpoint.

## Requirements

- Python 3.11+
- Redis
- Salt master (with `salt` and `salt-key` CLI available)
- An OpenAI-compatible LLM API endpoint

## Installation

```bash
pip install -e .
```

## Configuration

Copy and edit `config.toml`:

```toml
[scanning]
parallel_hosts = 3            # Celery worker concurrency
scan_period = "daily"         # how often each minion is scanned: hourly, daily, weekly, monthly
# report_directory = "/var/lib/salt-security-agent/reports"  # Optional; see Reports section

[llm]
url = "https://api.openai.com/v1"
access_token = "sk-..."
model = "gpt-4o"
threat_model_path = "threat_models/default_threat_model.md"
task_path = "tasks/default_task.md"

# Optional. Sub-agent delegation; omit the section to keep it disabled.
[subagents]
enabled = false
max_spawns = 5         # sub-agents per scan
max_iterations = 25    # tool-calling rounds per sub-agent

[salt]
repo_path = "/srv/salt"   # Absolute path to the Salt state repository on the master

[celery]
broker_url = "redis://localhost:6379/0"
result_backend = "redis://localhost:6379/0"

# Optional. If present, alerts emitted by the agent's send_alert tool are also
# delivered by e-mail using authenticated SMTP. Omit the entire section to disable.
[smtp]
host = "smtp.example.com"
port = 587
username = "alerts@example.com"
password = "changeme"
from_address = "alerts@example.com"
to_address = "soc@example.com"
use_starttls = true  # STARTTLS; set false for implicit TLS / SMTPS (typically port 465)
```

### Threat model and task

- **`threat_model_path`** — Markdown file describing what to look for. A default is
  provided at `threat_models/default_threat_model.md`.
- **`task_path`** — Markdown file with the step-by-step instructions given to the agent.
  A default is provided at `tasks/default_task.md`.

Both paths are resolved relative to the current working directory if not absolute.

#### Per-minion overrides

Before each scan, the agent looks for a minion-specific file inside the configured
directory and uses it if present. Resolution order:

1. **Exact match** — `<dir>/<minion>.md`.
2. **Glob match** — any `<dir>/<pattern>.md` where `_` in the filename stem acts as
   a `*` wildcard. For example, `keycloak_.md` matches minion `keycloak01.example.com`
   (pattern `keycloak*`). If multiple glob files match, the one with the longest
   stem wins (most specific).
3. **Default** — `<dir>/default.md`.

With the config above, a minion named `web-01.example.com` would pick up, in order,
`threat_models/web-01.example.com.md`, then any glob like `threat_models/web_.md`
(`web*`), then `threat_models/default.md`. Same resolution applies to `tasks/`.

### Sub-agents

With `subagents.enabled = true`, the main agent gains a `spawn_subagent` tool that
delegates one focused investigation to a short-lived sub-agent — for example, auditing
every cron entry against the Salt repo, or triaging a long list of SUID binaries. The
point is to keep bulk tool output out of the main agent's context: only the sub-agent's
summary comes back.

A sub-agent:

- starts with an **empty context** — it only knows the `task` and `context` strings the
  main agent writes, plus the threat model and target minion;
- has the **same read-only inspection tools**, and nothing else: it cannot spawn further
  sub-agents, cannot call `create_report`, and cannot call `send_alert`;
- ends by calling `submit_findings`, whose text is the only thing the main agent receives;
- runs **synchronously** — the main agent blocks until it returns.

Its answer reaches the main agent wrapped in the usual untrusted-data markers, because it
is derived from minion data that an attacker may control. The main agent is instructed to
treat sub-agent output as a lead and to re-verify anything that would drive a
high-severity finding or an alert. Each sub-agent uses its own nonce, so injected data
cannot forge markers for the parent's session.

Cost scales accordingly: enabling this allows up to `max_spawns * max_iterations`
additional LLM round trips per scan on top of the main agent's own budget. Sub-agents that
hit `max_iterations` are forced to submit what they have; a sub-agent that fails entirely
reports that failure to the main agent rather than aborting the scan.

### Reports

By default, scan reports are written to the worker's stdout. Set `scanning.report_directory`
to persist them on disk instead. Each report is written to
`{report_directory}/{isodate}/{minion_id}` (e.g. `/var/lib/salt-security-agent/reports/2026-06-07/web-01`).
Parent directories are created automatically; re-running a scan on the same day overwrites the
previous report for that minion.

## Usage

Start the Celery worker (handles actual scans):

```bash
salt-security-agent worker
```

Start the Celery Beat scheduler (dispatches scans at the configured rate):

```bash
salt-security-agent beat
```

Run both in separate terminals (or use a process supervisor like systemd or supervisord).
Example systemd units are provided under `examples/systemd/`.

Optional flags:

```bash
salt-security-agent worker --config /etc/salt-security-agent/config.toml --loglevel DEBUG
salt-security-agent beat   --config /etc/salt-security-agent/config.toml --loglevel INFO
```

## File layout

```
salt-security-agent/
├── config.toml                        # Main configuration
├── pyproject.toml
├── tasks/
│   └── default_task.md                # Default agent task instructions
├── threat_models/
│   └── default_threat_model.md        # Default threat model
└── agent/
    ├── cli.py                         # Entry point (click)
    ├── config.py                      # Config loading (tomllib + dataclasses)
    ├── celery_app.py                  # Celery app + Beat schedule
    ├── tasks.py                       # Celery tasks
    ├── scheduler.py                   # Minion picker (Redis)
    ├── llm_agent.py                   # Main LLM tool-calling loop
    ├── llm_client.py                  # Shared LLM transport (httpx, retries, data wrapping)
    ├── subagent.py                    # Delegated sub-agent loop
    └── tools/
        ├── registry.py                # Tool schemas + inspection-tool dispatch
        ├── minion_tools.py            # ls_minion, get_processes, get_cron_jobs, ...
        ├── repo_tools.py              # list_repo_files, read_repo_file, grep_repo
        ├── report_tool.py             # create_report (Markdown rendering)
        └── alert_tool.py              # send_alert (log + optional SMTP)
```

## How minion selection works

All accepted minions are discovered via `salt-key -L --out=json`. Redis stores each
minion's last-scan Unix timestamp in a sorted set. `dispatch_scans` runs once a minute
and:

1. Excludes minions currently being scanned (`salt:in_progress`).
2. Filters to minions that are *overdue* — last scan older than `scan_period`, or never
   scanned at all.
3. Picks the one with the oldest timestamp from the overdue set; if none are overdue,
   the tick is a no-op.
4. Adds the chosen minion to `salt:in_progress` with a 1-hour TTL (auto-released if the
   worker dies).
5. After a successful scan, the timestamp is updated and the lock is released.

With N minions, this naturally yields ~N scans per scan period, spread across the
period. Burst capacity is bounded by `parallel_hosts` (worker concurrency).
