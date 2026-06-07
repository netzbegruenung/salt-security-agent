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
                    ├─ get_processes  ──► salt <minion> cmd.run 'ps aux'
                    │
                    └─ run_agent (LLM tool-calling loop)
                            │
                            ├─ ls_minion(path)       → salt <minion> cmd.run 'ls -la <path>'
                            ├─ list_repo_files(path) → os.scandir(repo_path / path)
                            └─ read_repo_file(path)  → open(repo_path / path)
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

[llm]
url = "https://api.openai.com/v1"
access_token = "sk-..."
model = "gpt-4o"
threat_model_path = "threat_models/default_threat_model.md"
task_path = "tasks/default_task.md"

[salt]
repo_path = "/srv/salt"   # Absolute path to the Salt state repository on the master

[celery]
broker_url = "redis://localhost:6379/0"
result_backend = "redis://localhost:6379/0"
```

### Threat model and task

- **`threat_model_path`** — Markdown file describing what to look for. A default is
  provided at `threat_models/default_threat_model.md`.
- **`task_path`** — Markdown file with the step-by-step instructions given to the agent.
  A default is provided at `tasks/default_task.md`.

Both paths are resolved relative to the current working directory if not absolute.

#### Per-minion overrides

Before each scan, the agent looks for a minion-specific file alongside the configured
default and uses it if present:

- `<threat_model_path dir>/<minion>.md` — overrides the threat model for that minion.
- `<task_path dir>/<minion>.md` — overrides the task for that minion.

If no per-minion file exists, the configured default is used. For example, with the
default config above, a minion named `web-01` would pick up
`threat_models/web-01.md` and `tasks/web-01.md` when those files exist.

## Usage

Start the Celery worker (handles actual scans):

```bash
salt-agent worker
```

Start the Celery Beat scheduler (dispatches scans at the configured rate):

```bash
salt-agent beat
```

Run both in separate terminals (or use a process supervisor like systemd or supervisord).
Example systemd units are provided under `examples/systemd/`.

Optional flags:

```bash
salt-agent worker --config /etc/salt-agent/config.toml --loglevel DEBUG
salt-agent beat   --config /etc/salt-agent/config.toml --loglevel INFO
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
    ├── llm_agent.py                   # LLM tool-calling loop (httpx)
    └── tools/
        ├── salt_tools.py              # ls_minion, get_processes
        └── repo_tools.py             # list_repo_files, read_repo_file
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
