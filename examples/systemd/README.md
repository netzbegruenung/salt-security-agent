# systemd example units

Example `systemd` service files for running the Salt Security Agent under a
process supervisor. There are two units: one for the Celery worker (which
performs scans) and one for Celery Beat (which dispatches them on a schedule).
Both are needed for normal operation.

## Files

- `salt-security-agent-worker.service` — runs `salt-security-agent worker`
- `salt-security-agent-beat.service` — runs `salt-security-agent beat`

## Prerequisites

1. **Install the package in a virtual environment**:

   ```bash
   cd /opt/salt-security-agent
   python3 -m venv venv
   pip install /path/to/salt-security-agent
   ```

1. **Place the config** at `/etc/salt-security-agent/config.toml` (or adjust `--config`
   in both `ExecStart` lines). Make sure the `salt-security-agent` user can read it:

   ```bash
   install -d -o salt-security-agent -g salt-security-agent -m 0750 /etc/salt-security-agent
   install -o salt-security-agent -g salt-security-agent -m 0640 config.toml /etc/salt-security-agent/config.toml
   ```

1. **Grant Salt CLI access.** The agent calls `salt` and `salt-key`. The
   `salt-security-agent` user needs permission to run these — for example by adding it
   to the `salt` group, or via a narrowly scoped `sudoers` rule. Without this,
   minion discovery and process collection will fail.

## Install

```bash
sudo cp salt-security-agent-worker.service salt-security-agent-beat.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now salt-security-agent-worker.service salt-security-agent-beat.service
```

## Operate

```bash
systemctl status salt-security-agent-worker salt-security-agent-beat
journalctl -u salt-security-agent-worker -f
journalctl -u salt-security-agent-beat -f
```

## Notes

- Beat is ordered `After=` the worker but does not `Require=` it; the two
  units can be started, stopped, and restarted independently.
- `KillMode=mixed` with `TimeoutStopSec=30` gives the worker a 30 s window to
  finish in-flight scans on shutdown. Increase if your scans typically run
  longer.
- The hardening directives (`ProtectSystem=strict`, `ProtectHome=true`, etc.)
  assume the agent only needs to write under `/etc/salt-security-agent`. If you point
  it at logs or a Beat schedule file elsewhere, extend `ReadWritePaths=`.
