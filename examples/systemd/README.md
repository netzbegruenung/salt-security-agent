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
   in both `ExecStart` lines).

   ```bash
   install -d -o root -g salt-security-agent -m 0750 /etc/salt-security-agent
   install -o root -g salt-security-agent -m 0640 config.toml /etc/salt-security-agent/config.toml
   ```

   The directory and everything in it (config, threat models, tasks) belong to
   `root`; the service user can read them through its group but cannot change
   them. Install `threat_models/` and `tasks/` the same way.

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
- The agent has no write access to its own configuration: `/etc/salt-security-agent`
  is owned by `root` and mounted read-only for both units (`ReadOnlyPaths=`).
- Both units run as the unprivileged `salt-security-agent` user. Beat keeps its
  schedule database in the state directory (`--schedule` in its `ExecStart`).
- The units can write only to the state directory `/var/lib/salt-security-agent`
  (`StateDirectory=`, created by systemd). Set `scanning.report_directory` to a path
  below it, e.g. `/var/lib/salt-security-agent/reports`. If you write logs or reports
  elsewhere, add `ReadWritePaths=` for that location.
