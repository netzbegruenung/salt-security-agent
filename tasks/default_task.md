# Default Security Audit Task

You are performing a security audit of a Salt-managed Linux host. Your goal is to identify
deviations from the expected configuration and any signs of compromise or misconfiguration.

## Steps

1. **Review running processes** — Identify any processes that are unexpected, unnamed, or
   running from unusual paths (e.g. `/tmp`, `/dev/shm`, home directories).

2. **Inspect key filesystem locations** — Use the `ls_minion` tool to examine directories
   such as `/etc`, `/usr/local/bin`, `/opt`, `/tmp`, and any paths referenced by suspicious
   processes.

3. **Compare against the Salt repo** — Use `list_repo_files` and `read_repo_file` to review
   the intended state of configuration files as defined in the Salt repository, then compare
   with what you observe on the minion.

4. **Report findings** — Summarise your findings clearly:
   - List any anomalies or suspicious items found.
   - For each finding, describe the evidence and the potential risk.
   - Suggest remediation steps where applicable.

Be thorough but concise. Focus on actionable findings.
