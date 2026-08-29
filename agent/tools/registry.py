from __future__ import annotations

from typing import Any

from agent.config import SaltConfig
from agent.tools.repo_tools import grep_repo, list_repo_files, read_repo_file
from agent.tools.minion_tools import (
    DEFAULT_GREP_MATCHES,
    DEFAULT_READ_LINES,
    MAX_GREP_MATCHES,
    MAX_READ_LINES,
    file_minion,
    get_containers,
    get_cron_jobs,
    get_failed_services,
    get_last_logins,
    get_listening_ports,
    get_os_info,
    get_running_services,
    get_salt_grains,
    get_suid_files,
    get_support_status,
    get_users,
    grep_file_minion,
    ls_minion,
    read_file_minion,
)

# Read-only inspection tools. Available to the main agent and to sub-agents alike;
# every result is untrusted data and must be wrapped before it enters a context.
INVESTIGATION_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "ls_minion",
            "description": "List files and directories at the given absolute path on the Salt minion.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path on the minion to list.",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "file_minion",
            "description": "Run the `file` command on a path on the Salt minion to identify its type (e.g. ELF binary, script, data).",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path on the minion to inspect.",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_repo_files",
            "description": "List files and directories at a relative path inside the Salt repository on the master.",
            "parameters": {
                "type": "object",
                "properties": {
                    "rel_path": {
                        "type": "string",
                        "description": "Relative path inside the Salt repo. Use empty string for the root.",
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_repo_file",
            "description": "Read the contents of a file from the Salt repository on the master.",
            "parameters": {
                "type": "object",
                "properties": {
                    "rel_path": {
                        "type": "string",
                        "description": "Relative path to the file inside the Salt repo.",
                    }
                },
                "required": ["rel_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep_repo",
            "description": (
                "Recursively search for a text pattern in files within the Salt repository. "
                "Returns matched lines with filename, line number, and content. "
                "Use rel_path=''' to search from repo root, or specify a subdirectory. "
                "Search is case-insensitive."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Text pattern to search for (case-insensitive).",
                    },
                    "rel_path": {
                        "type": "string",
                        "description": "Relative subdirectory to search within. Use empty string for root.",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_os_info",
            "description": "Return /etc/os-release contents on the minion (OS name, version, ID).",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_listening_ports",
            "description": "Return TCP and UDP listening sockets on the minion with the owning process (ss -tulpen).",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_running_services",
            "description": "List currently running systemd services on the minion.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_failed_services",
            "description": "List failed systemd units on the minion (often a sign of tampering or misconfiguration).",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_suid_files",
            "description": "Return SUID binaries under /usr, /bin, /sbin, /opt on the minion. Key privilege-escalation indicator.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_users",
            "description": "Return local user accounts from /etc/passwd on the minion as username:uid:gid:home:shell. Does not expose passwords.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_cron_jobs",
            "description": "Return root's crontab and a listing of /etc/cron.* directories on the minion. Common persistence mechanism.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_last_logins",
            "description": "Return the last 20 login records from the auth log on the minion (output of `last -n 20`).",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_salt_grains",
            "description": "Return Salt grains (system metadata Salt knows about the minion) as YAML.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_support_status",
            "description": (
                "Run `check-support-status` on the minion to list installed packages whose "
                "security support has ended or is limited. Only works on Debian systems."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_containers",
            "description": (
                "List running Docker, Podman, and LXC containers on the minion. "
                "Use this to understand which workloads are expected to be running "
                "inside containers (container PIDs are excluded from the host process list)."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]

# Chat-only tools. These pull arbitrary file content off a minion, so they are
# deliberately absent from INVESTIGATION_TOOLS: an unattended scan and its sub-agents
# must never reach them. In the interactive chat every call is approved by the
# operator before it runs (see APPROVAL_REQUIRED_TOOLS).
CHAT_ONLY_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file_minion",
            "description": (
                "Read a page of a text file on the Salt minion, with absolute line numbers. "
                f"Returns at most {MAX_READ_LINES} lines per call ({DEFAULT_READ_LINES} by "
                "default) starting at `offset`; page through long files by repeating the call "
                "with a higher `offset`. Binary files are refused — use `file_minion` on those. "
                "Every call requires the operator's explicit approval, so read deliberately and "
                "say what you are looking for before you call it."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path of the file on the minion.",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "1-based line number to start reading at. Defaults to 1.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": (
                            f"Number of lines to read, capped at {MAX_READ_LINES}. "
                            f"Defaults to {DEFAULT_READ_LINES}."
                        ),
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep_file_minion",
            "description": (
                "Recursively search a file or directory on the Salt minion for an extended "
                "regular expression (case-sensitive, POSIX ERE as used by `grep -E`). Returns "
                "matches as path:line:content, skipping binary files and cutting long lines. "
                f"Capped at {DEFAULT_GREP_MATCHES} matches by default and {MAX_GREP_MATCHES} "
                "at most. Every call requires the operator's explicit approval — prefer a "
                "narrow path over searching from the filesystem root."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Extended regular expression to search for.",
                    },
                    "path": {
                        "type": "string",
                        "description": (
                            "Absolute file or directory path on the minion to search. "
                            "Directories are searched recursively."
                        ),
                    },
                    "max_matches": {
                        "type": "integer",
                        "description": (
                            f"Maximum number of matching lines to return (cap {MAX_GREP_MATCHES})."
                        ),
                    },
                },
                "required": ["pattern", "path"],
            },
        },
    },
]

# The full toolset offered in the interactive chat: read-only inspection plus the
# two approval-gated file tools. No reporting, alerting, or delegation.
CHAT_TOOLS = INVESTIGATION_TOOLS + CHAT_ONLY_TOOLS

# Tools the operator must approve on every single call.
APPROVAL_REQUIRED_TOOLS = frozenset({"read_file_minion", "grep_file_minion"})


# Terminal tools for the main agent only. Sub-agents never report or alert directly.
REPORTING_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "create_report",
            "description": (
                "Submit the final findings report. Call this exactly once at the end of your "
                "investigation. The report is rendered into a consistent Markdown structure "
                "from the fields you provide here — do not write the report as free-form text."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Executive summary of the investigation and the minion's overall security posture.",
                    },
                    "overall_risk": {
                        "type": "string",
                        "enum": ["none", "low", "medium", "high", "critical"],
                        "description": "Overall risk level for this minion based on the findings.",
                    },
                    "findings": {
                        "type": "array",
                        "description": "List of individual findings. May be empty if nothing of note was discovered.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {
                                    "type": "string",
                                    "description": "Short headline of the finding (one line).",
                                },
                                "severity": {
                                    "type": "string",
                                    "enum": ["info", "low", "medium", "high", "critical"],
                                    "description": "Severity of this individual finding.",
                                },
                                "evidence": {
                                    "type": "string",
                                    "description": "Concrete evidence: file paths, command output, configuration excerpts, etc.",
                                },
                                "risk": {
                                    "type": "string",
                                    "description": "Why this matters and what the potential impact is.",
                                },
                                "recommendation": {
                                    "type": "string",
                                    "description": "Recommended remediation or mitigation.",
                                },
                            },
                            "required": ["title", "severity", "evidence", "risk", "recommendation"],
                        },
                    },
                },
                "required": ["summary", "overall_risk", "findings"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_alert",
            "description": (
                "Dispatch a security alert for an extremely critical deviation or a strong "
                "indicator of compromise. Use sparingly — only for findings that require "
                "immediate human attention. Routine drift or low-confidence findings should "
                "be reported in the final report instead, not via this tool."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high"],
                        "description": "Severity of the alert.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Short headline of the alert (one line).",
                    },
                    "details": {
                        "type": "string",
                        "description": "Full details: what was found, where, evidence, and why it matters.",
                    },
                },
                "required": ["severity", "title", "details"],
            },
        },
    },
]

# Offered to the main agent only when sub-agents are enabled in the config.
SPAWN_SUBAGENT_TOOL = {
    "type": "function",
    "function": {
        "name": "spawn_subagent",
        "description": (
            "Delegate one focused, self-contained investigation to a sub-agent and get back a "
            "text summary of what it found. The sub-agent starts with an empty context: it "
            "knows nothing about your conversation beyond what you write in `task` and "
            "`context`. It has the same read-only inspection tools you do, cannot spawn "
            "further sub-agents, and cannot report or alert. Use this to keep bulk tool "
            "output out of your own context — e.g. auditing every cron entry against the "
            "Salt repo, or triaging a long list of SUID binaries. State exactly what you "
            "want established and what evidence to bring back."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": (
                        "The complete instruction for the sub-agent: what to investigate, "
                        "which paths or artefacts to look at, and what to report back."
                    ),
                },
                "context": {
                    "type": "string",
                    "description": (
                        "Optional background the sub-agent needs (findings so far, expected "
                        "baseline, paths already ruled out). It has no other knowledge."
                    ),
                },
            },
            "required": ["task"],
        },
    },
}

# The sub-agent's only terminal tool: hand results back to the orchestrator.
SUBMIT_FINDINGS_TOOL = {
    "type": "function",
    "function": {
        "name": "submit_findings",
        "description": (
            "Return your findings to the orchestrating agent. Call this exactly once when "
            "your assigned task is complete. This text is the only thing the orchestrator "
            "sees — it cannot inspect your tool calls."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "string",
                    "description": (
                        "What you established, with concrete evidence (paths, command output "
                        "excerpts), what you ruled out, and anything you could not determine."
                    ),
                },
                "risk_observed": {
                    "type": "string",
                    "enum": ["none", "low", "medium", "high", "critical"],
                    "description": "Your assessment of the risk implied by what you found.",
                },
            },
            "required": ["findings"],
        },
    },
}


def call_investigation_tool(
    name: str,
    arguments: dict[str, Any],
    minion: str,
    salt_cfg: SaltConfig,
) -> str | None:
    """Dispatch a read-only inspection tool.

    Returns None if `name` is not an investigation tool, so callers can handle the
    tools specific to their own agent role.
    """
    if name == "ls_minion":
        return ls_minion(minion, arguments["path"])
    if name == "file_minion":
        return file_minion(minion, arguments["path"])
    if name == "list_repo_files":
        return list_repo_files(salt_cfg.repo_path, arguments.get("rel_path", ""))
    if name == "read_repo_file":
        return read_repo_file(salt_cfg.repo_path, arguments["rel_path"])
    if name == "grep_repo":
        pattern = arguments["pattern"]
        rel_path = arguments.get("rel_path", "")
        return grep_repo(salt_cfg.repo_path, pattern, rel_path)
    if name == "get_os_info":
        return get_os_info(minion)
    if name == "get_listening_ports":
        return get_listening_ports(minion)
    if name == "get_running_services":
        return get_running_services(minion)
    if name == "get_failed_services":
        return get_failed_services(minion)
    if name == "get_suid_files":
        return get_suid_files(minion)
    if name == "get_users":
        return get_users(minion)
    if name == "get_cron_jobs":
        return get_cron_jobs(minion)
    if name == "get_last_logins":
        return get_last_logins(minion)
    if name == "get_salt_grains":
        return get_salt_grains(minion)
    if name == "get_containers":
        return get_containers(minion)
    if name == "get_support_status":
        return get_support_status(minion)
    return None


def call_chat_tool(
    name: str,
    arguments: dict[str, Any],
    minion: str,
    salt_cfg: SaltConfig,
) -> str | None:
    """Dispatch a tool available in the interactive chat.

    Kept separate from `call_investigation_tool` so the chat-only file tools stay
    unreachable from the scan and sub-agent loops, which call that function directly.
    """
    result = call_investigation_tool(name, arguments, minion, salt_cfg)
    if result is not None:
        return result
    if name == "read_file_minion":
        return read_file_minion(
            minion,
            arguments["path"],
            offset=arguments.get("offset", 1),
            limit=arguments.get("limit"),
        )
    if name == "grep_file_minion":
        return grep_file_minion(
            minion,
            arguments["pattern"],
            arguments["path"],
            max_matches=arguments.get("max_matches"),
        )
    return None
