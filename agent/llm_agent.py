from __future__ import annotations

import fnmatch
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from agent.config import LLMConfig, SaltConfig, SmtpConfig
from agent.tools.alert_tool import send_alert
from agent.tools.repo_tools import list_repo_files, read_repo_file, grep_repo
from agent.tools.report_tool import create_report
from agent.tools.minion_tools import (
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
    ls_minion,
)

logger = logging.getLogger(__name__)

MAX_ITERATIONS = 50
SERVER_ERROR_BACKOFF_SECONDS = 300
SERVER_ERROR_MAX_RETRIES = 5
COMPACTION_THRESHOLD = 0.8
COMPACTION_KEEP_HEAD = 2
COMPACTION_KEEP_TAIL = 6


def _post_with_retry(
    client: httpx.Client,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    minion: str,
) -> httpx.Response:
    for attempt in range(SERVER_ERROR_MAX_RETRIES + 1):
        try:
            response = client.post(url, headers=headers, json=payload)
        except (httpx.TimeoutException, httpx.RemoteProtocolError, httpx.NetworkError) as exc:
            if attempt >= SERVER_ERROR_MAX_RETRIES:
                raise
            logger.warning(
                "LLM request for minion %s raised %s: %s; backing off %d seconds before retry %d/%d.",
                minion,
                type(exc).__name__,
                exc,
                SERVER_ERROR_BACKOFF_SECONDS,
                attempt + 1,
                SERVER_ERROR_MAX_RETRIES,
            )
            time.sleep(SERVER_ERROR_BACKOFF_SECONDS)
            continue
        if response.status_code < 500:
            response.raise_for_status()
            return response
        if attempt >= SERVER_ERROR_MAX_RETRIES:
            response.raise_for_status()
        logger.warning(
            "LLM request for minion %s returned %d; backing off %d seconds before retry %d/%d.",
            minion,
            response.status_code,
            SERVER_ERROR_BACKOFF_SECONDS,
            attempt + 1,
            SERVER_ERROR_MAX_RETRIES,
        )
        time.sleep(SERVER_ERROR_BACKOFF_SECONDS)
    response.raise_for_status()
    return response


def _compact_history(
    client: httpx.Client,
    messages: list[dict[str, Any]],
    headers: dict[str, str],
    llm_cfg: LLMConfig,
    minion: str,
) -> list[dict[str, Any]]:
    tail_start = max(COMPACTION_KEEP_HEAD, len(messages) - COMPACTION_KEEP_TAIL)
    while tail_start < len(messages) and messages[tail_start].get("role") == "tool":
        tail_start += 1
    if tail_start <= COMPACTION_KEEP_HEAD or tail_start >= len(messages):
        return messages

    summarization_request = list(messages[:tail_start]) + [
        {
            "role": "user",
            "content": (
                "Summarize the security investigation so far in concise prose. Cover: "
                "tools called and what they returned, files/paths inspected, hypotheses "
                "confirmed or ruled out, suspected findings with their evidence, and what "
                "still needs to be checked. Do not call any tools — respond with plain "
                "text only."
            ),
        }
    ]

    before_chars = len(json.dumps(messages))
    before_count = len(messages)

    response = _post_with_retry(
        client,
        f"{llm_cfg.url}/chat/completions",
        headers,
        {
            "model": llm_cfg.model,
            "messages": summarization_request,
        },
        minion,
    )
    summary = (response.json()["choices"][0]["message"].get("content") or "").strip()
    if not summary:
        raise RuntimeError(f"Compaction returned empty summary for minion {minion}")

    compacted = (
        list(messages[:COMPACTION_KEEP_HEAD])
        + [
            {
                "role": "user",
                "content": (
                    "# Investigation So Far (Compacted)\n\n"
                    f"{summary}\n\n"
                    "Continue with tool calls and finish by calling `create_report`."
                ),
            }
        ]
        + list(messages[tail_start:])
    )

    after_chars = len(json.dumps(compacted))
    logger.info(
        "Compacted history for minion %s: %d -> %d chars, %d -> %d messages.",
        minion,
        before_chars,
        after_chars,
        before_count,
        len(compacted),
    )
    return compacted


TOOL_DEFINITIONS = [
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
            "description": "Return the last 20 login records on the minion (output of `last -n 20`).",
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


def _call_tool(
    name: str,
    arguments: dict[str, Any],
    minion: str,
    salt_cfg: SaltConfig,
    smtp_cfg: SmtpConfig | None,
) -> str:
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
    if name == "create_report":
        return create_report(
            minion=minion,
            summary=arguments.get("summary", ""),
            overall_risk=arguments.get("overall_risk", ""),
            findings=arguments.get("findings"),
        )
    if name == "send_alert":
        return send_alert(
            minion=minion,
            severity=arguments["severity"],
            title=arguments["title"],
            details=arguments["details"],
            smtp_cfg=smtp_cfg,
        )
    return f"Unknown tool: {name}"


def _resolve_for_minion(default_dir: Path, minion: str) -> Path:
    exact = default_dir / f"{minion}.md"
    if exact.is_file():
        logger.info("Using per-minion file %s", exact)
        return exact

    matches: list[Path] = []
    for entry in default_dir.glob("*.md"):
        stem = entry.stem
        if "_" not in stem:
            continue
        pattern = stem.replace("_", "*")
        if fnmatch.fnmatchcase(minion, pattern):
            matches.append(entry)

    if matches:
        best = max(matches, key=lambda p: len(p.stem))
        logger.info("Using glob-matched file %s for minion %s", best, minion)
        return best

    return default_dir / "default.md"


def run_agent(
    minion: str,
    processes: str,
    llm_cfg: LLMConfig,
    salt_cfg: SaltConfig,
    smtp_cfg: SmtpConfig | None = None,
) -> str:
    threat_model_path = _resolve_for_minion(llm_cfg.threat_model_path, minion)
    task_path = _resolve_for_minion(llm_cfg.task_path, minion)
    threat_model = threat_model_path.read_text(encoding="utf-8")
    task = task_path.read_text(encoding="utf-8")

    now = datetime.now(timezone.utc)
    system_prompt = (
        f"# Current Date and Time\n\n"
        f"{now.strftime('%Y-%m-%d %H:%M:%S %Z')} (current date: {now.strftime('%Y-%m-%d')})\n\n"
        f"# Threat Model\n\n{threat_model}\n\n"
        "# Output Requirement\n\n"
        "After completing your investigation using the available tools, you MUST call the "
        "`create_report` tool exactly once with structured findings (summary, overall_risk, "
        "and a list of findings — each with title, severity, evidence, risk, recommendation). "
        "Do not write the report as a free-form message; it is rendered from the fields you "
        "pass to `create_report`. Do not stop without calling this tool."
    )
    user_message = (
        f"# Task\n\n{task}\n\n"
        f"# Target Minion\n\n{minion}\n\n"
        f"# Currently Running Host Processes (container processes excluded)\n\n```\n{processes}\n```"
    )

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    headers = {
        "Authorization": f"Bearer {llm_cfg.access_token}",
        "Content-Type": "application/json",
    }

    report: str | None = None
    char_budget = llm_cfg.context_char_budget
    compaction_soft_limit = int(char_budget * COMPACTION_THRESHOLD)
    last_compacted_msg_count: int | None = None

    with httpx.Client(timeout=llm_cfg.request_timeout_seconds) as client:
        iterations_used = 0
        for iteration in range(MAX_ITERATIONS):
            iterations_used = iteration + 1
            context_chars = len(json.dumps(messages))
            if context_chars > char_budget:
                logger.warning(
                    "Context budget exceeded for minion %s (%d chars > %d); forcing report.",
                    minion,
                    context_chars,
                    char_budget,
                )
                break
            if (
                context_chars > compaction_soft_limit
                and len(messages) > COMPACTION_KEEP_HEAD + COMPACTION_KEEP_TAIL
                and (last_compacted_msg_count is None or len(messages) > last_compacted_msg_count)
            ):
                logger.info(
                    "Context at %d/%d chars (>%d%% of budget); compacting history for minion %s.",
                    context_chars,
                    char_budget,
                    int(COMPACTION_THRESHOLD * 100),
                    minion,
                )
                messages = _compact_history(client, messages, headers, llm_cfg, minion)
                last_compacted_msg_count = len(messages)
            response = _post_with_retry(
                client,
                f"{llm_cfg.url}/chat/completions",
                headers,
                {
                    "model": llm_cfg.model,
                    "messages": messages,
                    "tools": TOOL_DEFINITIONS,
                    "tool_choice": "auto",
                },
                minion,
            )
            choice = response.json()["choices"][0]
            message = choice["message"]
            messages.append(message)

            if choice["finish_reason"] != "tool_calls":
                break

            for tool_call in message.get("tool_calls", []):
                fn = tool_call["function"]
                name = fn["name"]
                arguments = json.loads(fn.get("arguments", "{}"))
                logger.debug("Tool call: %s(%s)", name, arguments)

                try:
                    result = _call_tool(name, arguments, minion, salt_cfg, smtp_cfg)
                except Exception as exc:
                    result = f"ERROR: {exc}"

                if name == "create_report":
                    report = result
                    tool_content = "Report recorded. End your turn now."
                else:
                    tool_content = result

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "content": tool_content,
                    }
                )

            if report is not None:
                break
        else:
            logger.warning("Agent reached max iterations (%d) for minion %s.", MAX_ITERATIONS, minion)

        if report is not None:
            logger.info("Report received via create_report after %d iteration(s).", iterations_used)
            return report

        logger.warning(
            "Agent did not call create_report after %d iteration(s); forcing a final call.",
            iterations_used,
        )
        messages.append({
            "role": "user",
            "content": (
                "Your investigation is complete. Call the `create_report` tool now with the "
                "structured findings. Do not respond with text — only call the tool."
            ),
        })
        forced_response = _post_with_retry(
            client,
            f"{llm_cfg.url}/chat/completions",
            headers,
            {
                "model": llm_cfg.model,
                "messages": messages,
                "tools": TOOL_DEFINITIONS,
                "tool_choice": {"type": "function", "function": {"name": "create_report"}},
            },
            minion,
        )
        forced_message = forced_response.json()["choices"][0]["message"]
        for tool_call in forced_message.get("tool_calls") or []:
            if tool_call["function"]["name"] != "create_report":
                continue
            try:
                arguments = json.loads(tool_call["function"].get("arguments", "{}"))
            except json.JSONDecodeError:
                continue
            return create_report(
                minion=minion,
                summary=arguments.get("summary", ""),
                overall_risk=arguments.get("overall_risk", ""),
                findings=arguments.get("findings"),
            )

        logger.error("Agent failed to produce a report for minion %s.", minion)
        return ""
