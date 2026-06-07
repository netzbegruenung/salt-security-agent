from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from agent.config import LLMConfig, SaltConfig, SmtpConfig
from agent.tools.alert_tool import send_alert
from agent.tools.repo_tools import list_repo_files, read_repo_file
from agent.tools.salt_tools import ls_minion
from agent.tools.system_tools import (
    get_cron_jobs,
    get_failed_services,
    get_last_logins,
    get_listening_ports,
    get_os_info,
    get_running_services,
    get_salt_grains,
    get_suid_files,
    get_users,
)

logger = logging.getLogger(__name__)

MAX_ITERATIONS = 50

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
    if name == "list_repo_files":
        entries = list_repo_files(salt_cfg.repo_path, arguments.get("rel_path", ""))
        return "\n".join(entries)
    if name == "read_repo_file":
        return read_repo_file(salt_cfg.repo_path, arguments["rel_path"])
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
    if name == "send_alert":
        return send_alert(
            minion=minion,
            severity=arguments["severity"],
            title=arguments["title"],
            details=arguments["details"],
            smtp_cfg=smtp_cfg,
        )
    return f"Unknown tool: {name}"


def _resolve_for_minion(default_path: Path, minion: str) -> Path:
    candidate = Path(default_path).parent / f"{minion}.md"
    if candidate.is_file():
        logger.info("Using per-minion file %s", candidate)
        return candidate
    return Path(default_path / "default.md")


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
        "After completing your investigation using the available tools, you MUST produce a "
        "written Markdown report as your final response. The report must summarise every "
        "finding with evidence, risk assessment, and recommended remediation. "
        "Do not stop without writing this report."
    )
    user_message = (
        f"# Task\n\n{task}\n\n"
        f"# Target Minion\n\n{minion}\n\n"
        f"# Currently Running Processes\n\n```\n{processes}\n```"
    )

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    headers = {
        "Authorization": f"Bearer {llm_cfg.access_token}",
        "Content-Type": "application/json",
    }

    with httpx.Client(timeout=300) as client:
        iterations_used = 0
        for iteration in range(MAX_ITERATIONS):
            iterations_used = iteration + 1
            response = client.post(
                f"{llm_cfg.url}/chat/completions",
                headers=headers,
                json={
                    "model": llm_cfg.model,
                    "messages": messages,
                    "tools": TOOL_DEFINITIONS,
                    "tool_choice": "auto",
                },
            )
            response.raise_for_status()
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

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "content": result,
                    }
                )
        else:
            logger.warning("Agent reached max iterations (%d) for minion %s.", MAX_ITERATIONS, minion)

        logger.info("Tool loop ended after %d iteration(s); generating final report.", iterations_used)
        messages.append({
            "role": "user",
            "content": (
                "Your investigation is complete. Now write the final findings report in "
                "Markdown. Include every finding with evidence, risk, and recommendation. "
                "Respond with the report only — no preamble, no tool calls."
            ),
        })
        report_response = client.post(
            f"{llm_cfg.url}/chat/completions",
            headers=headers,
            json={"model": llm_cfg.model, "messages": messages},
        )
        report_response.raise_for_status()
        report = report_response.json()["choices"][0]["message"].get("content") or ""
        if not report:
            logger.error("Final report call returned empty content for minion %s.", minion)
        return report
