from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx

from agent.config import LLMConfig, SaltConfig
from agent.tools.repo_tools import list_repo_files, read_repo_file
from agent.tools.salt_tools import ls_minion

logger = logging.getLogger(__name__)

MAX_ITERATIONS = 10

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
]


def _call_tool(
    name: str,
    arguments: dict[str, Any],
    minion: str,
    salt_cfg: SaltConfig,
) -> str:
    if name == "ls_minion":
        return ls_minion(minion, arguments["path"])
    if name == "list_repo_files":
        entries = list_repo_files(salt_cfg.repo_path, arguments.get("rel_path", ""))
        return "\n".join(entries)
    if name == "read_repo_file":
        return read_repo_file(salt_cfg.repo_path, arguments["rel_path"])
    return f"Unknown tool: {name}"


def run_agent(
    minion: str,
    processes: str,
    llm_cfg: LLMConfig,
    salt_cfg: SaltConfig,
) -> str:
    threat_model = Path(llm_cfg.threat_model_path).read_text(encoding="utf-8")
    task = Path(llm_cfg.task_path).read_text(encoding="utf-8")

    system_prompt = (
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

    with httpx.Client(timeout=120) as client:
        for iteration in range(MAX_ITERATIONS):
            payload = {
                "model": llm_cfg.model,
                "messages": messages,
                "tools": TOOL_DEFINITIONS,
                "tool_choice": "auto",
            }

            response = client.post(
                f"{llm_cfg.url}/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

            choice = data["choices"][0]
            message = choice["message"]
            messages.append(message)

            if choice["finish_reason"] != "tool_calls":
                content = message.get("content") or ""
                if content:
                    logger.info("Agent finished after %d iteration(s).", iteration + 1)
                    return content
                # Model stopped without writing a report — explicitly request it.
                logger.warning("Model returned empty content; requesting final report.")
                messages.append({"role": "user", "content": "Investigation complete. Write your full findings report now."})
                final_response = client.post(
                    f"{llm_cfg.url}/chat/completions",
                    headers=headers,
                    json={"model": llm_cfg.model, "messages": messages, "tool_choice": "none"},
                )
                final_response.raise_for_status()
                final_content = final_response.json()["choices"][0]["message"].get("content") or ""
                logger.info("Agent finished after %d iteration(s) (+ recovery call).", iteration + 1)
                return final_content

            for tool_call in message.get("tool_calls", []):
                fn = tool_call["function"]
                name = fn["name"]
                arguments = json.loads(fn.get("arguments", "{}"))
                logger.debug("Tool call: %s(%s)", name, arguments)

                try:
                    result = _call_tool(name, arguments, minion, salt_cfg)
                except Exception as exc:
                    result = f"ERROR: {exc}"

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "content": result,
                    }
                )

    logger.warning("Agent reached max iterations (%d) for minion %s.", MAX_ITERATIONS, minion)
    return "Max iterations reached without a final response."
