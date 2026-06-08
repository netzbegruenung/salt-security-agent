from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

VALID_FINDING_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_OVERALL_RISK = {"none", "low", "medium", "high", "critical"}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _normalize(value: Any, valid: set[str], default: str) -> str:
    if not isinstance(value, str):
        return default
    v = value.lower().strip()
    return v if v in valid else default


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def create_report(
    minion: str,
    summary: str,
    overall_risk: str,
    findings: list[dict[str, Any]] | None,
) -> str:
    """Render the agent's structured findings into a consistent Markdown report."""
    summary_text = _as_text(summary) or "(no summary provided)"
    overall = _normalize(overall_risk, VALID_OVERALL_RISK, "medium")

    rendered: list[dict[str, str]] = []
    for raw in findings or []:
        if not isinstance(raw, dict):
            continue
        rendered.append({
            "title": _as_text(raw.get("title")) or "(untitled)",
            "severity": _normalize(raw.get("severity"), VALID_FINDING_SEVERITIES, "info"),
            "evidence": _as_text(raw.get("evidence")) or "(none)",
            "risk": _as_text(raw.get("risk")) or "(none)",
            "recommendation": _as_text(raw.get("recommendation")) or "(none)",
        })
    rendered.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99))

    lines: list[str] = [
        f"# Security Scan Report: {minion}",
        "",
        f"**Overall risk:** {overall.upper()}",
        "",
        "## Summary",
        "",
        summary_text,
        "",
        "## Findings",
        "",
    ]
    if not rendered:
        lines.append("No findings.")
    else:
        for idx, finding in enumerate(rendered, 1):
            lines.extend([
                f"### {idx}. {finding['title']} ({finding['severity'].upper()})",
                "",
                "- **Evidence:** {finding['evidence']}",
                "- **Risk:** {finding['risk']}",
                "- **Recommendation: ** {finding['recommendation']}",
                "",
            ])
    return "\n".join(lines).rstrip() + "\n"
