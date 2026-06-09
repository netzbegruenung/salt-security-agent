from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

CONFIG_PATH_ENV_VAR = "SALT_SECURITY_AGENT_CONFIG"
DEFAULT_CONFIG_PATH = "/etc/salt-security-agent/config.toml"

SCAN_PERIOD_SECONDS = {
    "hourly": 3_600,
    "daily": 86_400,
    "weekly": 604_800,
    "monthly": 2_592_000,
}


@dataclass
class ScanningConfig:
    parallel_hosts: int
    scan_period: str
    report_directory: Path | None = None

    @property
    def scan_period_seconds(self) -> int:
        return SCAN_PERIOD_SECONDS[self.scan_period]


@dataclass
class LLMConfig:
    url: str
    access_token: str
    model: str
    threat_model_path: Path
    task_path: Path
    context_window_tokens: int = 120_000
    context_char_multiplier: float = 3.0

    @property
    def context_char_budget(self) -> int:
        return int(self.context_window_tokens * self.context_char_multiplier)


@dataclass
class SaltConfig:
    repo_path: Path


@dataclass
class CeleryConfig:
    broker_url: str
    result_backend: str


@dataclass
class SmtpConfig:
    host: str
    port: int
    username: str
    password: str
    from_address: str
    to_address: str
    use_starttls: bool = True


@dataclass
class Config:
    scanning: ScanningConfig
    llm: LLMConfig
    salt: SaltConfig
    celery: CeleryConfig
    smtp: SmtpConfig | None = None


def load_config(path: str | Path | None = None) -> Config:
    if path is None:
        path = os.environ.get(CONFIG_PATH_ENV_VAR, DEFAULT_CONFIG_PATH)
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    s = raw["scanning"]
    l = raw["llm"]
    salt = raw["salt"]
    c = raw["celery"]

    scan_period = s["scan_period"]
    if scan_period not in SCAN_PERIOD_SECONDS:
        raise ValueError(
            f"scanning.scan_period must be one of {sorted(SCAN_PERIOD_SECONDS)}, "
            f"got {scan_period!r}"
        )

    smtp_cfg: SmtpConfig | None = None
    if "smtp" in raw:
        smtp = raw["smtp"]
        smtp_cfg = SmtpConfig(
            host=smtp["host"],
            port=int(smtp["port"]),
            username=smtp["username"],
            password=smtp["password"],
            from_address=smtp["from_address"],
            to_address=smtp["to_address"],
            use_starttls=bool(smtp.get("use_starttls", True)),
        )

    report_directory = s.get("report_directory")
    return Config(
        scanning=ScanningConfig(
            parallel_hosts=s["parallel_hosts"],
            scan_period=scan_period,
            report_directory=Path(report_directory) if report_directory else None,
        ),
        llm=LLMConfig(
            url=l["url"].rstrip("/"),
            access_token=l["access_token"],
            model=l["model"],
            threat_model_path=Path(l["threat_model_path"]),
            task_path=Path(l["task_path"]),
            context_window_tokens=int(l.get("context_window_tokens", 120_000)),
            context_char_multiplier=float(l.get("context_char_multiplier", 3.0)),
        ),
        salt=SaltConfig(
            repo_path=Path(salt["repo_path"]),
        ),
        celery=CeleryConfig(
            broker_url=c["broker_url"],
            result_backend=c["result_backend"],
        ),
        smtp=smtp_cfg,
    )
