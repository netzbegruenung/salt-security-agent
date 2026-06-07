from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

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
    use_tls: bool = True


@dataclass
class Config:
    scanning: ScanningConfig
    llm: LLMConfig
    salt: SaltConfig
    celery: CeleryConfig
    smtp: SmtpConfig | None = None


def load_config(path: str | Path = "config.toml") -> Config:
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
            use_tls=bool(smtp.get("use_tls", True)),
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
