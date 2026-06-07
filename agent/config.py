from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ScanningConfig:
    parallel_hosts: int
    tasks_per_hour: int


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
class Config:
    scanning: ScanningConfig
    llm: LLMConfig
    salt: SaltConfig
    celery: CeleryConfig


def load_config(path: str | Path = "config.toml") -> Config:
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    s = raw["scanning"]
    l = raw["llm"]
    salt = raw["salt"]
    c = raw["celery"]

    return Config(
        scanning=ScanningConfig(
            parallel_hosts=s["parallel_hosts"],
            tasks_per_hour=s["tasks_per_hour"],
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
    )
