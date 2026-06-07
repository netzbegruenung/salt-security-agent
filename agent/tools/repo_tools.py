from __future__ import annotations

import os
from pathlib import Path


def _safe_resolve(repo_path: Path, rel_path: str) -> Path:
    """Resolve rel_path under repo_path and raise if it escapes the root."""
    resolved = (repo_path / rel_path).resolve()
    if not resolved.is_relative_to(repo_path.resolve()):
        raise ValueError(f"Path traversal attempt: {rel_path!r}")
    return resolved


def list_repo_files(repo_path: Path, rel_path: str = "") -> list[str]:
    """List files and directories at rel_path inside the Salt repo."""
    target = _safe_resolve(repo_path, rel_path) if rel_path else repo_path.resolve()
    if not target.is_dir():
        raise ValueError(f"{rel_path!r} is not a directory in the Salt repo")
    entries = []
    for entry in sorted(os.scandir(target), key=lambda e: (e.is_file(), e.name)):
        suffix = "/" if entry.is_dir() else ""
        entries.append(entry.name + suffix)
    return entries


def read_repo_file(repo_path: Path, rel_path: str) -> str:
    """Read a file from the Salt repo by relative path."""
    target = _safe_resolve(repo_path, rel_path)
    if not target.is_file():
        raise ValueError(f"{rel_path!r} is not a file in the Salt repo")
    return target.read_text(encoding="utf-8", errors="replace")
