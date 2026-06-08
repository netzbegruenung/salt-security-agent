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


def grep_repo(
    repo_path: Path,
    pattern: str,
    rel_path: str = "",
    max_results: int = 50,
) -> str:
    """Recursively grep for pattern in the Salt repo.
    
    Args:
        repo_path: Root of the Salt repository
        pattern: Text pattern to search for (case-insensitive)
        rel_path: Optional subdirectory to search within
        max_results: Maximum number of matches to return
        
    Returns:
        Formatted string with match snippets: file:line:content
    """
    repo_root = repo_path.resolve()
    start_dir = _safe_resolve(repo_root, rel_path) if rel_path else repo_root
    
    if not start_dir.is_dir():
        raise ValueError(f"{rel_path!r} is not a directory in the Salt repo")
    
    # Directories to exclude
    exclude_dirs = {
        ".git", "__pycache__", "node_modules", ".tox", ".eggs",
        "*.egg-info", "build", "dist", ".pytest_cache", ".mypy_cache"
    }
    
    matches = []
    
    for root, dirs, files in os.walk(start_dir):
        # Filter out excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            # Skip binary files and common non-text files
            if file.endswith((".pyc", ".so", ".bin", ".gz", ".zip", ".tar", ".jpg", ".png", ".gif", ".pdf")):
                continue
            
            file_path = Path(root) / file
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()
                
                for line_num, line in enumerate(lines, start=1):
                    if pattern.lower() in line.lower():
                        rel_file = file_path.relative_to(repo_root)
                        matches.append(f"{rel_file}:{line_num}:{line.rstrip()}")
                        
                        if len(matches) >= max_results:
                            break
                if len(matches) >= max_results:
                    break
            except (UnicodeDecodeError, IOError):
                # Skip files that can't be read as text
                continue
        
        if len(matches) >= max_results:
            break
    
    if not matches:
        return f"No matches found for pattern {pattern!r}"
    
    result = [f"Found {len(matches)} match(es) for pattern {pattern!r}:"]
    result.extend(matches)
    if len(matches) >= max_results:
        result.append(f"... and more (limited to {max_results} results)")
    
    return "\n".join(result)
