"""Intentionally unsafe educational fixture. No files are read on import."""

from pathlib import Path


def vulnerable_file_read(base_directory: str, user_path: str) -> str:
    """CWE-22: no containment checks for traversal or absolute user paths."""
    return (Path(base_directory) / user_path).read_text(encoding="utf-8")
