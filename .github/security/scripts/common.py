"""Shared JSON serialization and safe diagnostic handling for GitHub Actions."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

Json = dict[str, Any]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact(value: str) -> str:
    """Remove configured credentials and common authorization patterns from logs."""
    for key, secret in os.environ.items():
        if key.upper() == "SNYK_ORG":
            secret = secret.strip()
        if key.upper() == "SNYK_ORG" or any(
            word in key.upper() for word in ("TOKEN", "PASSWORD", "SECRET", "API_KEY")
        ):
            if len(secret) >= 4:
                value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"(?i)(Bearer\s+)[^\s\"']+", r"\1[REDACTED]", value)
    return re.sub(r"(https?://)[^/\s:@]+:[^@\s/]+@", r"\1[REDACTED]@", value)


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=True, indent=2, allow_nan=False) + "\n",
                    encoding="utf-8")


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8-sig") as stream:
        return json.load(stream)
