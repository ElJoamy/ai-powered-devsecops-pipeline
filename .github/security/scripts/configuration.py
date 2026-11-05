"""Strict configuration loading and repository-confined scan scope."""

from __future__ import annotations

import copy
import math
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

Json = dict[str, Any]
CONFIG_ROOT = Path(__file__).resolve().parents[1] / "config"
MANDATORY_EXCLUDES = [".git", ".venv", "node_modules", "__pycache__", "reports"]
ENUMS = {
    "environment": {"UNKNOWN", "DEVELOPMENT", "DEV", "TEST", "STAGING", "PRODUCTION", "PROD"},
    "business_criticality": {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"},
    "data_sensitivity": {"UNKNOWN", "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"},
}


class _UniqueLoader(yaml.SafeLoader):
    """Reject duplicate keys rather than silently overriding security controls."""


def _mapping(loader: _UniqueLoader, node: yaml.MappingNode) -> Json:
    result: Json = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ValueError("Configuration keys must be unique strings")
        result[key] = loader.construct_object(value_node)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _yaml(path: Path) -> Json:
    if path.stat().st_size > 1_000_000:
        raise ValueError("Configuration exceeds 1 MB")
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueLoader)
    except (yaml.YAMLError, RecursionError) as exc:
        raise ValueError("Invalid configuration YAML") from exc
    if not isinstance(value, dict):
        raise ValueError("Configuration must be a mapping")
    return value


def _merge(base: Json, override: Json, location: str = "") -> Json:
    result = copy.deepcopy(base)
    for key, value in override.items():
        name = f"{location}.{key}".strip(".")
        if key not in base:
            raise ValueError(f"Unknown configuration key: {name}")
        if isinstance(base[key], dict):
            if not isinstance(value, dict):
                raise ValueError(f"{name} must be a mapping")
            result[key] = _merge(base[key], value, name)
        else:
            result[key] = value
    return result


def confined_path(repo: Path, value: str, *, must_exist: bool = True) -> Path:
    """Resolve a user path without accepting absolute paths or symlink escapes."""
    relative = PurePosixPath(value)
    if not value or relative.is_absolute() or ".." in relative.parts or "\\" in value:
        raise ValueError(f"Path must be repository-relative: {value!r}")
    path = (repo.resolve() / value).resolve()
    if not path.is_relative_to(repo.resolve()):
        raise ValueError(f"Path escapes repository: {value!r}")
    if must_exist and not path.exists():
        raise ValueError(f"Path does not exist: {value!r}")
    return path


def _strings(value: Any, name: str, *, empty: bool = True) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ValueError(f"{name} must be a list of nonempty strings")
    if not empty and not value:
        raise ValueError(f"{name} cannot be empty")
    return value


def _boolean(value: Any, name: str) -> None:
    if type(value) is not bool:
        raise ValueError(f"{name} must be boolean")


def _number(value: Any, name: str, minimum: float, maximum: float) -> None:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")


def _application(app: Json) -> None:
    if app["name"] is not None and (
        not isinstance(app["name"], str) or not app["name"].strip()
    ):
        raise ValueError("application.name must be null or a nonempty string")
    for key, choices in ENUMS.items():
        if not isinstance(app[key], str) or app[key] not in choices:
            raise ValueError(f"application.{key} must be one of {sorted(choices)}")
    if app["internet_exposed"] is not None:
        _boolean(app["internet_exposed"], "application.internet_exposed")
    _strings(app["compensating_controls"], "application.compensating_controls")


def resolve_scan_types(value: str) -> set[str]:
    """Resolve the seven nonempty combinations through one authoritative parser."""
    allowed = {"sast", "iac", "dependencies"}
    if not isinstance(value, str):
        raise ValueError("scan.types must be all or a comma-separated scan selection")
    if value.strip().lower() == "all":
        return allowed
    requested = [item.strip().lower() for item in value.split(",")]
    if (not requested or any(item not in allowed for item in requested)
            or len(requested) != len(set(requested))):
        raise ValueError("Select all, sast, iac, dependencies, or a nonrepeating combination")
    return set(requested)


def _scan(scan: Json, repo: Path) -> None:
    resolve_scan_types(scan["types"])
    for value in _strings(scan["paths"], "scan.paths", empty=False):
        confined_path(repo, value)
    for value in _strings(scan["exclude"], "scan.exclude"):
        relative = PurePosixPath(value)
        if (relative.is_absolute() or ".." in relative.parts or "\\" in value
                or value == "." or value.startswith("!")
                or any(ord(char) < 32 for char in value)):
            raise ValueError("Excludes must be relative globs without traversal or negation")
    if type(scan["timeout_seconds"]) is not int:
        raise ValueError("scan.timeout_seconds must be an integer")
    _number(scan["timeout_seconds"], "scan.timeout_seconds", 1, 86400)
    org = scan["snyk_org"]
    if org is not None and (
        not isinstance(org, str) or not org.strip() or org.startswith("-")
        or any(ord(char) < 32 for char in org)
    ):
        raise ValueError("scan.snyk_org must be null or a nonempty organization ID")
    scan["exclude"] = list(dict.fromkeys(MANDATORY_EXCLUDES + scan["exclude"]))


def _remaining(config: Json) -> None:
    intel, gate = config["intelligence"], config["gate"]
    _boolean(intel["enabled"], "intelligence.enabled")
    _number(intel["timeout_seconds"], "intelligence.timeout_seconds", 1, 300)
    _number(intel["cache_hours"], "intelligence.cache_hours", 0, 8760)
    _boolean(gate["fail_on_scanner_error"], "gate.fail_on_scanner_error")
    allowed = {"P0", "P1", "P2", "P3", "REVIEW"}
    fail_on = gate["fail_on"]
    if fail_on is not None:
        if not isinstance(fail_on, str) or fail_on not in allowed:
            raise ValueError("gate.fail_on must be null or P0/P1/P2/P3/REVIEW")


def _risk_defaults() -> Json:
    policy = _yaml(CONFIG_ROOT / "risk-policy.yaml")
    expected = {"version", "epss_high", "critical_cvss", "high_cvss", "rules"}
    if set(policy) != expected or type(policy["version"]) is not int or policy["version"] != 1:
        raise ValueError("Unsupported default risk policy")
    _number(policy["epss_high"], "epss_high", 0, 1)
    for key in ("critical_cvss", "high_cvss"):
        _number(policy[key], key, 0, 10)
    if policy["high_cvss"] > policy["critical_cvss"]:
        raise ValueError("high_cvss must not exceed critical_cvss")
    names = {"kev_priority", "critical_priority", "high_priority",
             "medium_priority", "low_priority", "unknown_priority"}
    rules = policy["rules"]
    if not isinstance(rules, dict) or set(rules) != names:
        raise ValueError("Invalid default risk rules")
    if any(not isinstance(v, str) or v not in {"P0", "P1", "P2", "P3", "REVIEW"}
           for v in rules.values()):
        raise ValueError("Invalid default risk priority")
    return policy


def validate_config(config: Json, repo: Path) -> Json:
    """Revalidate CLI overrides; return an independent canonical configuration."""
    validated = _merge(_yaml(CONFIG_ROOT / "default.yaml"), config)
    _application(validated["application"])
    _scan(validated["scan"], repo.resolve(strict=True))
    _remaining(validated)
    return validated


def load_config(config_path: Path | None, repo: Path) -> Json:
    """Merge a repository-local override with validated bundled defaults.

    The default risk policy is validated here; custom policy handling belongs to
    the risk/orchestration layer. Exclusions use repository-relative globs.
    """
    repo = repo.resolve(strict=True)
    if not repo.is_dir():
        raise ValueError("Repository must be a directory")
    defaults = _yaml(CONFIG_ROOT / "default.yaml")
    override: Json = {}
    if config_path is not None:
        candidate = config_path if config_path.is_absolute() else repo / config_path
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(repo):
            raise ValueError("Configuration path escapes repository")
        override = _yaml(resolved)
    config = _merge(defaults, override)
    _risk_defaults()
    return validate_config(config, repo)
