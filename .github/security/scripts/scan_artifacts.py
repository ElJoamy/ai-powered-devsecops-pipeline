"""Strict, scanner-isolated collection artifacts for staged assessments."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
import stat
from pathlib import Path
from typing import Any

from artifact_manifest import create_manifest, digest, verify_manifest
from common import read_json, redact, write_json
from configuration import resolve_scan_types
from normalizer import validate_scans

Json = dict[str, Any]
KINDS = {"sast": ("snyk-sast", "SAST"), "dependencies": ("trivy-sca", "SCA"),
         "iac": ("trivy-iac", "IaC")}
METADATA = {"metadata/execution.json", "metadata/project-inventory.json",
            "metadata/scanners.json", "metadata/collection.json"}


def scanner_records(selected: set[str], reason: str = "") -> list[Json]:
    """Create explicit failures for selected kinds and skips for all others."""
    return [{"scanner": scanner, "type": category,
             "status": "FAILED" if kind in selected else "SKIPPED",
             "reason": reason if kind in selected else "Not selected in scan.types",
             "version": None, "exit_code": None, "json_path": None, "sarif_path": None}
            for kind, (scanner, category) in KINDS.items()]


def configuration_digest(config: Json) -> str:
    effective = copy.deepcopy(config)
    effective["scan"].pop("types")
    encoded = json.dumps(effective, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _attempt(value: Any) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value):
        raise ValueError("Run attempt must be a positive decimal string")
    return int(value)


def collection_identity(metadata: Json, config: Json, policy: Path,
                        baseline: Path | None) -> Json:
    identity = {key: metadata[key] for key in
                ("repository", "commit_sha", "run_id", "run_attempt", "engine_ref")}
    if not isinstance(identity["repository"], str) or not re.fullmatch(
            r"[^/\s]+/[^/\s]+", identity["repository"]):
        raise ValueError("Collection requires a GitHub repository identity")
    for key in ("commit_sha", "engine_ref"):
        if not isinstance(identity[key], str) or not re.fullmatch(
                r"(?:[a-f0-9]{40}|[a-f0-9]{64})", identity[key]):
            raise ValueError(f"Collection requires a resolved commit for {key}")
    _attempt(identity["run_id"])
    _attempt(identity["run_attempt"])
    identity.update(config_sha256=configuration_digest(config),
                    policy_sha256=digest(policy),
                    baseline_sha256=digest(baseline) if baseline else None)
    return identity


def write_collection(output: Path, metadata: Json, project: Json, scans: list[Json],
                     selected: set[str], identity: Json | None,
                     errors: list[str]) -> int:
    write_json(output / "metadata" / "execution.json", metadata)
    write_json(output / "metadata" / "project-inventory.json", project)
    write_json(output / "metadata" / "scanners.json", scans)
    failed = bool(errors) or any(row["status"] == "FAILED" for row in scans)
    write_json(output / "metadata" / "collection.json", {
        "schema_version": "1.0", "stage": "collection",
        "selection": [kind for kind in KINDS if kind in selected],
        "identity": identity, "status": "FAILED" if failed else "COMPLETED",
        "errors": errors,
    })
    create_manifest(output)
    verify_manifest(output)
    return 2 if failed else 0


def _allowed_files(scanner: str) -> set[str]:
    return METADATA | {"manifest.json"} | {
        f"raw/{scanner}.{suffix}" for suffix in ("json", "sarif")
    } | {f"logs/{scanner}-{name}.log" for name in ("json", "sarif", "version")}


def _tree(root: Path, scanner: str) -> set[str]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Worker directory is missing or is a symlink")
    actual = set()
    allowed = _allowed_files(scanner)
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode) and relative in {"raw", "logs", "metadata"}:
            continue
        if not stat.S_ISREG(mode) or relative not in allowed:
            raise ValueError(f"Unexpected or unsafe worker path: {relative}")
        actual.add(relative)
    if not (METADATA | {"manifest.json"}) <= actual:
        raise ValueError("Worker metadata or manifest is missing")
    return actual


def _manifest(root: Path, actual: set[str]) -> None:
    manifest = read_json(root / "manifest.json")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "1.0":
        raise ValueError("Invalid worker manifest schema")
    if manifest.get("algorithm") != "SHA-256" or not isinstance(manifest.get("files"), list):
        raise ValueError("Invalid worker manifest algorithm or inventory")
    seen = set()
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "bytes"}:
            raise ValueError("Invalid worker manifest entry")
        name = entry["path"]
        if not isinstance(name, str) or name not in actual - {"manifest.json"} or name in seen:
            raise ValueError("Unexpected or duplicate worker manifest path")
        if type(entry["bytes"]) is not int or entry["bytes"] != (root / name).stat().st_size:
            raise ValueError(f"Worker manifest size mismatch: {name}")
        if not isinstance(entry["sha256"], str) or not re.fullmatch(
                r"[a-f0-9]{64}", entry["sha256"]):
            raise ValueError("Invalid worker manifest digest")
        seen.add(name)
    if seen != actual - {"manifest.json"}:
        raise ValueError("Worker manifest inventory mismatch")
    verify_manifest(root)


def _identity(collection: Json, expected: Json, execution: Any) -> None:
    identity = collection.get("identity")
    if not isinstance(identity, dict) or set(identity) != set(expected):
        raise ValueError("Worker collection identity is missing or malformed")
    for key, value in expected.items():
        if key != "run_attempt" and identity[key] != value:
            raise ValueError(f"Worker collection identity mismatch: {key}")
    if _attempt(identity["run_attempt"]) > _attempt(expected["run_attempt"]):
        raise ValueError("Worker collection is from a future run attempt")
    if not isinstance(execution, dict) or any(
        execution.get(key) != identity[key] for key in
        ("repository", "commit_sha", "run_id", "run_attempt", "engine_ref")
    ):
        raise ValueError("Worker execution metadata disagrees with collection identity")


def _collection(root: Path, kind: str, expected: Json) -> Json:
    collection = read_json(root / "metadata" / "collection.json")
    if not isinstance(collection, dict) or collection.get("schema_version") != "1.0":
        raise ValueError("Invalid worker collection schema")
    if collection.get("stage") != "collection" or collection.get("selection") != [kind]:
        raise ValueError("Worker collection has wrong stage or selection")
    if collection.get("status") not in {"COMPLETED", "FAILED"}:
        raise ValueError("Invalid worker collection status")
    errors = collection.get("errors")
    if not isinstance(errors, list) or any(not isinstance(error, str) for error in errors):
        raise ValueError("Invalid worker collection diagnostics")
    execution = read_json(root / "metadata" / "execution.json")
    _identity(collection, expected, execution)
    if resolve_scan_types(execution.get("scan_types")) != {kind}:
        raise ValueError("Worker execution selection disagrees with collection selection")
    project = read_json(root / "metadata" / "project-inventory.json")
    if not isinstance(project, dict) or project.get("status") == "FAILED":
        raise ValueError(f"Worker inventory is invalid or failed: {'; '.join(errors)}")
    return collection


def _records(root: Path, kind: str, actual: set[str]) -> Json:
    records = validate_scans(read_json(root / "metadata" / "scanners.json"))
    if {row["scanner"] for row in records} != {value[0] for value in KINDS.values()}:
        raise ValueError("Worker must contain exactly the three known scanner rows")
    scanner = KINDS[kind][0]
    for row in records:
        if not isinstance(row.get("reason"), str):
            raise ValueError("Worker scanner reason must be a string")
        if row["scanner"] != scanner and (
                row["status"] != "SKIPPED" or row["json_path"] or row["sarif_path"]):
            raise ValueError("Worker contains evidence for an unselected scanner")
        for field, suffix in (("json_path", "json"), ("sarif_path", "sarif")):
            relative = row[field]
            canonical = f"raw/{scanner}.{suffix}"
            if relative is not None and (relative != canonical or canonical not in actual):
                raise ValueError(f"Unexpected or missing worker {field}")
        if row["scanner"] == scanner and row["status"] == "COMPLETED" and (
                not row["json_path"] or not row["sarif_path"]):
            raise ValueError("Completed worker must provide both native report paths")
    return next(row for row in records if row["scanner"] == scanner)


def _worker(root: Path, output: Path, kind: str, expected: Json) -> tuple[Json, list[str]]:
    scanner = KINDS[kind][0]
    actual = _tree(root, scanner)
    _manifest(root, actual)
    collection = _collection(root, kind, expected)
    row = _records(root, kind, actual)
    failed = bool(collection["errors"]) or row["status"] == "FAILED"
    if (collection["status"] == "FAILED") != failed:
        raise ValueError("Worker collection status disagrees with scanner diagnostics")
    diagnostics = list(collection["errors"])
    if collection["status"] == "FAILED":
        diagnostics.append(f"{scanner}: {row['reason'] or 'Worker collection failed'}")
        if row["status"] != "FAILED":
            row = dict(row, status="FAILED", reason="; ".join(diagnostics))
    for relative in sorted(actual):
        if relative.startswith(("raw/", "logs/")):
            destination = output / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with (root / relative).open("rb") as source, destination.open("xb") as target:
                shutil.copyfileobj(source, target)
    return row, diagnostics


def merge_collections(artifacts: Path, output: Path, selected: set[str],
                      identity: Json) -> tuple[list[Json], list[str]]:
    """Keep good workers when any selected worker is missing, invalid or failed."""
    records = scanner_records(selected)
    errors = []
    for kind, row in zip(KINDS, records):
        if kind not in selected:
            continue
        try:
            if artifacts.is_symlink() or not artifacts.is_dir():
                raise ValueError("Artifact download directory is missing or unsafe")
            worker = artifacts / f"security-scan-{kind}"
            if worker.is_symlink():
                raise ValueError("Worker directory must not be a symlink")
            if output == worker.resolve() or output.is_relative_to(worker.resolve()):
                raise ValueError("Aggregate output cannot be inside a worker artifact")
            merged, diagnostics = _worker(worker, output, kind, identity)
            row.update(merged)
            errors.extend(redact(message) for message in diagnostics)
        except (ValueError, KeyError, TypeError, OSError, AttributeError) as error:
            reason = redact(f"{row['scanner']} collection rejected: {error}")
            row.update(status="FAILED", reason=reason, json_path=None, sarif_path=None)
            errors.append(reason)
    return records, errors
