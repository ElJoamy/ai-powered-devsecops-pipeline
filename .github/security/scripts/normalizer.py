"""Canonical normalization, conservative identities, and schema validation."""

from __future__ import annotations

import hashlib
import json
import posixpath
from pathlib import Path

from jsonschema import Draft202012Validator

from common import read_json
from parsers import array_value, object_value, parse_sarif, parse_snyk, parse_trivy, text

SCANNERS = {"snyk-sast": "SAST", "trivy-sca": "SCA", "trivy-iac": "IaC"}
STATUSES = {"COMPLETED", "FAILED", "SKIPPED", "NOT_APPLICABLE"}
SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"


def validate_document(document: object, schema_name: str = "normalized.schema.json") -> dict:
    """Validate wrapped reports; never accept an arbitrary list as a baseline."""
    schema = read_json(SCHEMAS / schema_name)
    Draft202012Validator.check_schema(schema)
    errors = sorted(Draft202012Validator(schema).iter_errors(document),
                    key=lambda error: str(list(error.absolute_path)))
    if errors:
        error = errors[0]
        location = ".".join(str(item) for item in error.absolute_path) or "<root>"
        raise ValueError(f"{schema_name} at {location}: {error.message}")
    return document


def validate_scans(scans: object) -> list[dict]:
    records = array_value(scans, "scanner records")
    seen = set()
    for raw in records:
        record = object_value(raw, "scanner record")
        scanner = record.get("scanner")
        if scanner not in SCANNERS or scanner in seen:
            raise ValueError(f"scanner record: unknown or duplicate scanner {scanner!r}")
        seen.add(scanner)
        if record.get("type") != SCANNERS[scanner] or record.get("status") not in STATUSES:
            raise ValueError(f"scanner {scanner}: invalid type or status")
        for field in ("reason", "version", "json_path", "sarif_path"):
            text(record.get(field), f"scanner {scanner}.{field}")
        code = record.get("exit_code")
        if code is not None and (isinstance(code, bool) or not isinstance(code, int)):
            raise ValueError(f"scanner {scanner}.exit_code: expected integer or null")
    return records


def _report_path(root: Path, relative: object) -> tuple[Path, str]:
    name = text(relative, "scanner report path", True)
    path = Path(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("scanner report path must be relative to reports root without '..'")
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("scanner report path escapes reports root")
    if not resolved.is_file():
        raise ValueError(f"completed scanner report is missing: {name}")
    return resolved, path.as_posix()


def _read_report(path: Path) -> object:
    if path.stat().st_size > 100 * 1024 * 1024:
        raise ValueError(f"scanner report exceeds 100 MiB limit: {path.name}")
    try:
        return read_json(path)
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read scanner JSON {path.name}: {exc}") from exc


def fingerprint(row: dict) -> str:
    """Do not match versions, locations, ecosystems, or distinct resources together."""
    cves = sorted(i for i in row["identifiers"] if i.startswith("CVE-"))
    vulnerability = cves or [row["rule_id"] or row["title"]]
    identity = {
        "type": row["type"], "vulnerability": vulnerability,
        "ecosystem": row["ecosystem"], "package": row["package"],
        "version": row["installed_version"], "file": row["file"],
        "rule": row["rule_id"], "resource": row["resource"],
    }
    if row["type"] in {"SAST", "IaC"}:
        identity["location"] = [row.get(k) for k in
                                ("line", "end_line", "start_column", "end_column")]
    encoded = json.dumps(identity, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _canonical(row: dict) -> dict:
    row = dict(row)
    if row["file"]:
        path = row["file"].replace("\\", "/")
        if row["tool"] == "snyk-sast":
            for prefix in ("file:///project/", "/project/"):
                if path.startswith(prefix):
                    path = path[len(prefix):]
                    break
        row["file"] = posixpath.normpath(path)
    row["identifiers"] = sorted(set(row["identifiers"]))
    if row["line"] and row["end_line"] and row["end_line"] < row["line"]:
        raise ValueError("finding end_line precedes line")
    row["fingerprint"] = fingerprint(row)
    row["id"] = f"finding-{row['fingerprint']}"
    row["evidence"] = [*row["evidence"], {
        "tool": row["tool"], "original_severity": row["original_severity"],
        "cvss_score": row["cvss_score"], "cvss_vector": row["cvss_vector"],
        "raw_sources": row["raw_sources"],
    }]
    return row


def _merge(existing: dict, row: dict) -> None:
    for key in ("tools", "raw_sources", "references", "identifiers", "evidence"):
        for value in row[key]:
            if value not in existing[key]:
                existing[key].append(value)
    # Keep the first tool's original severity; conflicting originals remain in evidence.
    for key in ("description", "recommendation", "fixed_version", "cvss_score", "cvss_vector"):
        if existing[key] is None:
            existing[key] = row[key]
    if existing.get("reachability") != row.get("reachability"):
        existing["reachability"] = "UNKNOWN"


def _parse_record(root: Path, record: dict) -> list[dict]:
    scanner = record["scanner"]
    paths = [(field, record.get(field)) for field in ("json_path", "sarif_path")
             if record.get(field)]
    if not paths:
        raise ValueError(f"completed scanner {scanner} has no report path")
    rows = []
    seen = set()
    for field, relative in paths:
        path, source = _report_path(root, relative)
        if path in seen:
            continue
        seen.add(path)
        document = _read_report(path)
        if scanner == "snyk-sast":
            parsed = parse_snyk(document, source)
        elif field == "sarif_path":
            # Trivy SARIF omits package identity; JSON is authoritative for SCA/IaC.
            parse_sarif(document, scanner, source)
            continue
        else:
            parsed = parse_trivy(document, scanner, source)
        if any(row["type"] != record["type"] for row in parsed):
            raise ValueError(f"scanner {scanner} report contains unexpected finding type")
        rows.extend(parsed)
    if scanner.startswith("trivy") and not record.get("json_path"):
        raise ValueError(f"scanner {scanner}: authoritative Trivy JSON is required")
    for row in rows:
        row["raw_sources"] = sorted({str(value) for _, value in paths})
    return rows


def normalize(output: Path, scans: list[dict]) -> list[dict]:
    """Read raw reports relative to output; return findings without writing reports."""
    merged = {}
    for record in validate_scans(scans):
        if record["status"] != "COMPLETED":
            continue
        for parsed in _parse_record(Path(output), record):
            row = _canonical(parsed)
            if row["fingerprint"] in merged:
                _merge(merged[row["fingerprint"]], row)
            else:
                merged[row["fingerprint"]] = row
    findings = [merged[key] for key in sorted(merged)]
    validate_document({"schema_version": "1.0", "findings": findings})
    return findings
