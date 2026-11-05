"""Explicit, validated baselines; disappearance is never reported as remediation."""

from __future__ import annotations

import copy
from pathlib import Path

from common import read_json
from normalizer import SCANNERS, validate_document, validate_scans

TRACKED = (
    "title", "description", "original_severity", "cvss_score", "cvss_vector",
    "fixed_version", "identifiers", "tools", "contextual_risk", "priority",
    "epss_probability", "kev_listed", "reachability",
)


def _indexed(findings: list[dict], label: str) -> dict:
    indexed = {}
    for row in findings:
        fingerprint = row["fingerprint"]
        if fingerprint in indexed:
            raise ValueError(f"{label}: duplicate fingerprint {fingerprint}")
        indexed[fingerprint] = row
    return indexed


def _load_baseline(path: Path) -> dict:
    try:
        if path.stat().st_size > 100 * 1024 * 1024:
            raise ValueError("baseline exceeds 100 MiB")
        document = read_json(path)
    except (OSError, ValueError) as exc:
        raise ValueError(f"supplied baseline {path}: cannot load: {exc}") from exc
    validate_document(document)
    if any("priority" in row or "contextual_risk" in row for row in document["findings"]):
        validate_document(document, "risk.schema.json")
    _indexed(document["findings"], "baseline")
    if "scanners" in document:
        validate_scans(document["scanners"])
    return document


def _coverage(scans: list[dict]) -> dict:
    indexed = {record["scanner"]: record for record in scans}
    return {scanner: {
        "status": indexed.get(scanner, {}).get("status", "UNKNOWN"),
        "reason": indexed.get(scanner, {}).get("reason") or
                  ("No current scan record." if scanner not in indexed else None),
        "version": indexed.get(scanner, {}).get("version"),
    } for scanner in SCANNERS}


def _not_detected(row: dict, coverage: dict, previous: dict) -> dict:
    result = copy.deepcopy(row)
    tools = row["tools"]
    missing = [tool for tool in tools
               if coverage.get(tool, {}).get("status") != "COMPLETED"]
    prior = {item["scanner"]: item for item in previous.get("scanners", [])}
    versions_changed = [tool for tool in tools
                        if tool in prior and prior[tool].get("version") !=
                        coverage.get(tool, {}).get("version")]
    notes = ["Not observed in current output; this is not proof of a fix.",
             "Completed status does not establish identical targets, exclusions, or rules."]
    if missing:
        notes.append("Prior producing scanner(s) lack completed coverage: " + ", ".join(missing))
    if versions_changed:
        notes.append("Scanner version changed: " + ", ".join(versions_changed))
    if not previous.get("scanners"):
        notes.append("Baseline scanner coverage metadata is unavailable.")
    result.update({
        "baseline_status": "NOT_DETECTED",
        "coverage_status": "INCOMPLETE" if missing else "COMPLETED_WITH_UNCERTAINTY",
        "coverage_uncertainty": notes,
    })
    return result


def _comparison(current: dict, prior: dict, coverage: dict, document: dict) -> dict:
    result = {"new": [], "unchanged": [], "changed": [], "not_detected": []}
    for fingerprint, row in current.items():
        if fingerprint not in prior:
            result["new"].append(copy.deepcopy(row))
            continue
        previous = prior[fingerprint]
        fields = [key for key in TRACKED if row.get(key) != previous.get(key)]
        if fields:
            result["changed"].append({"fingerprint": fingerprint, "changed_fields": fields,
                                      "previous": copy.deepcopy(previous),
                                      "current": copy.deepcopy(row)})
        else:
            result["unchanged"].append(copy.deepcopy(row))
    result["not_detected"] = [_not_detected(row, coverage, document)
                               for fingerprint, row in prior.items() if fingerprint not in current]
    return result


def compare(findings: list[dict], baseline: Path | None, scans: list[dict]) -> dict:
    """Compare explicit normalized/risk JSON, returning NOT_DETECTED rather than fixed."""
    validate_document({"schema_version": "1.0", "findings": findings})
    coverage = _coverage(validate_scans(scans))
    current = _indexed(findings, "current findings")
    result = {
        "schema_version": "1.0", "status": "NO_BASELINE" if baseline is None else "COMPARED",
        "coverage": coverage, "new": [], "unchanged": [], "changed": [], "not_detected": [],
        "limitations": ["Fingerprint changes (including package version or location) appear "
                        "as new and not detected, not as verified remediation."],
    }
    if baseline is None:
        result["limitations"].append("No baseline supplied; no new/resolved claim is made.")
    else:
        document = _load_baseline(Path(baseline))
        result.update(_comparison(current, _indexed(document["findings"], "baseline"),
                                  coverage, document))
    result["summary"] = {key: len(result[key]) for key in
                         ("new", "unchanged", "changed", "not_detected")}
    validate_document(result, "baseline.schema.json")
    return result
