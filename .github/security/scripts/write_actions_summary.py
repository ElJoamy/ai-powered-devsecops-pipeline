#!/usr/bin/env python3
"""Append a read-only security assessment summary without engine dependencies."""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

# As in cli.py, PYTHONSAFEPATH must not prevent trusted sibling imports.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact_manifest import verify_manifest
from common import read_json, redact
from parsers import parse_sarif, parse_snyk, parse_trivy
from report_generator import PRIORITIES, markdown, ordered, table, text

LOGGER = logging.getLogger("security-summary")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")
SCANNERS = ("snyk-sast", "trivy-sca", "trivy-iac")
STATUSES = {"COMPLETED", "FAILED", "SKIPPED", "NOT_APPLICABLE"}


def _cell(value: object, limit: int = 0) -> str:
    value = redact(text(value))
    if limit and len(value) > limit:
        value = value[:limit - 1] + "…"
    value = "".join(c if c >= " " or c == "\n" else " " for c in value)
    return re.sub(r"([\\`*_{}\[\]()#+.!~-])", r"\\\1", value)


def _table(headers: list[str], rows: list[list[object]], limit: int = 240) -> str:
    return table(headers, [[_cell(cell, limit) for cell in row] for row in rows])


def _load(root: Path, name: str, kind: type, errors: list[str],
          missing: list[str]) -> Any:
    path = root / name
    if not path.is_file():
        missing.append(name)
        return None
    try:
        if not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
            raise ValueError("report path is not a contained regular file")
        document = read_json(path)
        if not isinstance(document, kind):
            raise ValueError(f"expected {kind.__name__}")
        return document
    except (OSError, ValueError, RecursionError) as error:
        errors.append(f"{name}: unreadable or malformed report ({type(error).__name__})")
        return None


def _integrity(root: Path, errors: list[str], missing: list[str]) -> bool:
    manifest = _load(root, "manifest.json", dict, errors, missing)
    if manifest is None:
        return False
    try:
        entries = manifest.get("files")
        if manifest.get("algorithm") != "SHA-256" or not isinstance(entries, list):
            raise ValueError("invalid manifest algorithm or inventory")
        if not entries or any(not isinstance(e, dict) for e in entries):
            raise ValueError("empty or invalid manifest entries")
        names = [e.get("path") for e in entries]
        if any(not isinstance(n, str) or not n for n in names):
            raise ValueError("invalid manifest path")
        if len(set(names)) != len(names) or "manifest.json" in names:
            raise ValueError("duplicate or self-referencing manifest entries")
        if any(p.is_symlink() for p in root.rglob("*")):
            raise ValueError("artifact contains a symlink")
        verify_manifest(root)
        return True
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        errors.append(f"Manifest verification FAILED: {redact(str(error))}")
        return False


def _records(document: object, errors: list[str]) -> list[dict[str, Any]]:
    if document is None:
        return []
    if not isinstance(document, list):
        errors.append("Scanner records are malformed")
        return []
    result: list[dict[str, Any]] = []
    for row in document:
        if (not isinstance(row, dict) or row.get("scanner") not in SCANNERS
                or not isinstance(row.get("status"), str) or row["status"] not in STATUSES
                or any(row.get(k) is not None and not isinstance(row[k], str)
                       for k in ("json_path", "sarif_path"))
                or any(row.get("scanner") == s["scanner"] for s in result)):
            errors.append("Scanner records contain an invalid or duplicate entry")
            continue
        result.append(row)
    return result


def _findings(document: dict[str, Any] | None,
              errors: list[str]) -> list[dict[str, Any]] | None:
    if document is None:
        return None
    rows = document.get("findings")
    if not isinstance(rows, list):
        errors.append("Findings report has no valid findings array")
        return None
    seen: set[str] = set()
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                or not row["id"] or row["id"] in seen
                or not isinstance(row.get("original_severity"), str)
                or not row["original_severity"]
                or not isinstance(row.get("raw_sources"), list) or not row["raw_sources"]
                or not all(isinstance(s, str) for s in row["raw_sources"])
                or not isinstance(row.get("tools"), list)
                or not row["tools"] or any(t not in SCANNERS for t in row["tools"])
                or not isinstance(row.get("evidence"), list)
                or any(not isinstance(e, dict) for e in row["evidence"])
                or row.get("scan_status") != "COMPLETED"
                or not isinstance(row.get("priority"), str)
                or row["priority"] not in PRIORITIES):
            errors.append("Findings report contains an invalid or duplicate finding")
            return None
        seen.add(row["id"])
    return rows


def _severity(value: object) -> str:
    label = str(value).upper()
    if label in {"INFORMATIONAL", "INFORMATION", "NOTE", "NONE"}:
        return "INFO"
    return label if label in SEVERITIES else "UNKNOWN"


def _scanner_findings(scan: dict[str, Any],
                      findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    name = scan["scanner"]
    paths = {scan.get(k) for k in ("json_path", "sarif_path") if scan.get(k)}
    return [f for f in findings if name in f.get("tools", [])
            or f.get("tool") == name or paths.intersection(f.get("raw_sources", []))]


def _scanner_severity(finding: dict[str, Any], scanner: str) -> str:
    # A deduplicated finding retains the first severity; evidence keeps each original.
    for evidence in finding.get("evidence", []):
        if isinstance(evidence, dict) and evidence.get("tool") == scanner:
            return _severity(evidence.get("original_severity"))
    return _severity(finding.get("original_severity"))


def _validate_sources(root: Path, scans: list[dict[str, Any]],
                      errors: list[str], missing: list[str]) -> None:
    for scan in scans:
        if scan["status"] != "COMPLETED":
            continue
        sources = [(key, scan.get(key)) for key in ("json_path", "sarif_path")
                   if scan.get(key)]
        if not sources or (scan["scanner"].startswith("trivy") and not scan.get("json_path")):
            missing.append(f"{scan['scanner']}: authoritative raw result unavailable")
        for key, name in sources:
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                errors.append(f"{scan['scanner']}: invalid raw report path")
                continue
            document = _load(root, name, dict, errors, missing)
            if document is None:
                continue
            try:
                if scan["scanner"] == "snyk-sast":
                    parse_snyk(document, name)
                elif key == "sarif_path":
                    parse_sarif(document, scan["scanner"], name)
                else:
                    parse_trivy(document, scan["scanner"], name)
            except (ValueError, KeyError, TypeError) as error:
                errors.append(f"{name}: invalid raw result ({type(error).__name__})")


def _scanner_table(scans: list[dict[str, Any]],
                   findings: list[dict[str, Any]] | None, pending: bool) -> str:
    rows: list[list[object]] = []
    for name in SCANNERS:
        scan = next((s for s in scans if s["scanner"] == name), None)
        if scan is None:
            rows.append([name, "UNAVAILABLE", "Scanner metadata missing", "UNKNOWN",
                         *(["Unknown"] * 7)])
            continue
        counts: list[object] = ["Pending" if pending and scan["status"] == "COMPLETED"
                                else "Unknown"] * 7
        if findings is not None and not pending and scan["status"] == "COMPLETED":
            selected = _scanner_findings(scan, findings)
            severities = Counter(_scanner_severity(f, name) for f in selected)
            counts = [len(selected), *(severities[s] for s in SEVERITIES)]
        rows.append([name, scan["status"], scan.get("reason") or "Not supplied",
                     scan.get("version") or "UNKNOWN", *counts])
    return _table(["Scanner", "Status", "Reason", "Version", "Total",
                   "Critical", "High", "Medium", "Low", "Info", "Unknown"], rows)


def _url(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"https", "http"} or not parsed.hostname
                or parsed.username or parsed.password or redact(value) != value
                or any(c.isspace() or ord(c) < 32 or c == "\\" for c in value)):
            return None
        parsed.port  # Reject malformed ports as well.
        return quote(value, safe="/:%?=&;,+@!$-._~")
    except ValueError:
        return None


def _run_url(metadata: dict[str, Any]) -> str | None:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    repo = str(metadata.get("repository") or os.environ.get("GITHUB_REPOSITORY", ""))
    run = str(metadata.get("run_id") or os.environ.get("GITHUB_RUN_ID", ""))
    if not _url(server) or not re.fullmatch(r"[\w.-]+/[\w.-]+", repo, re.ASCII):
        return None
    parsed = urlsplit(server)
    if parsed.path or parsed.query or parsed.fragment or not run.isascii() or not run.isdigit():
        return None
    if any(part in {".", ".."} for part in repo.split("/")):
        return None
    return _url(f"{server}/{repo}/actions/runs/{run}")


def _identity(metadata: dict[str, Any], stage: str, job_status: str) -> str:
    rows = [
        ["Stage", stage or "Not supplied"],
        ["Job", job_status or "Not supplied"],
        ["Repository", metadata.get("repository") or os.environ.get("GITHUB_REPOSITORY")
         or "UNAVAILABLE"],
        ["Ref", metadata.get("ref") or metadata.get("branch")
         or os.environ.get("GITHUB_REF") or "UNAVAILABLE"],
        ["Commit", metadata.get("commit_sha") or os.environ.get("GITHUB_SHA")
         or "UNAVAILABLE"],
        ["Run", metadata.get("run_id") or os.environ.get("GITHUB_RUN_ID") or "UNAVAILABLE"],
        ["Attempt", metadata.get("run_attempt") or os.environ.get("GITHUB_RUN_ATTEMPT")
         or "UNAVAILABLE"],
        ["Engine ref", metadata.get("engine_ref") or os.environ.get("SECURITY_ENGINE_REF")
         or "UNAVAILABLE"],
        ["Scan types", metadata.get("scan_types") or "UNAVAILABLE"],
    ]
    result = _table(["Field", "Value"], rows)
    run = _run_url(metadata)
    return result + (f"\n\n[View workflow run]({run})" if run else "")


def _consistency(summary: dict[str, Any] | None,
                 findings: list[dict[str, Any]] | None, gate: dict[str, Any] | None,
                 errors: list[str]) -> None:
    if gate is not None and (not isinstance(gate.get("status"), str)
                             or gate["status"] not in {"PASSED", "FAILED"}
                             or not isinstance(gate.get("reasons"), list)):
        errors.append("Gate report has invalid status or reasons")
    if summary is None:
        return
    if (not isinstance(summary.get("scan_integrity"), str)
            or summary["scan_integrity"] not in {"COMPLETE", "INCOMPLETE", "FAILED"}
            or not isinstance(summary.get("processing_errors"), list)
            or not isinstance(summary.get("limitations"), list)):
        errors.append("Summary has invalid integrity, processing errors or limitations")
    if findings is None:
        return
    severity = dict(Counter(f["original_severity"] for f in findings))
    priority = dict(Counter(f.get("priority", "REVIEW") for f in findings))
    if (type(summary.get("unique_findings")) is not int
            or summary["unique_findings"] != len(findings)
            or summary.get("by_severity") != severity
            or summary.get("by_priority") != priority):
        errors.append("Summary counts do not match persisted findings")


def _overview(summary: dict[str, Any] | None, findings: list[dict[str, Any]] | None,
              verified: bool, pending: bool, intact: bool, failed: bool,
              missing: list[str]) -> str:
    integrity = "FAILED" if failed else (
        "INCOMPLETE" if missing or pending else (summary or {}).get("scan_integrity", "INCOMPLETE"))
    total: object = len(findings) if verified and findings is not None else (
        "Pending consolidation" if pending else "UNAVAILABLE — not verified")
    rows = [["Assessment integrity", integrity],
            ["Artifact integrity", "SHA-256 inventory verified (not authenticity)"
             if intact else "UNAVAILABLE / FAILED — results are not verified"],
            ["Total verified findings", total]]
    sections = [_table(["Assessment", "Result"], rows)]
    if verified and findings is not None:
        severity = Counter(_severity(f["original_severity"]) for f in findings)
        priority = Counter(f.get("priority", "REVIEW") for f in findings)
        sections.extend([
            _table(["Severity", *SEVERITIES], [["Count", *(severity[s] for s in SEVERITIES)]]),
            _table(["Priority", *PRIORITIES], [["Count", *(priority[p] for p in PRIORITIES)]]),
        ])
    else:
        sections.append("Severity and priority counts: **pending consolidation**."
                        if pending else "Severity and priority counts: **unavailable**.")
    sections.append("Counts cover available evidence only; unknown is not zero. "
                    "Static assessment is not proof of safety or complete coverage.")
    return "\n\n".join(sections)


def _gate(gate: dict[str, Any] | None, ready: bool, pending: bool,
          job_status: str) -> str:
    job = job_status.lower()
    if job in {"failure", "failed", "cancelled", "canceled"}:
        status = f"JOB {job.upper()} — stored gate cannot establish job success"
    elif not ready:
        status = "NOT EVALUATED — pending consolidation" if pending else "UNAVAILABLE / UNVERIFIED"
    else:
        status = str((gate or {}).get("status", "UNAVAILABLE"))
    rows: list[list[object]] = [["Effective status", status]]
    if gate:
        rows.append(["Stored policy result", gate.get("status", "UNKNOWN")])
        reasons = gate.get("reasons")
        if isinstance(reasons, list):
            rows.extend(["Reason", reason] for reason in reasons[:8])
            if len(reasons) > 8:
                rows.append(["Additional reasons", f"{len(reasons) - 8}; see metadata/gate.json"])
        rows.append(["Threshold", gate.get("threshold") or "Not configured"])
    return _table(["Gate", "Result"], rows) + (
        "\n\nA passed policy gate does not establish that the repository is secure.")


def _top(findings: list[dict[str, Any]] | None, verified: bool) -> str:
    if not verified or findings is None:
        return "Prioritized findings unavailable until consolidation and integrity verification."
    rows: list[list[object]] = []
    for finding in ordered(findings)[:10]:
        location = str(finding.get("file") or finding.get("package") or "UNKNOWN")
        if finding.get("line"):
            location += f":{finding['line']}"
        recommendation = finding.get("recommendation") or (
            f"Update to {finding['fixed_version']}" if finding.get("fixed_version")
            else "Validate scanner evidence and assess remediation")
        rows.append([finding.get("priority", "REVIEW"), finding["original_severity"],
                     finding.get("title") or finding["id"], location, recommendation])
    return _table(["Priority", "Severity", "Finding", "Location", "Recommendation"], rows, 180) \
        if rows else "No findings in verified available results; coverage limitations still apply."


def _notes(summary: dict[str, Any] | None, inventory: dict[str, Any] | None,
           collection: dict[str, Any] | None, missing: list[str], errors: list[str]) -> str:
    rows: list[list[object]] = []
    for label, values in [
        ("Summary processing errors", (summary or {}).get("processing_errors", [])),
        ("Coverage limitations", (summary or {}).get("limitations", [])),
        ("Inventory limitations", (inventory or {}).get("coverage_limitations",
                                                      (inventory or {}).get("limitations", []))),
        ("Collection errors", (collection or {}).get("processing_errors",
                                                    (collection or {}).get("errors", []))),
        ("Missing evidence", missing), ("Summary errors", errors),
    ]:
        values = values if isinstance(values, list) else [values]
        rows.extend([label, v] for v in values[:5])
        if len(values) > 5:
            rows.append([label, f"{len(values) - 5} more; consult full artifact"])
    if collection:
        rows.append(["Collection", collection.get("status", "UNKNOWN")])
    if inventory and inventory.get("coverage"):
        rows.append(["Coverage", inventory["coverage"]])
    return _table(["Evidence / limitation", "Detail"], rows) if rows else (
        "No processing errors recorded. Consult full reports for scope and exclusions.")


def _artifacts(root: Path, artifact_url: str, metadata: dict[str, Any]) -> str:
    url = _url(artifact_url) if artifact_url else None
    run = _run_url(metadata)
    if url:
        heading = f"[Download assessment artifact]({url})"
    elif run:
        heading = f"[Workflow artifacts — download from this run]({run}#artifacts)"
    else:
        heading = "Artifact download link unavailable."
    if artifact_url and not url:
        heading += "\n\nSupplied artifact URL rejected (unsafe or contains credentials)."
    names = ("SECURITY-REPORT.md", "SECURITY-REPORT.html", "findings.csv",
             "COPILOT-REMEDIATION.md", "summary.json", "reports/summary.json",
             "reports/SECURITY-REPORT.md", "reports/SECURITY-REPORT.html",
             "reports/findings.csv", "risk/risk-assessment.json",
             "normalized/normalized-findings.json", "metadata/execution.json",
             "metadata/scanners.json", "metadata/collection.json",
             "metadata/inventory.json", "metadata/project-inventory.json",
             "metadata/gate.json", "manifest.json")
    available = [name for name in names if (root / name).is_file()]
    return heading + "\n\n" + (
        _table(["Report files present"], [[n] for n in available])
        if available else "No report files available.")


def render_summary(args: argparse.Namespace) -> tuple[str, int]:
    """Render artifact evidence without writing to or changing the artifact directory."""
    root = args.reports.resolve()
    errors: list[str] = []
    missing: list[str] = []
    intact = _integrity(root, errors, missing)
    execution = _load(root, "metadata/execution.json", dict, errors, missing)
    scans = _records(_load(root, "metadata/scanners.json", list, errors, missing), errors)
    summary_name = "summary.json" if (root / "summary.json").exists() else "reports/summary.json"
    final = any((root / p).exists() for p in
                (summary_name, "metadata/gate.json", "risk/risk-assessment.json"))
    summary = _load(root, summary_name, dict, errors, missing) if final else None
    gate = _load(root, "metadata/gate.json", dict, errors, missing) if final else None
    risk = _load(root, "risk/risk-assessment.json", dict, errors, missing) if final else None
    inventory_name = ("metadata/project-inventory.json"
                      if (root / "metadata/project-inventory.json").exists()
                      else "metadata/inventory.json")
    inventory = _load(root, inventory_name, dict, errors, missing)
    collection = _load(root, "metadata/collection.json", dict, errors, missing) if not final else None
    findings = _findings(risk, errors)
    _consistency(summary, findings, gate, errors)
    if final:
        _validate_sources(root, scans, errors, missing)
    metadata = execution or (summary or {}).get("metadata", {})
    metadata = metadata if isinstance(metadata, dict) else {}
    verified = bool(intact and not errors and not missing and summary is not None
                    and findings is not None
                    and (findings or any(s["status"] == "COMPLETED" for s in scans))
                    and (risk or {}).get("status") != "FAILED")
    for error in errors:
        LOGGER.error("%s", redact(error))
    job_failed = args.job_status.lower() in {"failure", "failed", "cancelled", "canceled"}
    failed = bool(errors) or job_failed or any(s["status"] == "FAILED" for s in scans)
    failed = failed or (collection or {}).get("status") == "FAILED"
    sections = ["# Security assessment summary", _identity(metadata, args.stage, args.job_status),
                "## Assessment overview",
                _overview(summary, findings, verified, not final, intact,
                          failed, missing),
                "## Scanner coverage", _scanner_table(scans, findings if verified else None, not final),
                "Per-scanner totals may overlap after cross-scanner deduplication. "
                "Pending means counts await consolidation; unavailable scanners have unknown counts.",
                "## Policy gate", _gate(gate, verified and not missing, not final, args.job_status),
                "## Top 10 prioritized findings", _top(findings, verified),
                "## Artifacts and reports", _artifacts(root, args.artifact_url, metadata),
                "## Processing and coverage", _notes(summary, inventory, collection, missing, errors)]
    return "\n\n".join(sections) + "\n\n", 2 if errors else 0


def main() -> int:
    """Append Markdown externally, or print to stdout when no output is configured."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, required=True, help="Artifact root directory")
    parser.add_argument("--output", type=Path, default=os.environ.get("GITHUB_STEP_SUMMARY"),
                        help="Append destination; defaults to GITHUB_STEP_SUMMARY or stdout")
    parser.add_argument("--stage", default="")
    parser.add_argument("--artifact-url", default="")
    parser.add_argument("--job-status", default="")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if args.output is not None:
        destination = args.output.resolve()
        if destination.is_relative_to(args.reports.resolve()):
            LOGGER.error("Summary output must be outside the artifact directory")
            return 2
    result, status = render_summary(args)
    try:
        if args.output is None:
            sys.stdout.write(result)
        else:
            with args.output.open("a", encoding="utf-8") as stream:
                stream.write("\n" + result)
    except OSError as error:
        LOGGER.error("Cannot append summary: %s", redact(str(error)))
        return 2
    return status


if __name__ == "__main__":
    sys.exit(main())
