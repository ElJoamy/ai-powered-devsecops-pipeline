#!/usr/bin/env python3
"""GitHub Actions entry point: scan, publish evidence, then evaluate the gate."""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

# PYTHONSAFEPATH keeps target-controlled import paths out; import only trusted engine siblings.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifact_manifest import create_manifest, verify_manifest
from baseline_comparator import compare
from common import read_json, redact, utc_now, write_json
from configuration import load_config, resolve_scan_types, validate_config
from copilot_prompt_generator import generate_prompt
from inventory import inventory
from normalizer import normalize
from report_generator import PRIORITIES, generate
from risk_engine import assess
from scan_artifacts import (collection_identity, merge_collections, scanner_records,
                            write_collection)
from scanner_runner import _coverage, run_scanners
from threat_intelligence import enrich

LOGGER = logging.getLogger("security-pipeline")
DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "config" / "risk-policy.yaml"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "collect", "consolidate"):
        command = commands.add_parser(name, help="Read-only security assessment stage")
        _scan_arguments(command)
        if name == "consolidate":
            command.add_argument("--artifacts", type=Path, required=True)
    select = commands.add_parser("select", help="Resolve requested scanners for workflow steps")
    select.add_argument("--scan-types", required=True)
    select.add_argument("--matrix", action="store_true")
    for name in ("gate", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _scan_arguments(scan: argparse.ArgumentParser) -> None:
    scan.add_argument("--repo", type=Path, required=True)
    scan.add_argument("--output", type=Path, required=True)
    for name in ("config", "policy", "baseline"):
        scan.add_argument(f"--{name}", type=Path)
    scan.add_argument("--exclude", action="append", default=[])
    scan.add_argument("--scan-types", help="all or any combination of sast,iac,dependencies")
    scan.add_argument("--offline", action="store_true")
    scan.add_argument("--fail-on", choices=list(PRIORITIES))


def _input_file(repo: Path, path: Path | None, name: str) -> Path | None:
    if path is None:
        return None
    resolved = (repo / path).resolve()
    if not resolved.is_relative_to(repo) or not resolved.is_file():
        raise ValueError(f"{name} must be an existing file inside the scanned repository")
    return resolved


def _git(repo: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments], capture_output=True, text=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        LOGGER.warning("Git metadata unavailable: %s", redact(str(error)))
        return "UNKNOWN"
    return result.stdout.strip() if result.returncode == 0 else "UNKNOWN"


def _metadata(repo: Path) -> dict[str, Any]:
    return {
        "repository": os.environ.get("GITHUB_REPOSITORY", repo.name),
        "branch": os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME")
        or _git(repo, "branch", "--show-current"),
        "commit_sha": _git(repo, "rev-parse", "HEAD"),
        "generated_at": utc_now(), "engine_version": "0.1.0",
        "event": os.environ.get("GITHUB_EVENT_NAME", "local-validation"),
        "run_id": os.environ.get("GITHUB_RUN_ID", "LOCAL"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
        "engine_ref": os.environ.get("SECURITY_ENGINE_REF", "UNKNOWN"),
        "analysis": "Read-only static assessment; no exploitation or remediation",
    }


def _configuration(args: argparse.Namespace, repo: Path) -> dict[str, Any]:
    config = load_config(_input_file(repo, args.config, "Config"), repo)
    config["scan"]["exclude"].extend(args.exclude)
    if args.scan_types is not None:
        resolve_scan_types(args.scan_types)
        config["scan"]["types"] = args.scan_types
    if args.offline:
        config["intelligence"]["enabled"] = False
    if args.fail_on:
        config["gate"]["fail_on"] = args.fail_on
    return config


def _gate_result(config: dict[str, Any], scans: list[dict[str, Any]],
                 findings: list[dict[str, Any]], errors: list[str]) -> dict[str, Any]:
    reasons = list(errors)
    if config["gate"]["fail_on_scanner_error"]:
        reasons.extend(f"{s['scanner']}: {s.get('reason')}" for s in scans
                       if s["status"] == "FAILED")
    if "sast" in resolve_scan_types(config["scan"]["types"]):
        if not any(s["type"] == "SAST" and s["status"] == "COMPLETED" for s in scans):
            reasons.append("Required SAST assessment was not completed")
    threshold = config["gate"]["fail_on"]
    blocked = []
    if threshold:
        blocked = [f["id"] for f in findings
                   if f.get("priority") == "REVIEW" and threshold == "REVIEW"
                   or f.get("priority") != "REVIEW"
                   and PRIORITIES.get(f.get("priority"), 99) <= PRIORITIES[threshold]]
        if blocked:
            reasons.append(f"{len(blocked)} findings meet configured threshold {threshold}")
    return {"status": "FAILED" if reasons else "PASSED", "reasons": reasons,
            "threshold": threshold, "blocked_findings": blocked,
            "note": "PASSED means gate policy satisfied, not that the repository is secure."}


def _normalize_scans(output: Path, scans: list[dict[str, Any]],
                     errors: list[str]) -> list[dict[str, Any]]:
    findings = []
    for scan in scans:
        if scan["status"] != "COMPLETED":
            continue
        try:
            findings.extend(normalize(output, [scan]))
        except (ValueError, KeyError, TypeError, OSError) as error:
            reason = redact(f"{scan['scanner']} normalization failed: {error}")
            LOGGER.error("%s", reason)
            errors.append(reason)
            scan["status"] = "FAILED"
            scan["reason"] = reason
    # Normalize together once more to apply cross-scanner deduplication.
    if findings:
        try:
            return normalize(output, [s for s in scans if s["status"] == "COMPLETED"])
        except (ValueError, KeyError, TypeError, OSError) as error:
            errors.append(redact(f"Cross-scanner normalization failed: {error}"))
    return findings


def _risk(findings: list[dict[str, Any]], config: dict[str, Any], policy: Path,
          output: Path, errors: list[str]) -> list[dict[str, Any]]:
    try:
        enriched = enrich(findings, config, output / "intelligence")
        return assess(enriched, config, policy)
    except (ValueError, KeyError, TypeError, OSError) as error:
        reason = redact(f"Risk processing failed: {error}")
        LOGGER.error("%s", reason)
        errors.append(reason)
        return [dict(f, priority="REVIEW", contextual_risk="NOT_ASSESSED",
                     risk_factors=[reason], confidence="LOW",
                     limitations=[*f.get("limitations", []), reason]) for f in findings]


def _comparison(output: Path, findings: list[dict[str, Any]], baseline: Path | None,
                scans: list[dict[str, Any]], errors: list[str]) -> None:
    try:
        result = compare(findings, baseline, scans)
    except (ValueError, KeyError, TypeError, OSError) as error:
        reason = redact(f"Baseline comparison failed: {error}")
        LOGGER.error("%s", reason)
        errors.append(reason)
        result = {"status": "FAILED", "reason": reason}
    write_json(output / "comparison" / "findings-diff.json", result)
    report = "# Baseline comparison\n\nDisappearance is not proof of remediation.\n\n"
    report += "```json\n" + json.dumps(result, indent=2, ensure_ascii=True) + "\n```\n"
    (output / "comparison" / "COMPARISON-REPORT.md").write_text(report, encoding="utf-8")


def _finish(output: Path, metadata: dict[str, Any], project: dict[str, Any],
            scans: list[dict[str, Any]], findings: list[dict[str, Any]],
            config: dict[str, Any], errors: list[str]) -> int:
    gate = _gate_result(config, scans, findings, errors)
    write_json(output / "metadata" / "project-inventory.json", project)
    write_json(output / "metadata" / "scanners.json", scans)
    write_json(output / "metadata" / "execution.json", metadata)
    write_json(output / "metadata" / "gate.json", gate)
    summary = generate(output, metadata, project, scans, findings, errors)
    generate_prompt(output, metadata, project, findings, scans)
    write_json(output / "metadata" / "phases.json", {
        "inventory": "FAILED" if project.get("status") == "FAILED" else "COMPLETED",
        "scanning": {s["scanner"]: s["status"] for s in scans},
        "processing": "FAILED" if errors else "COMPLETED",
        "reporting": "COMPLETED", "gate": gate["status"],
    })
    create_manifest(output)
    verify_manifest(output)
    print(f"Reports: {output}\nIntegrity: {summary['scan_integrity']}; "
          f"findings: {len(findings)}; gate: {gate['status']}")
    return 2 if errors or any(s["status"] == "FAILED" for s in scans) else 0


def _execute(args: argparse.Namespace, repo: Path, output: Path,
             metadata: dict[str, Any]) -> int:
    errors: list[str] = []
    config = _configuration(args, repo)
    metadata["scan_types"] = config["scan"]["types"]
    policy = _input_file(repo, args.policy, "Risk policy") or DEFAULT_POLICY
    baseline = _input_file(repo, args.baseline, "Baseline")
    if output.is_relative_to(repo):
        config["scan"]["exclude"].append(output.relative_to(repo).as_posix())
    project = inventory(repo, config)
    scans = run_scanners(repo, output, config, project)
    return _process(output, metadata, project, scans, config, policy, baseline, errors)


def _process(output: Path, metadata: dict[str, Any], project: dict[str, Any],
             scans: list[dict[str, Any]], config: dict[str, Any], policy: Path,
             baseline: Path | None, errors: list[str], *,
             merged: bool = False) -> int:
    normalized = _normalize_scans(output, scans, errors)
    if merged:
        _coverage(scans, project)
    write_json(output / "normalized" / "normalized-findings.json", {
        "schema_version": "1.0", "metadata": metadata, "scanners": scans,
        "findings": normalized,
    })
    findings = _risk(normalized, config, policy, output, errors)
    write_json(output / "risk" / "risk-assessment.json", {
        "schema_version": "1.0", "metadata": metadata, "scanners": scans,
        "findings": findings,
    })
    _comparison(output, findings, baseline, scans, errors)
    return _finish(output, metadata, project, scans, findings, config, errors)


def _stage_inputs(args: argparse.Namespace, repo: Path,
                  metadata: dict[str, Any]) -> tuple[dict[str, Any], Path, Path | None,
                                                     dict[str, Any]]:
    config = validate_config(_configuration(args, repo), repo)
    metadata["scan_types"] = config["scan"]["types"]
    policy = _input_file(repo, args.policy, "Risk policy") or DEFAULT_POLICY
    baseline = _input_file(repo, args.baseline, "Baseline")
    identity = collection_identity(metadata, config, policy, baseline)
    return config, policy, baseline, identity


def _collect(args: argparse.Namespace, repo: Path, output: Path,
             metadata: dict[str, Any]) -> int:
    config, _, _, identity = _stage_inputs(args, repo, metadata)
    selected = resolve_scan_types(config["scan"]["types"])
    if len(selected) != 1:
        raise ValueError("collect requires exactly one scan kind per isolated worker")
    if output.is_relative_to(repo):
        config["scan"]["exclude"].append(output.relative_to(repo).as_posix())
    errors: list[str] = []
    try:
        project = inventory(repo, config)
        collected = run_scanners(repo, output, config, project)
        # A staging failure can mark every adapter FAILED; unselected adapters never ran.
        expected = scanner_records(selected)
        by_name = {row["scanner"]: row for row in collected}
        scans = [by_name[template["scanner"]] if template["status"] == "FAILED" else template
                 for template in expected]
        if scans != collected:
            project["coverage_limitations"] = [
                item for item in project["coverage_limitations"]
                if not item.startswith("NOT_ASSESSED: ")]
            _coverage(scans, project)
            project["coverage_limitations"] = list(dict.fromkeys(project["coverage_limitations"]))
    except (ValueError, KeyError, TypeError, OSError) as error:
        reason = redact(f"Collection failed: {error}")
        errors.append(reason)
        project = {"status": "FAILED", "coverage_limitations": [reason], "languages": []}
        scans = scanner_records(selected, reason)
        _coverage(scans, project)
    return write_collection(output, metadata, project, scans, selected, identity, errors)


def _consolidate(args: argparse.Namespace, repo: Path, output: Path,
                 metadata: dict[str, Any]) -> int:
    config, policy, baseline, identity = _stage_inputs(args, repo, metadata)
    selected = resolve_scan_types(config["scan"]["types"])
    if output.is_relative_to(repo):
        config["scan"]["exclude"].append(output.relative_to(repo).as_posix())
    project = inventory(repo, config)
    scans, errors = merge_collections(args.artifacts.absolute(), output, selected, identity)
    return _process(output, metadata, project, scans, config, policy, baseline, errors,
                    merged=True)


def _failed_collection(args: argparse.Namespace, output: Path,
                       metadata: dict[str, Any], error: Exception) -> int:
    reason = redact(f"Collection could not complete: {error}")
    LOGGER.error("%s", reason)
    try:
        selection = metadata.get("scan_types", args.scan_types or "all")
        selected = resolve_scan_types(selection if selection != "UNKNOWN" else "all")
    except ValueError:
        selected = {"sast", "dependencies", "iac"}
    project = {"status": "FAILED", "coverage_limitations": [reason], "languages": []}
    scans = scanner_records(selected, reason)
    _coverage(scans, project)
    return write_collection(output, metadata, project, scans, selected, None, [reason])


def _failed_assessment(output: Path, metadata: dict[str, Any], error: Exception,
                       selected: set[str] | None = None) -> int:
    reason = redact(f"Assessment could not complete: {error}")
    LOGGER.error("%s", reason)
    project = {"languages": [], "coverage": {"status": "NOT_ASSESSED"},
               "limitations": [reason], "status": "FAILED"}
    scans = scanner_records(selected if selected is not None else
                            {"sast", "dependencies", "iac"}, reason)
    for path in ("normalized/normalized-findings.json", "risk/risk-assessment.json"):
        write_json(output / path, {"schema_version": "1.0", "metadata": metadata,
                                  "scanners": scans, "findings": [], "status": "FAILED"})
    # This policy is only for failure reporting; no scan runs with fallback configuration.
    config = {"gate": {"fail_on_scanner_error": True, "fail_on": None},
              "scan": {"types": ",".join(sorted(selected)) if selected else "all"}}
    return _finish(output, metadata, project, scans, [], config, [reason])


def scan(args: argparse.Namespace) -> int:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("Scanning is only permitted in GitHub Actions, not on this machine")
    repo, output = args.repo.resolve(), args.output.resolve()
    if not repo.is_dir():
        raise ValueError("Repository path must be an existing directory")
    if output == repo or repo.is_relative_to(output):
        raise ValueError("Reports directory cannot be the repository or its ancestor")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("Reports directory must be empty; use a new path for every execution")
    output.mkdir(parents=True, exist_ok=True)
    metadata = _metadata(repo)
    metadata["scan_types"] = args.scan_types or "UNKNOWN"
    try:
        execute = {"scan": _execute, "collect": _collect, "consolidate": _consolidate}
        return execute[args.command](args, repo, output, metadata)
    except (ValueError, KeyError, TypeError, OSError) as error:
        if args.command == "collect":
            return _failed_collection(args, output, metadata, error)
        if args.command == "consolidate":
            selected = _failure_selection(args, repo)
            return _failed_assessment(output, metadata, error, selected)
        return _failed_assessment(output, metadata, error)


def _failure_selection(args: argparse.Namespace, repo: Path) -> set[str]:
    try:
        value = _configuration(args, repo)["scan"]["types"]
    except (ValueError, KeyError, TypeError, OSError):
        value = args.scan_types or "all"
    try:
        return resolve_scan_types(value)
    except ValueError:
        return {"sast", "dependencies", "iac"}


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = _arguments()
    try:
        if args.command == "select":
            selected = resolve_scan_types(args.scan_types)
            if args.matrix:
                print(json.dumps({"include": [{"scan": kind} for kind in
                      ("sast", "dependencies", "iac") if kind in selected]},
                      separators=(",", ":")))
                return 0
            for name, kind in (("sast", "sast"), ("sca", "dependencies"), ("iac", "iac")):
                print(f"{name}={str(kind in selected).lower()}")
            return 0
        if args.command in {"scan", "collect", "consolidate"}:
            return scan(args)
        output = args.output.resolve()
        verify_manifest(output)
        if args.command == "verify":
            print("Artifact SHA-256 inventory verified (not an authenticity signature)")
            return 0
        gate = read_json(output / "metadata" / "gate.json")
        print(gate["status"])
        for reason in gate["reasons"]:
            print(reason)
        return 1 if gate["status"] == "FAILED" else 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        LOGGER.error("%s", redact(str(error)))
        return 2


if __name__ == "__main__":
    sys.exit(main())
