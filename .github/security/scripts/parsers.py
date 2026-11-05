"""Strict, local-only adapters for Trivy and Snyk Code reports."""

from __future__ import annotations

import math
import re
from urllib.parse import unquote

IDENTIFIER = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|CWE-\d+)\b", re.I)


def object_value(value: object, where: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{where}: expected an object")
    return value


def array_value(value: object, where: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{where}: expected an array")
    return value


def text(value: object, where: str, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value.strip()):
        raise ValueError(f"{where}: expected {'nonempty ' if required else ''}string")
    return value


def score(value: object, where: str, maximum: float = 10) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{where}: expected a finite number")
    try:
        number = float(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{where}: expected a finite number") from exc
    if not math.isfinite(number) or not 0 <= number <= maximum:
        raise ValueError(f"{where}: expected a number in [0, {maximum}]")
    return number


def position(value: object, where: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{where}: expected a positive integer")
    return value


def strings(value: object, where: str) -> list[str]:
    return [text(item, where, True) for item in array_value(value, where)]


def identifiers(*values: object) -> list[str]:
    return sorted({m.upper() for v in values for m in IDENTIFIER.findall(str(v))})


def finding(tool: str, kind: str, source: str) -> dict:
    return {
        "id": "", "fingerprint": "", "tool": tool, "tools": [tool], "type": kind,
        "identifiers": [], "title": "", "description": None,
        "original_severity": "UNKNOWN", "cvss_score": None, "cvss_vector": None,
        "file": None, "line": None, "end_line": None, "start_column": None,
        "end_column": None, "package": None, "ecosystem": None,
        "installed_version": None, "fixed_version": None, "rule_id": None,
        "references": [], "evidence": [], "recommendation": None,
        "scan_status": "COMPLETED", "raw_sources": [source], "resource": None,
        "reachability": "UNKNOWN",
    }


def _trivy_cvss(raw: dict) -> tuple[float | None, str | None]:
    vendors = object_value(raw.get("CVSS", {}), "Trivy CVSS")
    candidates = []
    for vendor, details in vendors.items():
        data = object_value(details, f"Trivy CVSS.{vendor}")
        for generation in ("V4", "V3", "V2"):
            number = score(data.get(f"{generation}Score"), f"CVSS.{vendor}.{generation}Score")
            vector = text(data.get(f"{generation}Vector"), f"CVSS.{vendor}.{generation}Vector")
            if number is not None:
                candidates.append((generation, vendor != "nvd", str(vendor), number, vector))
    if not candidates:
        return None, None
    selected = sorted(candidates, key=lambda x: (-int(x[0][1]), x[1], x[2]))[0]
    return selected[3], selected[4]


def _trivy_vulnerability(raw: object, result: dict, tool: str, source: str) -> dict:
    data = object_value(raw, "Trivy vulnerability")
    identifier = text(data.get("VulnerabilityID"), "Trivy VulnerabilityID", True)
    row = finding(tool, "SCA", source)
    row.update({
        "title": text(data.get("Title"), "Trivy Title") or identifier,
        "description": text(data.get("Description"), "Trivy Description"),
        "original_severity": text(data.get("Severity"), "Trivy Severity") or "UNKNOWN",
        "package": text(data.get("PkgName"), "Trivy PkgName", True),
        "ecosystem": text(result.get("Type"), "Trivy result Type", True),
        "installed_version": text(data.get("InstalledVersion"), "Trivy InstalledVersion", True),
        "fixed_version": text(data.get("FixedVersion"), "Trivy FixedVersion"),
        "file": text(result.get("Target"), "Trivy Target", True),
        "rule_id": identifier,
        "references": strings(data.get("References", []), "Trivy References"),
        "identifiers": identifiers(identifier, strings(data.get("CweIDs", []), "Trivy CweIDs")),
    })
    row["cvss_score"], row["cvss_vector"] = _trivy_cvss(data)
    row["evidence"] = [{"source": source, "vulnerability_id": identifier,
                        "package_path": text(data.get("PkgPath"), "Trivy PkgPath")}]
    if row["fixed_version"]:
        row["recommendation"] = f"Review upgrade to fixed version(s): {row['fixed_version']}"
    return row


def _trivy_misconfiguration(raw: object, result: dict, tool: str, source: str) -> dict | None:
    data = object_value(raw, "Trivy misconfiguration")
    rule = text(data.get("ID"), "Trivy misconfiguration ID", True)
    status = text(data.get("Status"), "Trivy misconfiguration Status") or "FAIL"
    if status not in {"FAIL", "PASS", "EXCEPTION"}:
        raise ValueError(f"Trivy misconfiguration Status: unsupported {status!r}")
    cause = object_value(data.get("CauseMetadata", {}), "Trivy CauseMetadata")
    row = finding(tool, "IaC", source)
    row.update({
        "title": text(data.get("Title"), "Trivy Title") or rule,
        "description": text(data.get("Description"), "Trivy Description"),
        "original_severity": text(data.get("Severity"), "Trivy Severity") or "UNKNOWN",
        "rule_id": rule, "file": text(result.get("Target"), "Trivy Target", True),
        "resource": text(cause.get("Resource"), "Trivy Resource"),
        "line": position(cause.get("StartLine") or None, "Trivy StartLine"),
        "end_line": position(cause.get("EndLine") or None, "Trivy EndLine"),
        "recommendation": text(data.get("Resolution"), "Trivy Resolution"),
        "references": strings(data.get("References", []), "Trivy References"),
        "identifiers": identifiers(rule, data.get("AVDID"), data.get("References", [])),
        "evidence": [{"source": source, "status": status,
                      "message": text(data.get("Message"), "Trivy Message")}],
    })
    return row if status == "FAIL" else None


def parse_trivy(document: object, tool: str, source: str) -> list[dict]:
    root = object_value(document, "Trivy report")
    if root.get("SchemaVersion") != 2:
        raise ValueError("Trivy report: expected SchemaVersion 2")
    text(root.get("ArtifactName"), "Trivy ArtifactName", True)
    text(root.get("ArtifactType"), "Trivy ArtifactType", True)
    results = array_value(root.get("Results", []), "Trivy Results")
    rows = []
    for item in results:
        result = object_value(item, "Trivy result")
        text(result.get("Target"), "Trivy Target", True)
        for key, parser in (("Vulnerabilities", _trivy_vulnerability),
                            ("Misconfigurations", _trivy_misconfiguration)):
            entries = result.get(key)
            for entry in ([] if entries is None else array_value(entries, f"Trivy {key}")):
                row = parser(entry, result, tool, source)
                if row is not None:
                    rows.append(row)
    return rows


def _sarif_message(value: object, where: str) -> str | None:
    message = object_value(value, where)
    return text(message.get("text", message.get("markdown")), where)


def _sarif_location(value: object) -> dict:
    location = object_value(value, "SARIF location")
    physical = object_value(location.get("physicalLocation", {}), "SARIF physicalLocation")
    artifact = object_value(physical.get("artifactLocation", {}), "SARIF artifactLocation")
    region = object_value(physical.get("region", {}), "SARIF region")
    uri = text(artifact.get("uri"), "SARIF artifact URI")
    return {
        "file": unquote(uri) if uri else None,
        "line": position(region.get("startLine"), "SARIF startLine"),
        "end_line": position(region.get("endLine"), "SARIF endLine"),
        "start_column": position(region.get("startColumn"), "SARIF startColumn"),
        "end_column": position(region.get("endColumn"), "SARIF endColumn"),
    }


def _sarif_rule(raw: dict, rules: list[dict]) -> dict:
    rule_id = text(raw.get("ruleId"), "SARIF ruleId")
    index = raw.get("ruleIndex")
    if index is not None:
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(rules):
            raise ValueError("SARIF ruleIndex: outside driver.rules")
        rule = rules[index]
        if rule_id and rule.get("id") != rule_id:
            raise ValueError("SARIF ruleId and ruleIndex disagree")
        return rule
    return next((rule for rule in rules if rule.get("id") == rule_id), {})


def _sarif_result(raw: object, rules: list[dict], tool: str, source: str) -> list[dict]:
    data = object_value(raw, "SARIF result")
    if data.get("kind") in {"pass", "notApplicable", "informational"}:
        return []
    rule = _sarif_rule(data, rules)
    rule_id = text(data.get("ruleId", rule.get("id")), "SARIF ruleId", True)
    properties = object_value(rule.get("properties", {}), "SARIF rule properties")
    result_props = object_value(data.get("properties", {}), "SARIF result properties")
    merged = {**properties, **result_props}
    message = _sarif_message(data.get("message"), "SARIF result message")
    locations = array_value(data.get("locations", []), "SARIF locations")
    row = finding(tool, "SAST", source)
    row.update({
        "rule_id": rule_id, "title": text(rule.get("name"), "SARIF rule name") or rule_id,
        "description": message,
        "original_severity": text(merged.get("severity", data.get("level")), "SARIF severity")
        or text(object_value(rule.get("defaultConfiguration", {}), "SARIF defaults").get("level"),
                  "SARIF default level") or "UNKNOWN",
        "cvss_score": score(merged.get("security-severity"), "SARIF security-severity"),
        "cvss_vector": text(merged.get("cvssVector"), "SARIF cvssVector"),
        "identifiers": identifiers(rule_id, strings(properties.get("tags", []), "SARIF tags"),
                                   merged.get("cwe", [])),
        "references": [text(rule["helpUri"], "SARIF helpUri", True)] if "helpUri" in rule else [],
        "recommendation": _sarif_message(rule["help"], "SARIF help") if "help" in rule else None,
        "evidence": [{"source": source, "message": message,
                      "rule_metadata": properties, "result_metadata": result_props}],
    })
    if "reachability" in merged:
        row["evidence"].append({"tool_explicit_reachability": merged["reachability"]})
        if merged["reachability"] in {"REACHABLE", "UNREACHABLE", "UNKNOWN"}:
            row["reachability"] = merged["reachability"]
    return [{**row, **_sarif_location(location)} for location in locations] or [row]


def parse_sarif(document: object, tool: str, source: str) -> list[dict]:
    root = object_value(document, "SARIF report")
    if root.get("version") != "2.1.0":
        raise ValueError("SARIF report: expected version 2.1.0")
    runs = array_value(root.get("runs"), "SARIF runs")
    if not runs:
        raise ValueError("SARIF report: runs must include a completed tool run")
    rows = []
    for raw in runs:
        run = object_value(raw, "SARIF run")
        driver = object_value(object_value(run.get("tool"), "SARIF tool").get("driver"),
                              "SARIF driver")
        text(driver.get("name"), "SARIF driver name", True)
        rules = [object_value(r, "SARIF rule")
                 for r in array_value(driver.get("rules", []), "SARIF rules")]
        for invocation in array_value(run.get("invocations", []), "SARIF invocations"):
            if object_value(invocation, "SARIF invocation").get("executionSuccessful") is False:
                raise ValueError("SARIF report: tool invocation was unsuccessful")
        for result in array_value(run.get("results", []), "SARIF results"):
            rows.extend(_sarif_result(result, rules, tool, source))
    return rows


def _snyk_issue(raw: object, source: str) -> list[dict]:
    data = object_value(raw, "Snyk Code issue")
    rule = text(data.get("ruleId", data.get("id")), "Snyk issue id", True)
    row = finding("snyk-sast", "SAST", source)
    row.update({
        "rule_id": rule, "title": text(data.get("title"), "Snyk title") or rule,
        "description": text(data.get("message", data.get("description")), "Snyk description"),
        "original_severity": text(data.get("severity"), "Snyk severity") or "UNKNOWN",
        "identifiers": identifiers(rule, data.get("cwe", []), data.get("identifiers", {})),
        "cvss_score": score(data.get("cvssScore"), "Snyk cvssScore"),
        "cvss_vector": text(data.get("cvssVector"), "Snyk cvssVector"),
        "references": strings(data.get("references", []), "Snyk references"),
        "evidence": [{"source": source, "issue_id": rule}],
    })
    locations = data.get("locations", data.get("positions"))
    if locations is None:
        locations = [data] if "filePath" in data else []
    rows = []
    for raw_location in array_value(locations, "Snyk issue locations"):
        loc = object_value(raw_location, "Snyk issue location")
        if "physicalLocation" in loc:
            rows.append({**row, **_sarif_location(loc)})
            continue
        lines = object_value(loc.get("rows", {}), "Snyk location rows")
        rows.append({**row, "file": text(loc.get("filePath"), "Snyk filePath", True),
                     "line": position(loc.get("lineNumber", lines.get("begin")), "Snyk line"),
                     "end_line": position(lines.get("end"), "Snyk end line")})
    return rows or [row]


def parse_snyk(document: object, source: str) -> list[dict]:
    if isinstance(document, dict) and "runs" in document:
        return parse_sarif(document, "snyk-sast", source)
    root = object_value(document, "Snyk Code report")
    if root.get("error") or root.get("success") is False:
        raise ValueError("Snyk Code report: scanner reported an error")
    issues = array_value(root.get("issues"), "Snyk Code issues")
    return [row for issue in issues for row in _snyk_issue(issue, source)]
