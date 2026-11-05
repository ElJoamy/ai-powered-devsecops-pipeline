"""Generate self-contained assessment reports from actual scanner results."""

from __future__ import annotations

import csv
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from common import write_json

PRIORITIES = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "REVIEW": 4}


def ordered(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda item: (
        PRIORITIES.get(item.get("priority", "REVIEW"), 4), str(item.get("id", ""))
    ))


def text(value: object) -> str:
    if value is None:
        return "UNKNOWN"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=True, sort_keys=True)
    return str(value)


def markdown(value: object) -> str:
    return html.escape(text(value)).replace("|", "&#124;").replace("\n", "<br>")


def table(headers: list[str], rows: list[list[object]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(markdown(cell) for cell in row) + " |" for row in rows)
    return "\n".join(lines)


def _summary(metadata: dict[str, Any], inventory: dict[str, Any],
             scans: list[dict[str, Any]], findings: list[dict[str, Any]],
             errors: list[str]) -> dict[str, Any]:
    completed = sum(scan["status"] == "COMPLETED" for scan in scans)
    applicable = [scan for scan in scans if scan["status"] != "NOT_APPLICABLE"]
    integrity = "COMPLETE" if completed == len(applicable) and completed else "INCOMPLETE"
    if errors or any(scan["status"] == "FAILED" for scan in scans):
        integrity = "FAILED"
    return {
        "schema_version": "1.0", "metadata": metadata, "scan_integrity": integrity,
        "unique_findings": len(findings),
        "by_severity": dict(Counter(item.get("original_severity", "UNKNOWN")
                                    for item in findings)),
        "by_priority": dict(Counter(item.get("priority", "REVIEW") for item in findings)),
        "by_type": dict(Counter(item.get("type", "UNKNOWN") for item in findings)),
        "scanners": scans, "coverage": inventory.get("coverage", {}),
        "limitations": inventory.get("coverage_limitations", inventory.get("limitations", [])),
        "processing_errors": errors,
        "conclusion": (
            "Static findings require validation; this is not a penetration test."
            if findings else
            "No findings reported. This does not establish safety or complete coverage."
        ),
    }


def _details(findings: list[dict[str, Any]]) -> str:
    sections = []
    fields = [
        ("Location", "file"), ("Line", "line"), ("Identifiers", "identifiers"),
        ("Original severity", "original_severity"), ("CVSS", "cvss_score"),
        ("CVSS vector", "cvss_vector"), ("Priority", "priority"),
        ("Contextual risk", "contextual_risk"), ("Risk factors", "risk_factors"),
        ("Confidence", "confidence"), ("Description", "description"),
        ("Evidence", "evidence"), ("Package", "package"),
        ("Installed version", "installed_version"), ("Fixed version", "fixed_version"),
        ("Recommendation (scanner)", "recommendation"), ("References", "references"),
        ("Limitations", "limitations"), ("Raw sources", "raw_sources"),
    ]
    for finding in ordered(findings):
        sections.append(f"### {markdown(finding['id'])}: {markdown(finding.get('title'))}")
        sections.extend(f"- **{label}:** {markdown(finding.get(key))}"
                        for label, key in fields)
        sections.append("")
    return "\n".join(sections) or "No normalized findings; consult Scan Integrity."


def _report(summary: dict[str, Any], inventory: dict[str, Any],
            findings: list[dict[str, Any]]) -> str:
    scan_rows = [[s["scanner"], s["status"], s.get("version"), s.get("reason")]
                 for s in summary["scanners"]]
    priorities = [[f["id"], f.get("priority"), f.get("original_severity"),
                   f.get("file"), f.get("risk_factors")] for f in ordered(findings)]
    return "\n\n".join([
        "# Security Assessment",
        "## 1. Executive Summary",
        table(["Field", "Value"], [[k, v] for k, v in summary["metadata"].items()]),
        f"**Integrity: {summary['scan_integrity']}** | "
        f"Unique findings: {len(findings)}\n\n{summary['conclusion']}",
        table(["Severity", "Count"], [list(v) for v in summary["by_severity"].items()]),
        table(["Priority", "Count"], [list(v) for v in summary["by_priority"].items()]),
        "## 2. Security Assessment Scope",
        f"```json\n{json.dumps(inventory, ensure_ascii=True, indent=2)}\n```",
        "## 3. Vulnerability Overview",
        table(["Type", "Findings"], [list(v) for v in summary["by_type"].items()]),
        "## 4. Risk-Based Prioritization",
        "Original scanner severity and contextual priority are independent. "
        "Unknown reachability is not evidence of non-exploitability.",
        table(["ID", "Priority", "Original severity", "File", "Decision factors"], priorities),
        "## 5. Detailed Findings", _details(findings),
        "## 6. Recommended Remediation Plan",
        "Validate findings at the analyzed commit; address P0 then P1/P2/P3 and manually "
        "review REVIEW findings. Inspect affected files, update manifests and lockfiles "
        "using their package manager, preserve security controls and run the project's "
        "existing relevant checks. See COPILOT-REMEDIATION.md. No source was remediated.",
        "## 7. Scan Integrity",
        table(["Scanner", "Status", "Version", "Reason"], scan_rows),
        f"Processing errors: {markdown(summary['processing_errors'])}",
        f"Coverage limitations: {markdown(summary['limitations'])}",
        "Scanner observations are static evidence, risk assignments are contextual "
        "inferences, and remediation steps are recommendations, not verified fixes.",
    ]) + "\n"


def generate(output: Path, metadata: dict[str, Any], inventory: dict[str, Any],
             scans: list[dict[str, Any]], findings: list[dict[str, Any]],
             errors: list[str]) -> dict[str, Any]:
    summary = _summary(metadata, inventory, scans, findings, errors)
    report = _report(summary, inventory, findings)
    output.mkdir(parents=True, exist_ok=True)
    (output / "SECURITY-REPORT.md").write_text(report, encoding="utf-8")
    document = _html(summary, inventory, findings)
    (output / "SECURITY-REPORT.html").write_text(document, encoding="utf-8")
    _csv(output, findings)
    write_json(output / "summary.json", summary)
    return summary


def _html_table(headers: list[str], rows: list[list[object]]) -> str:
    head = "".join(f"<th>{html.escape(label)}</th>" for label in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(text(cell))}</td>" for cell in row)
                   + "</tr>" for row in rows)
    return f"<div class='scroll'><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def _html(summary: dict[str, Any], inventory: dict[str, Any],
          findings: list[dict[str, Any]]) -> str:
    details = []
    for finding in ordered(findings):
        body = "".join(f"<dt>{html.escape(key)}</dt><dd>{html.escape(text(value))}</dd>"
                       for key, value in finding.items())
        title = html.escape(f"{finding.get('priority')} | {finding.get('title')}")
        details.append(f"<details><summary>{title}</summary><dl>{body}</dl></details>")
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        'style-src \'unsafe-inline\'"><title>Security Assessment</title>'
        '<style>body{max-width:1200px;margin:2rem auto;padding:1rem;font:16px system-ui;'
        'color:#182230;background:#fafbfc}h1{color:#164679}table{border-collapse:collapse;'
        'width:100%}td,th{padding:.7rem;text-align:left;border:1px solid #d5dce5;'
        'overflow-wrap:anywhere;vertical-align:top}th{background:#e8eef5}.scroll{overflow:auto}'
        'pre,dd{white-space:pre-wrap;overflow-wrap:anywhere}dt{font-weight:bold;margin-top:1rem}'
        'details{margin:1rem 0;padding:1rem;background:white;border:1px solid #ccd5df}'
        'summary{cursor:pointer;font-weight:bold}header{border-bottom:4px solid #164679}</style>'
        '<body><header><h1>Security Assessment</h1>'
        f'<p>Integrity: <strong>{summary["scan_integrity"]}</strong> | '
        f'Unique findings: {len(findings)}</p></header><h2>1. Executive Summary</h2>'
        + _html_table(["Field", "Value"], [[k, v] for k, v in summary["metadata"].items()])
        + f'<p>{html.escape(summary["conclusion"])}</p><h2>2. Assessment Scope</h2>'
        + f'<pre>{html.escape(json.dumps(inventory, ensure_ascii=True, indent=2))}</pre>'
        + '<h2>3. Vulnerability Overview</h2>'
        + _html_table(["Type", "Findings"], [list(v) for v in summary["by_type"].items()])
        + '<h2>4. Risk-Based Prioritization</h2>'
        + _html_table(["Priority", "Count"], [list(v) for v in summary["by_priority"].items()])
        + '<h2>5. Detailed Findings</h2>' + "".join(details)
        + '<h2>6. Remediation Plan</h2><p>Validate at the analyzed commit; address P0, P1, '
        'P2, P3 in order; manually review REVIEW. Use COPILOT-REMEDIATION.md. '
        'Run existing relevant checks and rescan; no source was remediated.</p>'
        + '<h2>7. Scan Integrity</h2>'
        + _html_table(["Scanner", "Status", "Reason"],
                      [[s["scanner"], s["status"], s.get("reason")] for s in summary["scanners"]])
        + f'<pre>{html.escape(text(summary["processing_errors"]))}</pre>'
        + '<p>Static evidence is not proof of exploitability. This is not a penetration test. '
        'Priorities are contextual inferences, not changes to original CVSS.</p></body></html>'
    )


def _csv(output: Path, findings: list[dict[str, Any]]) -> None:
    fields = ["id", "type", "priority", "original_severity", "cvss_score", "title",
              "file", "line", "package", "installed_version", "fixed_version",
              "identifiers", "tools", "risk_factors"]
    with (output / "findings.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for finding in ordered(findings):
            row = {field: text(finding.get(field)) for field in fields}
            writer.writerow({key: "'" + value if value.startswith(("=", "+", "-", "@",
                              "\t", "\r")) else value for key, value in row.items()})
