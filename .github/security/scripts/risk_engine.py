"""Versioned first-match risk decisions, never a weighted or altered severity."""

from __future__ import annotations

import copy
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from common import read_json
from normalizer import SCHEMAS, validate_document
from parsers import object_value, score

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "config" / "risk-policy.yaml"


def _policy(path: Path | None) -> dict:
    target = Path(path) if path is not None else DEFAULT_POLICY
    try:
        if target.stat().st_size > 65536:
            raise ValueError("policy exceeds 64 KiB")
        document = yaml.safe_load(target.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError, ValueError) as exc:
        raise ValueError(f"risk policy {target}: cannot load policy: {exc}") from exc
    schema = read_json(SCHEMAS / "risk-policy.schema.json")
    errors = list(Draft202012Validator(schema).iter_errors(document))
    if errors:
        error = errors[0]
        where = ".".join(str(item) for item in error.absolute_path) or "<root>"
        raise ValueError(f"risk policy {where}: {error.message}")
    if document["critical_cvss"] < document["high_cvss"]:
        raise ValueError("risk policy critical_cvss must be >= high_cvss")
    return document


def _context(config: dict) -> dict:
    application = object_value(config.get("application", {}), "config.application")
    context = {key: application.get(key, "UNKNOWN") for key in
               ("environment", "business_criticality", "data_sensitivity")}
    for key, value in context.items():
        if not isinstance(value, str):
            raise ValueError(f"config.application.{key}: expected string")
    context["internet_exposed"] = application.get("internet_exposed")
    if context["internet_exposed"] is not None and not isinstance(context["internet_exposed"], bool):
        raise ValueError("config.application.internet_exposed: expected boolean or null")
    controls = application.get("compensating_controls", [])
    if not isinstance(controls, list) or not all(isinstance(item, str) for item in controls):
        raise ValueError("config.application.compensating_controls: expected string array")
    context["compensating_controls"] = controls
    return context


def _technical_band(row: dict, policy: dict) -> str:
    number = score(row.get("cvss_score"), "finding.cvss_score")
    if number is not None:
        if number >= policy["critical_cvss"]:
            return "CRITICAL"
        if number >= policy["high_cvss"]:
            return "HIGH"
        return "MEDIUM" if number >= 4 else "LOW"
    original = row["original_severity"].upper()
    original = {"ERROR": "HIGH", "WARNING": "MEDIUM", "NOTE": "LOW",
                "MODERATE": "MEDIUM"}.get(original, original)
    return original if original in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "UNKNOWN"


def _decision(row: dict, context: dict, policy: dict) -> tuple[str, str, list[str]]:
    band = _technical_band(row, policy)
    factors = [f"Technical assessment basis: {band}; original severity preserved."]
    epss = score(row.get("epss_probability"), "finding.epss_probability", 1)
    kev = row.get("kev_listed")
    if kev is not None and not isinstance(kev, bool):
        raise ValueError("finding.kev_listed: expected boolean or null")
    if kev is True:
        return "CRITICAL", "kev_priority", factors + ["Public CVE is listed in CISA KEV."]
    if band == "CRITICAL":
        return band, "critical_priority", factors + ["Critical technical severity threshold met."]
    if band == "HIGH":
        return band, "high_priority", factors + ["High technical severity threshold met."]
    if epss is not None and epss >= policy["epss_high"]:
        return "HIGH", "high_priority", factors + ["EPSS meets configured high-probability threshold."]
    sensitive = context["data_sensitivity"].upper() in {"HIGH", "CONFIDENTIAL", "RESTRICTED"}
    critical = context["business_criticality"].upper() in {"HIGH", "CRITICAL"}
    if band == "MEDIUM" and context["internet_exposed"] is True and (sensitive or critical):
        return "HIGH", "high_priority", factors + [
            "Medium technical risk in explicitly internet-exposed, high-impact application."]
    key = {"MEDIUM": "medium_priority", "LOW": "low_priority"}.get(band, "unknown_priority")
    return band, key, factors


def _limitations(row: dict, context: dict) -> list[str]:
    notes = [
        "Contextual risk is a deterministic triage decision, not proof of exploitability.",
        "No transitive dependency or execution-path relationship is inferred.",
    ]
    if row.get("reachability", "UNKNOWN") == "UNKNOWN":
        notes.append("Reachability is UNKNOWN; no explicit tool reachability evidence.")
    if row["cvss_score"] is None:
        notes.append("CVSS unavailable; original severity is used when recognized.")
    if any(value in {None, "UNKNOWN"} for key, value in context.items()
           if key != "compensating_controls"):
        notes.append("Application context is incomplete.")
    if context["compensating_controls"]:
        notes.append("Declared compensating controls are unverified and do not lower risk.")
    intelligence = row.get("intelligence", {})
    for source in ("epss", "kev"):
        details = intelligence.get(source, {})
        if details.get("status") not in {"AVAILABLE", "CACHED", "NOT_APPLICABLE"}:
            notes.append(f"{source.upper()} intelligence unavailable, disabled, or partial.")
        notes.extend(details.get("limitations", []))
    return sorted(set(notes))


def _assess_one(raw: dict, context: dict, policy: dict) -> dict:
    row = copy.deepcopy(raw)
    band, key, factors = _decision(row, context, policy)
    limitations = _limitations(row, context)
    confidence = "LOW" if band == "UNKNOWN" else "MEDIUM"
    if row.get("kev_listed") is True:
        confidence = "HIGH"
    row.update({
        "contextual_risk": band, "priority": policy["rules"][key],
        "risk_factors": factors, "confidence": confidence,
        "limitations": sorted(set(row.get("limitations", []) + limitations)),
    })
    row["evidence"].append({
        "risk_policy_version": policy["version"], "matched_rule": key,
        "thresholds": {name: policy[name] for name in
                       ("epss_high", "critical_cvss", "high_cvss")},
        "application_context": context,
        "confidence_scope": "Confidence in triage decision, not exploitability assurance.",
    })
    return row


def assess(findings: list[dict], config: dict, policy_path: Path | None = None) -> list[dict]:
    """Assess enriched or normalized findings without mutating original severity."""
    validate_document({"schema_version": "1.0", "findings": findings})
    policy = _policy(policy_path)
    context = _context(config)
    results = [_assess_one(row, context, policy) for row in findings]
    validate_document({"schema_version": "1.0", "findings": results}, "risk.schema.json")
    return results
