"""Bounded public-CVE intelligence. No source, package, or application data leaves."""

from __future__ import annotations

import copy
import json
import logging
import math
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from common import read_json, utc_now, write_json
from normalizer import validate_document
from parsers import array_value, object_value, score

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE = re.compile(r"CVE-\d{4}-\d{4,}\Z")
BATCH_SIZE = 100
MAX_BATCHES = 20
MAX_RESPONSE = 12 * 1024 * 1024
LOGGER = logging.getLogger(__name__)


def _settings(config: dict) -> dict:
    settings = object_value(config.get("intelligence", {}), "config.intelligence")
    enabled = settings.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("config.intelligence.enabled: expected boolean")
    result = {"enabled": enabled}
    for key, default, low, high in (("timeout_seconds", 15, 1, 300),
                                    ("cache_hours", 24, 0, 8760)):
        raw = settings.get(key, default)
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ValueError(f"config.intelligence.{key}: expected number")
        if not math.isfinite(raw) or not low <= raw <= high:
            raise ValueError(f"config.intelligence.{key}: expected value in [{low}, {high}]")
        result[key] = raw
    return result


def _fresh(entry: object, hours: float) -> bool:
    if not isinstance(entry, dict) or not isinstance(entry.get("timestamp"), str):
        return False
    try:
        timestamp = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - timestamp).total_seconds()
        return 0 <= age < hours * 3600
    except (ValueError, TypeError):
        return False


def _load_cache(path: Path) -> dict:
    try:
        if path.stat().st_size > MAX_RESPONSE:
            return {"epss": {}}
        value = read_json(path)
        if isinstance(value, dict) and isinstance(value.get("epss"), dict):
            return value
    except FileNotFoundError:
        return {"epss": {}}
    except (OSError, ValueError) as error:
        LOGGER.warning("Intelligence cache unavailable or invalid: %s", error)
    return {"epss": {}}


def _fetch(url: str, deadline: float) -> dict:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("intelligence total request time budget exhausted")
    request = Request(url, headers={"Accept": "application/json",
                                   "User-Agent": "bounded-security-pipeline/1.0"})
    with urlopen(request, timeout=remaining) as response:
        chunks, size = [], 0
        while True:
            if time.monotonic() >= deadline:
                raise ValueError("intelligence total request time budget exhausted")
            chunk = response.read1(min(65536, MAX_RESPONSE + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_RESPONSE:
                raise ValueError("intelligence response exceeds 12 MiB")
    return object_value(json.loads(b"".join(chunks)), "intelligence response")


def _epss_batch(cves: list[str], deadline: float) -> dict:
    document = _fetch(EPSS_URL + "?" + urlencode({"cve": ",".join(cves)}), deadline)
    if document.get("status") != "OK":
        raise ValueError("FIRST EPSS response does not declare OK status")
    values = {}
    for raw in array_value(document.get("data"), "FIRST EPSS data"):
        row = object_value(raw, "FIRST EPSS record")
        identifier = row.get("cve")
        if not isinstance(identifier, str) or identifier not in cves or identifier in values:
            raise ValueError("FIRST EPSS response contains unexpected/duplicate CVE")
        probability = score(row.get("epss"), "FIRST EPSS probability", 1)
        if probability is None:
            raise ValueError("FIRST EPSS response has missing probability")
        values[identifier] = {"value": probability, "timestamp": utc_now(),
                              "date": row.get("date"), "source": EPSS_URL}
    return values


def _kev_feed(deadline: float) -> dict:
    document = _fetch(KEV_URL, deadline)
    vulnerabilities = array_value(document.get("vulnerabilities"), "CISA KEV vulnerabilities")
    # An empty/mismatched feed must not turn every vulnerability into KEV=false.
    if not vulnerabilities or document.get("count") != len(vulnerabilities):
        raise ValueError("CISA KEV response has empty or inconsistent catalog")
    ids = []
    for raw in vulnerabilities:
        identifier = object_value(raw, "CISA KEV record").get("cveID")
        if not isinstance(identifier, str) or not CVE.fullmatch(identifier):
            raise ValueError("CISA KEV response contains invalid CVE")
        ids.append(identifier)
    return {"value": sorted(set(ids)), "timestamp": utc_now(), "source": KEV_URL,
            "catalog_version": document.get("catalogVersion")}


def _entry(value: object, source: str, status: str, timestamp: str | None = None,
           limitation: str | None = None) -> dict:
    return {"value": value, "status": status, "source": source, "observed_at": timestamp,
            "limitations": [limitation] if limitation else []}


def _cached_epss(cache: dict, cve: str, hours: float) -> dict | None:
    cached = cache["epss"].get(cve)
    if not _fresh(cached, hours):
        return None
    try:
        value = score(cached.get("value"), "cached EPSS", 1)
    except ValueError:
        return None
    if value is None:
        return None
    return _entry(value, EPSS_URL, "CACHED", cached["timestamp"])


def _collect_epss(cves: list[str], cache: dict, settings: dict, deadline: float) -> dict:
    results = {}
    pending = []
    for cve in cves:
        cached = _cached_epss(cache, cve, settings["cache_hours"])
        if cached:
            results[cve] = cached
        else:
            pending.append(cve)
    for offset in range(0, min(len(pending), BATCH_SIZE * MAX_BATCHES), BATCH_SIZE):
        batch = pending[offset:offset + BATCH_SIZE]
        try:
            values = _epss_batch(batch, deadline)
            cache["epss"].update(values)
            for cve, value in values.items():
                results[cve] = _entry(value["value"], EPSS_URL, "AVAILABLE", value["timestamp"])
        except (OSError, ValueError, TimeoutError):
            # Avoid repeatedly contacting an offline or rate-limited endpoint.
            break
    for cve in cves:
        results.setdefault(cve, _entry(None, EPSS_URL, "UNAVAILABLE",
                                      limitation="EPSS absent, request failed, or bounded budget exhausted."))
    return results


def _collect_kev(cache: dict, settings: dict, deadline: float) -> tuple[dict | None, str]:
    cached = cache.get("kev")
    if _fresh(cached, settings["cache_hours"]):
        ids = cached.get("value")
        if (isinstance(ids, list) and ids
                and all(isinstance(item, str) and CVE.fullmatch(item) for item in ids)):
            return cached, "CACHED"
    try:
        cached = _kev_feed(deadline)
        cache["kev"] = cached
        return cached, "AVAILABLE"
    except (OSError, ValueError, TimeoutError):
        return None, "UNAVAILABLE"


def _source_summary(entries: dict, source: str, default_status: str) -> dict:
    statuses = {entry["status"] for entry in entries.values()}
    if not entries:
        status = default_status
    elif statuses <= {"AVAILABLE", "CACHED"}:
        status = "CACHED" if statuses == {"CACHED"} else "AVAILABLE"
    elif len(statuses) == 1:
        status = next(iter(statuses))
    else:
        status = "PARTIAL"
    return {"status": status, "source": source, "cves": entries,
            "limitations": sorted({note for entry in entries.values()
                                    for note in entry["limitations"]})}


def _attach(row: dict, epss: dict, kev: dict, enabled: bool) -> dict:
    cves = sorted({identifier for identifier in row["identifiers"] if CVE.fullmatch(identifier)})
    default = "NOT_APPLICABLE" if not cves else "DISABLED"
    epss_entries = {cve: epss.get(cve, _entry(None, EPSS_URL, default,
                                           limitation="Intelligence disabled.")) for cve in cves}
    kev_entries = {cve: kev.get(cve, _entry(None, KEV_URL, default,
                                         limitation="Intelligence disabled.")) for cve in cves}
    probabilities = [entry["value"] for entry in epss_entries.values() if entry["value"] is not None]
    kev_values = [entry["value"] for entry in kev_entries.values()]
    row["epss_probability"] = max(probabilities) if probabilities else None
    row["kev_listed"] = (True if True in kev_values else
                         False if kev_values and all(v is False for v in kev_values) else None)
    row["intelligence"] = {
        "enabled": enabled, "epss": _source_summary(epss_entries, EPSS_URL, default),
        "kev": _source_summary(kev_entries, KEV_URL, default),
        "limitations": ["EPSS is population-level probability, not application reachability.",
                        "Absence from KEV is not evidence that exploitation is impossible."],
    }
    return row


def enrich(findings: list[dict], config: dict, cache: Path) -> list[dict]:
    """Return enriched copies. Cache is a directory; a failed refresh is unknown."""
    validate_document({"schema_version": "1.0", "findings": findings})
    settings = _settings(config)
    cves = sorted({identifier for row in findings for identifier in row["identifiers"]
                   if CVE.fullmatch(identifier)})
    epss, kev = {}, {}
    if settings["enabled"] and cves:
        path = Path(cache) / "intelligence-cache.json"
        store = _load_cache(path)
        deadline = time.monotonic() + settings["timeout_seconds"]
        # KEV gets a separate half-budget so EPSS cannot starve this independent source.
        epss = _collect_epss(cves, store, settings,
                             time.monotonic() + settings["timeout_seconds"] / 2)
        feed, status = _collect_kev(store, settings, deadline)
        listed = set(feed["value"]) if feed else set()
        kev = {cve: _entry(cve in listed if feed else None, KEV_URL, status,
                           feed["timestamp"] if feed else None,
                           None if feed else "KEV unavailable; no negative membership inference.")
               for cve in cves}
        try:
            write_json(path, store)
        except OSError:
            for entry in (*epss.values(), *kev.values()):
                entry["limitations"].append("Intelligence cache could not be persisted.")
    return [_attach(copy.deepcopy(row), epss, kev, settings["enabled"]) for row in findings]
