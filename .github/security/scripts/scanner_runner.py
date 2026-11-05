"""Real CLI adapters: explicit coverage, isolated scope, and validated artifacts."""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from common import read_json, redact
from configuration import resolve_scan_types, validate_config
from inventory import SNYK_LANGUAGES, inventory as discover
from parsers import parse_snyk

Json = dict[str, Any]
SCANNERS = (("snyk-sast", "SAST"), ("trivy-sca", "SCA"), ("trivy-iac", "IaC"))
LOGGER = logging.getLogger(__name__)


def _record(scanner: str, kind: str) -> Json:
    return {"scanner": scanner, "type": kind, "status": "FAILED", "reason": "",
            "version": None, "exit_code": None, "json_path": None, "sarif_path": None}


def _environment(scanner: str) -> dict[str, str]:
    # Do not inherit scanner flags, plugin paths, proxy hooks or repo-controlled config.
    keys = ("PATH", "HOME", "TMPDIR", "TEMP", "TMP", "SSL_CERT_FILE",
            "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY")
    env = {key: os.environ[key] for key in keys if key in os.environ}
    env.update({"CI": "true", "NO_COLOR": "1", "SNYK_DISABLE_ANALYTICS": "1"})
    if scanner == "snyk-sast":
        for key in ("SNYK_TOKEN", "SNYK_ORG", "SNYK_IMAGE"):
            value = os.environ.get(key)
            if value:
                env[key] = value
    return env


def _failure_reason(code: int, stdout: str, stderr: str) -> str:
    message = stdout.strip() or stderr.strip()
    if stdout.lstrip().startswith("{"):
        try:
            document = json.loads(stdout)
        except json.JSONDecodeError as error:
            LOGGER.warning("Scanner returned malformed JSON diagnostics: %s", error.msg)
        else:
            if isinstance(document, dict) and isinstance(document.get("error"), str):
                message = document["error"]
    message = redact(message)
    reason = f"CLI exited with code {code}"
    if message:
        reason += f": {message[:2000]}"
    if "Snyk Code is not supported for your current organization" in message:
        reason += (
            " Personal Snyk accounts also use a workspace (Organization); no GitHub "
            "organization is required. Without --org, the CLI uses the account's "
            "preferred workspace. Check that same workspace in Settings > Snyk Code. "
            "If Code is already enabled in another workspace, select it using "
            "SNYK_ORG (Secret or Variable) or the snyk-org input."
        )
    return reason


def _command(argv: list[str], cwd: Path, timeout: int, env: dict[str, str],
             log: Path, stdout_path: Path | None = None,
             cleanup: list[str] | None = None) -> tuple[int | None, str]:
    """Execute without a shell; only sanitized diagnostics are persisted."""
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True,
                                text=True, errors="replace", timeout=timeout, check=False)
        code = result.returncode
        text = f"exit_code={code}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        reason = "" if code in (0, 1) else _failure_reason(code, result.stdout, result.stderr)
        if stdout_path is not None and not stdout_path.exists() and result.stdout.strip():
            stdout_path.write_text(result.stdout, encoding="utf-8")
    except subprocess.TimeoutExpired as exc:
        code = None
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr
        text = f"Timed out after {timeout}s\n{stdout or ''}\n{stderr or ''}"
        reason = f"Scanner timed out after {timeout} seconds"
        if cleanup is not None:
            try:
                removed = subprocess.run(cleanup, env=env, capture_output=True, text=True,
                                         timeout=30, check=False)
                text += f"\nContainer cleanup exit={removed.returncode}\n{removed.stderr}"
                if removed.returncode != 0:
                    reason += "; container cleanup failed, see scanner log"
            except (OSError, subprocess.TimeoutExpired) as cleanup_error:
                reason += "; container cleanup could not complete"
                text += f"\nContainer cleanup error: {cleanup_error}"
    except OSError as exc:
        code, text, reason = None, str(exc), f"Scanner could not start: {exc.strerror}"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(redact(text), encoding="utf-8")
    return code, reason


def _copy_file(repo: Path, relative: str, stage: Path) -> None:
    parts = Path(relative).parts
    if Path(relative).is_absolute() or ".." in parts:
        raise ValueError(f"Refusing unsafe inventory path: {relative}")
    directory = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError(f"Refusing nonregular source: {relative}")
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as target:
            shutil.copyfileobj(source, target)
        destination.chmod(0o600)


def _stage(repo: Path, output: Path, config: Json, inv: Json, stage: Path) -> None:
    scoped = copy.deepcopy(config)
    if output.is_relative_to(repo):
        scoped["scan"]["exclude"].append(output.relative_to(repo).as_posix())
    current = discover(repo, scoped)
    # Re-enumeration enforces current configuration rather than trusting supplied paths.
    inv["files"] = current["files"]
    inv["file_count"] = current["file_count"]
    for key in ("languages", "manifests", "iac_files", "unsupported_files"):
        inv[key] = current[key]
    for item in current["coverage_limitations"]:
        if item not in inv["coverage_limitations"]:
            inv["coverage_limitations"].append(item)
    for relative in current["files"]:
        if Path(relative).name == ".snyk":
            inv["coverage_limitations"].append(
                f"Scanner policy file {relative} excluded to prevent target-controlled suppression")
            continue
        _copy_file(repo, relative, stage)


def _sarif(document: Any) -> None:
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise ValueError("Expected SARIF 2.1.0 document")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("SARIF document has no scanner run")
    for run in runs:
        if not isinstance(run, dict):
            raise ValueError("Invalid SARIF run")
        tool = run.get("tool")
        driver = tool.get("driver", {}) if isinstance(tool, dict) else {}
        if not isinstance(driver, dict) or not isinstance(driver.get("name"), str):
            raise ValueError("SARIF document has no tool identity")
        if not isinstance(run.get("results", []), list):
            raise ValueError("SARIF results must be an array")
        if any(not isinstance(item, dict) or not isinstance(item.get("message"), dict)
               for item in run.get("results", [])):
            raise ValueError("Invalid SARIF result")
        for notification in run.get("invocations", []):
            if notification.get("executionSuccessful") is False:
                raise ValueError("SARIF reports unsuccessful execution")


def _trivy_json(document: Any) -> None:
    if not isinstance(document, dict) or document.get("SchemaVersion") != 2:
        raise ValueError("Expected Trivy SchemaVersion 2 JSON")
    if not isinstance(document.get("ArtifactName"), str):
        raise ValueError("Trivy document is missing ArtifactName")
    if not isinstance(document.get("ArtifactType"), str):
        raise ValueError("Trivy document is missing ArtifactType")
    results = document.get("Results", [])
    if not isinstance(results, list):
        raise ValueError("Trivy Results must be an array")
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("Target"), str):
            raise ValueError("Invalid Trivy result")
        for key in ("Vulnerabilities", "Misconfigurations"):
            entries = result.get(key)
            if entries is not None and (
                not isinstance(entries, list) or any(not isinstance(v, dict) for v in entries)
            ):
                raise ValueError(f"Invalid Trivy {key}")


def _enabled(record: Json, config: Json, inv: Json) -> bool:
    kind = record["type"]
    key = {"SAST": "sast", "SCA": "dependencies", "IaC": "iac"}[kind]
    if key not in resolve_scan_types(config["scan"]["types"]):
        record.update(status="SKIPPED", reason="Not selected in scan.types")
    elif kind == "SAST" and not os.environ.get("SNYK_TOKEN"):
        record.update(status="SKIPPED", reason="SNYK_TOKEN is not configured")
    elif kind == "SAST" and not any(lang in SNYK_LANGUAGES for lang in inv["languages"]):
        record.update(status="NOT_APPLICABLE", reason="No candidate Snyk Code language in scope")
    elif kind == "SCA" and not inv["manifests"]:
        record.update(status="NOT_APPLICABLE", reason="No dependency manifests detected in scope")
    elif kind == "IaC" and not inv["iac_files"]:
        record.update(status="NOT_APPLICABLE", reason="No candidate IaC files detected in scope")
    else:
        return True
    return False


def _snyk_container(binary: str, stage: Path, output: Path,
                    env: dict[str, str]) -> tuple[list[str], list[str]]:
    image = env.get("SNYK_IMAGE", "")
    if not re.fullmatch(r"snyk/snyk:linux@sha256:[a-f0-9]{64}", image):
        raise ValueError("SNYK_IMAGE must pin the official snyk/snyk:linux image by digest")
    name = f"security-snyk-{uuid.uuid4().hex}"
    command = [
        binary, "run", "--rm", "--pull=never", "--name", name,
        "--entrypoint", "/usr/local/bin/snyk",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--mount", f"type=bind,source={stage},target=/project,readonly",
        "--mount", f"type=bind,source={output},target=/reports",
        "--workdir", "/project", "-e", "SNYK_TOKEN",
        "-e", "HOME=/tmp", "-e", "CI=true", "-e", "SNYK_DISABLE_ANALYTICS=1",
        image,
    ]
    return command, [binary, "rm", "--force", name]


def _version(binary: str, scanner: str, stage: Path, output: Path,
             timeout: int, env: dict[str, str]) -> str | None:
    command, cleanup = ([binary, "version"], None)
    if scanner == "snyk-sast":
        command, cleanup = _snyk_container(binary, stage, output, env)
        command.append("--version")
    log = output / "logs" / f"{scanner}-version.log"
    code, _ = _command(command, stage, min(timeout, 30), env, log, cleanup=cleanup)
    if code != 0:
        return None
    return log.read_text(encoding="utf-8").split("stdout:\n", 1)[-1].split(
        "\nstderr:", 1)[0].strip()[:1000]


def _snyk_export(binary: str, record: Json, stage: Path, output: Path, config: Json,
                 env: dict[str, str], fmt: str) -> bool:
    scanner = record["scanner"]
    timeout = config["scan"]["timeout_seconds"]
    org = (config["scan"]["snyk_org"] or env.get("SNYK_ORG") or "").strip()
    options = [f"--org={org}"] if org else []
    if fmt == "json":
        LOGGER.info("Snyk Code context: %s", "explicit Snyk workspace" if org
                    else "token account's preferred workspace")
    destination = output / "raw" / f"{scanner}.{fmt}"
    command, cleanup = _snyk_container(binary, stage, output, env)
    container_report = f"/reports/raw/{scanner}.{fmt}"
    command += ["code", "test", ".", *options,
                f"--{fmt}", f"--{fmt}-file-output={container_report}"]
    code, reason = _command(command, stage, timeout, env,
                            output / "logs" / f"{scanner}-{fmt}.log", destination, cleanup)
    record["exit_code"] = code
    if code == 3:
        record.update(status="NOT_APPLICABLE", reason="Snyk reports no supported project")
        return False
    if code not in (0, 1):
        record["reason"] = reason or "Snyk failed to analyze source"
        return False
    if fmt == "json" and code == 0 and not destination.exists():
        record["json_export"] = "OMITTED_BY_SNYK_ON_ZERO_FINDINGS"
        return True
    document = read_json(destination)
    if fmt == "json":
        parse_snyk(document, destination.name)
    else:
        _sarif(document)
    return True


def _snyk(binary: str, record: Json, stage: Path, output: Path, config: Json,
          env: dict[str, str]) -> None:
    for fmt in ("json", "sarif"):
        if not _snyk_export(binary, record, stage, output, config, env, fmt):
            return
    if record.get("json_export") == "OMITTED_BY_SNYK_ON_ZERO_FINDINGS":
        sarif = output / "raw" / f"{record['scanner']}.sarif"
        document = read_json(sarif)
        if any(run.get("results", []) for run in document["runs"]):
            raise ValueError("Snyk exports disagree: JSON reported zero but SARIF has findings")
        # SARIF is JSON: preserve the native bytes, never synthesize an empty result.
        shutil.copyfile(sarif, output / "raw" / f"{record['scanner']}.json")
        record["json_export"] = "NATIVE_SARIF_JSON; original JSON export omitted by Snyk"
        LOGGER.warning("Snyk omitted zero-finding JSON; preserving validated native SARIF JSON")
    record.update(status="COMPLETED", reason="Snyk Code Docker JSON and SARIF validated")


def _trivy(binary: str, record: Json, stage: Path, output: Path, config: Json,
           env: dict[str, str], controls: Path) -> None:
    scanner, kind = record["scanner"], record["type"]
    timeout = config["scan"]["timeout_seconds"]
    json_path = output / "raw" / f"{scanner}.json"
    sarif_path = output / "raw" / f"{scanner}.sarif"
    command = [binary, "--config", str(controls / "trivy.yaml")]
    command += ["fs", "--scanners", "vuln"] if kind == "SCA" else ["config"]
    command += ["--ignorefile", str(controls / "empty.ignore"), "--exit-code", "0",
                "--timeout", f"{timeout}s", "--format", "json", "--output",
                str(json_path), "."]
    code, reason = _command(command, stage, timeout, env,
                            output / "logs" / f"{scanner}-json.log")
    record["exit_code"] = code
    if code != 0:
        record["reason"] = reason or f"Trivy scan exited with code {code}"
        return
    _trivy_json(read_json(json_path))
    command = [binary, "--config", str(controls / "trivy.yaml"), "convert",
               "--format", "sarif", "--output", str(sarif_path), str(json_path)]
    code, reason = _command(command, stage, timeout, env,
                            output / "logs" / f"{scanner}-sarif.log")
    record["exit_code"] = code
    if code != 0:
        record["reason"] = reason or f"Trivy SARIF conversion exited with code {code}"
        return
    _sarif(read_json(sarif_path))
    record.update(status="COMPLETED", reason="Trivy JSON scan and SARIF conversion validated")


def _prepare_output(output: Path, records: list[Json]) -> None:
    """Reject pre-existing report symlinks before tools can follow them."""
    output.mkdir(parents=True, exist_ok=True)
    for folder in ("raw", "logs"):
        directory = output / folder
        if directory.is_symlink():
            raise ValueError(f"Report {folder} directory must not be a symlink")
        directory.mkdir(exist_ok=True)
    for record in records:
        scanner = record["scanner"]
        paths = [output / "raw" / f"{scanner}.{suffix}" for suffix in ("json", "sarif")]
        paths += [output / "logs" / f"{scanner}-{name}.log"
                  for name in ("json", "sarif", "version")]
        for path in paths:
            if path.exists() or path.is_symlink():
                if path.is_symlink() or not path.is_file():
                    raise ValueError(f"Report path must be a regular file: {path.name}")
                path.unlink()


def _execute(record: Json, repo: Path, stage: Path, output: Path, config: Json,
             controls: Path) -> None:
    scanner = record["scanner"]
    binary = shutil.which("docker" if scanner == "snyk-sast" else "trivy")
    if not binary:
        record["reason"] = "Required scanner executable is not installed"
        return
    if Path(binary).resolve().is_relative_to(repo):
        record["reason"] = "Refusing scanner executable located inside target repository"
        return
    env = _environment(scanner)
    try:
        if scanner == "snyk-sast":
            record.update(execution="docker", container_image=env.get("SNYK_IMAGE"))
        record["version"] = _version(binary, scanner, stage, output,
                                     config["scan"]["timeout_seconds"], env)
        if record["version"] is None:
            record["reason"] = "Scanner version probe failed; see sanitized version log"
            return
        if scanner == "snyk-sast":
            _snyk(binary, record, stage, output, config, env)
        else:
            _trivy(binary, record, stage, output, config, env, controls)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        record.update(status="FAILED", reason=redact(f"Invalid/missing scanner output: {exc}"))
    if record["status"] == "COMPLETED":
        record.update(json_path=f"raw/{scanner}.json", sarif_path=f"raw/{scanner}.sarif")
    else:
        # Partial reports never masquerade as usable artifacts.
        for suffix in ("json", "sarif"):
            (output / "raw" / f"{scanner}.{suffix}").unlink(missing_ok=True)


def _coverage(records: list[Json], inv: Json) -> None:
    inv["scanners_executed"] = [r["scanner"] for r in records
                                if r["status"] in {"COMPLETED", "FAILED"}]
    inv["scanners_skipped"] = [{"scanner": r["scanner"], "reason": r["reason"],
                               "status": r["status"]} for r in records
                              if r["status"] in {"SKIPPED", "NOT_APPLICABLE"}]
    inv["coverage"] = {
        "scanners": {r["scanner"]: r["status"] for r in records},
        "dependency_manifests": inv.get("manifests", []),
        "iac_candidates": inv.get("iac_files", []),
        "unsupported_files": inv.get("unsupported_files", []),
        "note": "Detected candidates are not proof that every dependency or file was analyzed.",
    }
    for record in records:
        if record["status"] != "COMPLETED":
            inv["coverage_limitations"].append(
                f"NOT_ASSESSED: {record['scanner']}: {record['status']}: {record['reason']}")
    inv["coverage_limitations"].append(
        "COMPLETED means tool execution and document validation, not full language or "
        "dependency coverage. Trivy does not install target dependencies.")


def run_scanners(repo: Path, output: Path, config: Json, inventory: Json) -> list[Json]:
    """Run real scanners against a filtered temporary copy; mutate coverage in place."""
    repo, output = repo.resolve(strict=True), output.resolve()
    config = validate_config(config, repo)
    if output == repo or repo.is_relative_to(output):
        raise ValueError("Reports root must not contain or equal the target repository")
    inventory.setdefault("coverage_limitations", [])
    records = [_record(scanner, kind) for scanner, kind in SCANNERS]
    _prepare_output(output, records)
    with tempfile.TemporaryDirectory(prefix="security-scan-") as directory:
        controls = Path(directory)
        stage = controls / "source"
        stage.mkdir()
        (controls / "trivy.yaml").write_text("{}\n", encoding="utf-8")
        (controls / "empty.ignore").write_text("", encoding="utf-8")
        try:
            _stage(repo, output, config, inventory, stage)
        except (OSError, ValueError) as exc:
            for record in records:
                record["reason"] = redact(f"Safe source staging failed: {exc}")
            _coverage(records, inventory)
            return records
        for record in records:
            if _enabled(record, config, inventory):
                _execute(record, repo, stage, output, config, controls)
    _coverage(records, inventory)
    return records
