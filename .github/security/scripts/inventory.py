"""Read-only, scope-aware inventory shared by every scanner."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path, PurePosixPath
from typing import Any

from common import utc_now
from configuration import confined_path, resolve_scan_types

Json = dict[str, Any]
LANGUAGES = {
    ".py": "Python", ".pyi": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".mjs": "JavaScript", ".cjs": "JavaScript", ".ts": "TypeScript",
    ".tsx": "TypeScript", ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin",
    ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".vb": "Visual Basic",
    ".rs": "Rust", ".c": "C", ".h": "C/C++", ".cc": "C++", ".cpp": "C++",
    ".hpp": "C++", ".swift": "Swift", ".scala": "Scala", ".sc": "Scala",
    ".sh": "Shell", ".bash": "Shell", ".ps1": "PowerShell", ".r": "R",
    ".dart": "Dart", ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang",
    ".hs": "Haskell", ".lua": "Lua", ".pl": "Perl", ".clj": "Clojure",
    ".groovy": "Groovy", ".vue": "Vue", ".svelte": "Svelte", ".sol": "Solidity",
}
SNYK_LANGUAGES = {
    "Python", "JavaScript", "TypeScript", "Java", "Kotlin", "Go", "Ruby",
    "PHP", "C#", "Visual Basic", "C", "C++", "C/C++", "Swift", "Scala",
}
MANIFESTS = {
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "bun.lock", "bun.lockb", "requirements.txt", "Pipfile",
    "Pipfile.lock", "poetry.lock", "uv.lock", "pyproject.toml", "setup.py",
    "setup.cfg", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "Gemfile",
    "Gemfile.lock", "composer.json", "composer.lock", "pom.xml", "build.gradle",
    "build.gradle.kts", "gradle.lockfile", "packages.lock.json", "packages.config",
    "pubspec.yaml", "pubspec.lock", "mix.lock", "Package.resolved", "Podfile.lock",
    "conan.lock", "renv.lock", "paket.lock",
}
LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lock", "bun.lockb", "Pipfile.lock", "poetry.lock", "uv.lock", "go.sum",
    "Cargo.lock", "Gemfile.lock", "composer.lock", "gradle.lockfile",
    "packages.lock.json", "pubspec.lock", "mix.lock", "Package.resolved",
    "Podfile.lock", "conan.lock", "renv.lock", "paket.lock",
}
ECOSYSTEMS = {
    "npm": {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
            "pnpm-lock.yaml", "bun.lock", "bun.lockb"},
    "pypi": {"requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock",
             "poetry.lock", "uv.lock", "setup.py", "setup.cfg"},
    "maven": {"pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"},
    "go": {"go.mod", "go.sum"}, "cargo": {"Cargo.toml", "Cargo.lock"},
    "rubygems": {"Gemfile", "Gemfile.lock"}, "composer": {"composer.json", "composer.lock"},
    "nuget": {"packages.lock.json", "packages.config", "paket.lock"},
}


def excluded(relative: str, patterns: list[str]) -> bool:
    """Directory names match at any depth; globs match paths and ancestors."""
    path = PurePosixPath(relative)
    candidates = [path.as_posix()] + [p.as_posix() for p in path.parents if str(p) != "."]
    for pattern in patterns:
        pattern = pattern.rstrip("/")
        if "/" not in pattern and any(fnmatch.fnmatchcase(p, pattern) for p in path.parts):
            return True
        variants = [pattern, pattern[3:]] if pattern.startswith("**/") else [pattern]
        if any(fnmatch.fnmatchcase(item, p) for item in candidates for p in variants):
            return True
    return False


def _walk(repo: Path, config: Json) -> tuple[list[str], list[str]]:
    files: set[str] = set()
    limitations: list[str] = []
    patterns = config["scan"]["exclude"]
    for scope in config["scan"]["paths"]:
        root = confined_path(repo, scope)
        if root.is_file():
            if not excluded(root.relative_to(repo).as_posix(), patterns):
                files.add(root.relative_to(repo).as_posix())
            continue
        def onerror(error: OSError) -> None:
            limitations.append(f"NOT_ASSESSED: cannot enumerate {error.filename}: {error.strerror}")
        for directory, dirs, names in os.walk(root, followlinks=False, onerror=onerror):
            base = Path(directory)
            dirs[:] = _directories(base, dirs, repo, patterns, limitations)
            for name in names:
                path = base / name
                relative = path.relative_to(repo).as_posix()
                if excluded(relative, patterns):
                    continue
                if path.is_symlink() or not path.is_file():
                    limitations.append(f"NOT_ASSESSED: symlink or special file {relative}")
                    continue
                files.add(relative)
    return sorted(files), limitations


def _directories(base: Path, names: list[str], repo: Path, patterns: list[str],
                 limitations: list[str]) -> list[str]:
    allowed: list[str] = []
    for name in names:
        path = base / name
        relative = path.relative_to(repo).as_posix()
        if excluded(relative, patterns):
            continue
        if path.is_symlink():
            limitations.append(f"NOT_ASSESSED: symlink directory {relative}")
        else:
            allowed.append(name)
    return allowed


def _manifest(path: Path) -> bool:
    return (path.name in MANIFESTS or path.name.startswith("requirements")
            and path.suffix in {".txt", ".in"} or path.suffix in {".csproj", ".fsproj", ".vbproj"})


def _iac(repo: Path, relative: str) -> bool:
    path = Path(relative)
    if relative.startswith(".github/workflows/") or path.name in {"action.yml", "action.yaml"}:
        return False
    if path.suffix.lower() in {".tf", ".tfvars", ".hcl", ".bicep"}:
        return True
    if path.name.lower().startswith(("dockerfile", "containerfile")):
        return True
    if path.suffix.lower() not in {".yaml", ".yml", ".json", ".template"}:
        return False
    try:
        with (repo / relative).open(encoding="utf-8", errors="replace") as stream:
            text = stream.read(262144)
    except OSError:
        return False
    markers = ("apiVersion:", "AWSTemplateFormatVersion", '"AWS::', "AWS::",
               "services:", "Resources:", "azure.com/schemas", "jobs:", "kind:")
    return any(marker in text for marker in markers)


def inventory(repo: Path, config: Json) -> Json:
    """Return file-scoped detection, not a claim that every file is assessed."""
    repo = repo.resolve(strict=True)
    files, limitations = _walk(repo, config)
    languages: dict[str, list[str]] = {}
    manifests, iac_files, unsupported = [], [], []
    for relative in files:
        path = Path(relative)
        language = LANGUAGES.get(path.suffix.lower())
        if language:
            languages.setdefault(language, []).append(relative)
        manifest = _manifest(path)
        iac = _iac(repo, relative)
        if manifest:
            manifests.append(relative)
        if iac:
            iac_files.append(relative)
        if (language and language not in SNYK_LANGUAGES
                or not language and not manifest and not iac):
            unsupported.append(relative)
    if unsupported:
        limitations.append("NOT_ASSESSED: unsupported_files has files without a candidate "
                           "scanner, including unsupported languages and GitHub Actions YAML; "
                           "actual tool support is determined at runtime")
    if manifests and not any(Path(p).name in LOCKFILES for p in manifests):
        limitations.append("SCA coverage may be partial: no recognized lockfile; dependencies "
                           "are never installed, built, or resolved by executing repository code")
    limitations.append("Inventory detection is heuristic; scanner support varies by language, "
                       "manifest and IaC format. Unknown files are not implicitly assessed.")
    return {
        "generated_at": utc_now(), "repository": str(repo), "files": files,
        "languages": languages, "manifests": manifests, "iac_files": iac_files,
        "unsupported_files": unsupported, "file_count": len(files),
        "scan_paths": config["scan"]["paths"], "excluded_patterns": config["scan"]["exclude"],
        "selected_scan_types": sorted(resolve_scan_types(config["scan"]["types"])),
        "dependency_ecosystems": sorted({ecosystem for ecosystem, names in ECOSYSTEMS.items()
                                         if any(Path(p).name in names for p in manifests)}),
        "scanners_executed": [], "scanners_skipped": [], "coverage_limitations": limitations,
    }
