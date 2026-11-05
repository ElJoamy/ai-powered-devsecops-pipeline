"""Generate and verify a SHA-256 inventory without following artifact symlinks."""

from __future__ import annotations

import hashlib
from pathlib import Path

from common import read_json, utc_now, write_json


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def create_manifest(output: Path) -> None:
    files = []
    for path in sorted(output.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"Artifact contains a symlink: {path.relative_to(output)}")
        if path.is_file() and path != output / "manifest.json":
            files.append({"path": path.relative_to(output).as_posix(),
                          "sha256": digest(path), "bytes": path.stat().st_size})
    write_json(output / "manifest.json", {
        "schema_version": "1.0", "algorithm": "SHA-256", "generated_at": utc_now(),
        "note": "The manifest excludes itself; hashes detect changes, not authenticity.",
        "files": files,
    })


def verify_manifest(output: Path) -> None:
    manifest = read_json(output / "manifest.json")
    expected = set()
    for entry in manifest["files"]:
        relative = Path(entry["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Manifest path escapes artifact directory")
        path = output / relative
        if path.is_symlink() or not path.resolve().is_relative_to(output.resolve()):
            raise ValueError(f"Manifest entry is not contained: {relative}")
        if not path.is_file() or digest(path) != entry["sha256"]:
            raise ValueError(f"Manifest hash mismatch or missing file: {relative}")
        expected.add(relative.as_posix())
    actual = {p.relative_to(output).as_posix() for p in output.rglob("*")
              if p.is_file() and p != output / "manifest.json"}
    if expected != actual:
        raise ValueError("Manifest file inventory does not match artifact directory")
