"""Intentionally unsafe educational fixture. Nothing runs on import."""

import subprocess


def vulnerable_shell_command(user_input: str) -> subprocess.CompletedProcess[str]:
    """CWE-78: untrusted input becomes shell syntax; never call with real input."""
    return subprocess.run(
        f"echo {user_input}", shell=True, capture_output=True, text=True, check=False
    )
