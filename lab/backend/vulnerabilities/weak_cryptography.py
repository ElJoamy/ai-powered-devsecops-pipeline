"""Intentionally unsafe educational fixtures, not real authentication code."""

import hashlib


def vulnerable_md5_digest(value: str) -> str:
    """CWE-327: MD5 is unsuitable for cryptographic integrity or passwords."""
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def vulnerable_fictional_password() -> str:
    """CWE-798: fictional demonstration only; not a credential for any system."""
    password = "FICTIONAL_LAB_ONLY_NOT_A_REAL_PASSWORD"
    return password
