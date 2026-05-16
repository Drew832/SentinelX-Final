"""Password strength validation aligned with ISO/IEC 27001-style practice."""
from __future__ import annotations

import re

_MIN_LEN = 12
_SPECIAL_RE = re.compile(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/\\~`"\'°§£€]')
_UPPER_RE = re.compile(r"[A-Z]")
_LOWER_RE = re.compile(r"[a-z]")
_DIGIT_RE = re.compile(r"\d")


def validate_password(password: str) -> None:
    """Raise ValueError with a human-readable message if the password is too weak."""
    if not password or len(password) < _MIN_LEN:
        raise ValueError(f"Password must be at least {_MIN_LEN} characters long.")
    if not _UPPER_RE.search(password):
        raise ValueError("Password must include at least one uppercase letter.")
    if not _LOWER_RE.search(password):
        raise ValueError("Password must include at least one lowercase letter.")
    if not _DIGIT_RE.search(password):
        raise ValueError("Password must include at least one digit.")
    if not _SPECIAL_RE.search(password):
        raise ValueError("Password must include at least one special character.")
