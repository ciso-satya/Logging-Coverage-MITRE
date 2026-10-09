"""Encryption of connector secrets at rest (Fernet / AES-128-CBC + HMAC)."""
from __future__ import annotations

import os
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from .config import settings


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    key = settings.secret_key
    if not key:
        key_file = settings.data_dir / ".secret_key"
        if key_file.exists():
            key = key_file.read_text().strip()
        else:
            key = Fernet.generate_key().decode()
            key_file.write_text(key)
            try:
                os.chmod(key_file, 0o600)
            except OSError:
                pass
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:  # pragma: no cover - only on key rotation
        raise ValueError("Stored secret cannot be decrypted with the current LCM_SECRET_KEY") from exc
