"""Web console session signing and verification helpers."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


SESSION_COOKIE_NAME = "xianyu_session"


def derive_session_secret(
    username: str,
    password: str,
    configured_secret: str | None = None,
) -> bytes:
    """Build a stable signing key without storing the web password in a cookie."""
    seed = configured_secret or f"{username}\0{password}"
    return hashlib.sha256(f"ai-goofish-session-v1\0{seed}".encode("utf-8")).digest()


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def create_session_token(
    username: str,
    secret: bytes,
    *,
    ttl_seconds: int,
    now: int | None = None,
) -> str:
    issued_at = int(time.time() if now is None else now)
    payload = {
        "sub": username,
        "iat": issued_at,
        "exp": issued_at + ttl_seconds,
    }
    payload_segment = _encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signature = hmac.new(secret, payload_segment.encode("ascii"), hashlib.sha256).digest()
    return f"{payload_segment}.{_encode(signature)}"


def verify_session_token(
    token: str | None,
    expected_username: str,
    secret: bytes,
    *,
    now: int | None = None,
) -> bool:
    if not token:
        return False

    try:
        payload_segment, signature_segment = token.split(".", 1)
        expected_signature = hmac.new(
            secret,
            payload_segment.encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(_decode(signature_segment), expected_signature):
            return False

        payload = json.loads(_decode(payload_segment))
        expires_at = int(payload["exp"])
        current_time = int(time.time() if now is None else now)
        return payload.get("sub") == expected_username and expires_at > current_time
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False
