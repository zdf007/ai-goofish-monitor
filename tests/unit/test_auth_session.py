from src.core.auth import (
    create_session_token,
    derive_session_secret,
    verify_session_token,
)


def test_session_token_round_trip_and_expiry():
    secret = derive_session_secret("admin", "password", "configured-secret")
    token = create_session_token("admin", secret, ttl_seconds=60, now=1000)

    assert verify_session_token(token, "admin", secret, now=1059) is True
    assert verify_session_token(token, "admin", secret, now=1060) is False


def test_session_token_rejects_tampering_and_other_users():
    secret = derive_session_secret("admin", "password")
    token = create_session_token("admin", secret, ttl_seconds=60, now=1000)
    payload, signature = token.split(".", 1)

    assert verify_session_token(f"{payload}x.{signature}", "admin", secret, now=1001) is False
    assert verify_session_token(token, "other", secret, now=1001) is False
    assert verify_session_token(token, "admin", b"wrong-secret", now=1001) is False
    assert verify_session_token(None, "admin", secret, now=1001) is False
