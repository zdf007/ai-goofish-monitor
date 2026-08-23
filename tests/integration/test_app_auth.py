from fastapi.testclient import TestClient
import pytest
from starlette.websockets import WebSocketDisconnect

import src.app as app_module


def test_api_requires_server_verified_session(monkeypatch):
    monkeypatch.setattr(app_module.app_settings, "web_username", "test-admin")
    monkeypatch.setattr(app_module.app_settings, "web_password", "test-password")
    monkeypatch.setattr(app_module.app_settings, "web_session_secret", "test-secret")
    monkeypatch.setattr(app_module.app_settings, "web_cookie_secure", False)

    client = TestClient(app_module.app)

    assert client.get("/api/accounts").status_code == 401
    assert client.post(
        "/auth/status",
        json={"username": "test-admin", "password": "wrong"},
    ).status_code == 401

    login_response = client.post(
        "/auth/status",
        json={"username": "test-admin", "password": "test-password"},
    )
    assert login_response.status_code == 200
    assert "HttpOnly" in login_response.headers["set-cookie"]
    assert "SameSite=strict" in login_response.headers["set-cookie"]
    assert client.get("/auth/session").json()["username"] == "test-admin"
    assert client.get("/api/accounts").status_code == 200

    assert client.post("/auth/logout").status_code == 200
    assert client.get("/api/accounts").status_code == 401


def test_websocket_requires_session(monkeypatch):
    monkeypatch.setattr(app_module.app_settings, "web_username", "test-admin")
    monkeypatch.setattr(app_module.app_settings, "web_password", "test-password")
    monkeypatch.setattr(app_module.app_settings, "web_session_secret", "test-secret")

    client = TestClient(app_module.app)
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws"):
            pass
    assert exc_info.value.code == 4401

    login_response = client.post(
        "/auth/status",
        json={"username": "test-admin", "password": "test-password"},
    )
    assert login_response.status_code == 200
    with client.websocket_connect("/ws") as websocket:
        websocket.send_text("ping")
