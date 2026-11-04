import pytest
from fastapi.testclient import TestClient

import app.main as main

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def no_sandbox_binary(monkeypatch):
    monkeypatch.setattr(main, "SANDBOX_BINARY", "/nonexistent/vulnigo-sandbox")
    monkeypatch.setattr(main, "_config_cache", None)


def test_health_reports_ok():
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["service"] == "vulnigo-lite"


def test_health_publishes_no_host_facts():
    # The public URL is not a place to disclose instance names or environment state.
    body = client.get("/health").json()
    assert set(body) == {"status", "service", "version", "uptime_s"}


def test_sandbox_config_reports_failure_instead_of_inventing_limits():
    body = client.get("/sandbox/config").json()
    assert body["available"] is False
    assert "memory" not in body
