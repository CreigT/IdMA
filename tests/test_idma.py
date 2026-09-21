import os

os.environ["IDMA_JWT_SECRET"] = "test-secret"
os.environ["IDMA_BOOTSTRAP_TOKEN"] = "boot"

from fastapi.testclient import TestClient

from src.idma.app import app, revoked

client = TestClient(app)


def setup_function() -> None:
    revoked.clear()


def test_health() -> None:
    assert client.get("/v1/identity/health").json()["status"] == "ok"


def test_issue_introspect_revoke() -> None:
    r = client.post(
        "/v1/identity/issue",
        json={"agent_id": "refund_agent", "scopes": ["memory:write", "memory:read"], "ttl_seconds": 60},
        headers={"X-Bootstrap-Token": "boot"},
    )
    assert r.status_code == 200
    token = r.json()["token"]
    jti = r.json()["jti"]
    i = client.post("/v1/identity/introspect", headers={"Authorization": f"Bearer {token}"})
    assert i.status_code == 200
    assert i.json()["agent_id"] == "refund_agent"
    client.post("/v1/identity/revoke", json={"jti": jti}, headers={"X-Bootstrap-Token": "boot"})
    dead = client.post("/v1/identity/introspect", headers={"Authorization": f"Bearer {token}"})
    assert dead.status_code == 401


def test_issue_without_auth() -> None:
    r = client.post("/v1/identity/issue", json={"agent_id": "x"})
    assert r.status_code == 401
