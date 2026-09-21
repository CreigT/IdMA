"""IdMA — issue, introspect, revoke short-lived scoped agent tokens."""

from __future__ import annotations

import os
import time
import uuid
from typing import Any

import jwt
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="IdMA", version="0.1.0")
SECRET = os.environ.get("IDMA_JWT_SECRET") or os.environ.get("PAMF_JWT_SECRET") or "dev-secret"
BOOTSTRAP = os.environ.get("IDMA_BOOTSTRAP_TOKEN", "owner-dev-token")
ISSUER = "idma"
revoked: set[str] = set()
issued: dict[str, dict[str, Any]] = {}


class IssueRequest(BaseModel):
    agent_id: str
    scopes: list[str] = Field(default_factory=lambda: ["memory:read"])
    ttl_seconds: int = 3600


class RevokeRequest(BaseModel):
    jti: str


def _decode(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"], issuer=ISSUER)
    except jwt.PyJWTError as exc:
        raise HTTPException(401, f"invalid token: {exc}") from exc
    if payload.get("jti") in revoked:
        raise HTTPException(401, "revoked")
    return payload


def _require_issuer(authorization: str | None, bootstrap: str | None) -> None:
    if bootstrap and bootstrap == BOOTSTRAP:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "bearer or bootstrap required")
    claims = _decode(authorization.removeprefix("Bearer ").strip())
    if "identity:issue" not in claims.get("scopes", []) and claims.get("sub") != "owner":
        raise HTTPException(403, "identity:issue required")


@app.get("/v1/identity/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "issuer": ISSUER, "revoked": len(revoked)}


@app.post("/v1/identity/issue")
def issue(
    body: IssueRequest,
    authorization: str | None = Header(default=None),
    x_bootstrap_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_issuer(authorization, x_bootstrap_token)
    if body.ttl_seconds > 86400:
        raise HTTPException(400, "ttl max 86400")
    jti = uuid.uuid4().hex
    now = int(time.time())
    claims = {
        "sub": body.agent_id,
        "scopes": body.scopes,
        "jti": jti,
        "iss": ISSUER,
        "iat": now,
        "exp": now + body.ttl_seconds,
    }
    token = jwt.encode(claims, SECRET, algorithm="HS256")
    issued[jti] = {"agent_id": body.agent_id, "scopes": body.scopes, "exp": claims["exp"]}
    return {"token": token, "jti": jti, "agent_id": body.agent_id, "scopes": body.scopes, "expires_in": body.ttl_seconds}


@app.post("/v1/identity/introspect")
def introspect(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "bearer required")
    claims = _decode(authorization.removeprefix("Bearer ").strip())
    return {
        "active": True,
        "agent_id": claims["sub"],
        "scopes": claims.get("scopes", []),
        "jti": claims.get("jti"),
        "exp": claims.get("exp"),
    }


@app.post("/v1/identity/revoke")
def revoke(
    body: RevokeRequest,
    authorization: str | None = Header(default=None),
    x_bootstrap_token: str | None = Header(default=None),
) -> dict[str, str]:
    _require_issuer(authorization, x_bootstrap_token)
    revoked.add(body.jti)
    return {"status": "revoked", "jti": body.jti}
