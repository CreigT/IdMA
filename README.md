# Day 2 — Identity Management Agent (IdMA)

Zero-trust tokens for the control plane. PAMF ACLs are paper until this is on.

**Doctrine:** motion by default. Review only on over-cap and irreversible.  
Issuing a new agent identity is gated. Using a valid scoped token is not.

## Purpose
Give every agent a workload name, short-lived token, and explicit scopes. No shared god key on the mesh.

## Contracts

Issue (owner or identity:issue scope):

```
POST /v1/identity/issue
{"agent_id":"refund_agent","scopes":["memory:write","memory:read"],"ttl_seconds":3600}
```

Introspect:

```
POST /v1/identity/introspect
Authorization: Bearer <token>
```

Revoke:

```
POST /v1/identity/revoke
{"jti":"..."}
```

Token claims: `sub` (agent_id), `scopes`, `jti`, `exp`, `iss=idma`.

## PAMF wiring
Set on PAMF:

```
PAMF_REQUIRE_AUTH=1
PAMF_JWT_SECRET=<same secret as IdMA>
```

Write needs `memory:write`. Query needs `memory:read`. Freeze needs `memory:freeze`. Forget needs `memory:forget`.

## Run

```bash
pip install -r requirements.txt
IDMA_BOOTSTRAP_TOKEN=owner-dev-token IDMA_JWT_SECRET=dev-secret \
  uvicorn src.idma.app:app --port 8090
```

Bootstrap header: `X-Bootstrap-Token: owner-dev-token` for first issue only.

## Not this week
SPIFFE/SPIRE, mTLS certs, OIDC. JWT + revoke list is the stand-in. Swap issuer later without changing PAMF scope names.

## Sequence
1. PAMF → Postgres (shipped)
2. **IdMA ← you are here**
3. Event Trigger Agent
4. Governance + Warden → PAMF freeze
5. One money loop
