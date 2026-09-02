"""SGK-2026-0467: product-neutral multi-user authorization app (sealed demo target).

A minimal two-user API used to fact-check SHIGOKU's IDOR/BOLA confirmation
path. Product-neutral (no target-specific tokens): only generic paths, owner
labels ("user-a"/"user-b"), and benign non-sensitive notes. Lives under tests/
ONLY — production code never references this target (product independence).

GET-only reads (no state change). Auth is a simple bearer token in the
``X-Auth-Token`` header: ``token-a`` -> user-a, ``token-b`` -> user-b, absent
or unknown -> unauthenticated. Bodies are path-dependent (distinct per id/owner)
so the SGK-2026-0447 forwarding check never sees a canned-identical 200.

Two authorization flavors are exposed, matching the two branches of the
payout-grade authz vocabulary:

- GET /api/public/{id}
    Unauthenticated-access-allowed flavor. Returns 200 whether or not a token
    is present (an endpoint that SHOULD require auth but does not). An
    authenticated request and an unauthenticated request both succeed ->
    build_authz_differential yields auth_success + unauth_success. This is the
    flavor the current API-probe confirmation path recognizes.

- GET /api/records/{id}
    Cross-user BOLA flavor. Requires a valid token (no token -> 401), but does
    NOT check ownership: user-a's token can read user-b's record and vice
    versa. Unauthenticated access fails, so the auth_success/unauth_success
    marker does NOT fire — this is the true broken-object-level-authorization
    case that the capability map flags as the weak spot.

Enforcement toggle: SHIGOKU_DEMO_AUTHZ_ENFORCE=1 makes /api/records/{id}
enforce ownership (403 when the token's user is not the owner) and makes
/api/public/{id} require auth (401 when unauthenticated) — the secured
negative-control environment. Empty/unset = vulnerable (default).
"""
import os
from typing import Dict, Optional

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="vdp authz multiuser app (demo target)")

# SGK-2026-0469: demo login credentials (fixture-local demo constants,
# product-neutral — generic fields only). Used by the config-driven login
# recipe demo path; returning a fresh demo token mirrors a real session
# endpoint's "auth.token" response shape.
_DEMO_LOGIN_USER = "demo-user"
_DEMO_LOGIN_PASS = "demo-pass"


@app.post("/login")
async def login(request: Request):
    """Demo login endpoint for the config-driven login recipe path.

    Accepts generic JSON (default) or form-encoded ``{"user", "pass"}``.
    Correct creds are the fixture-local constants above; any other values are
    rejected. On success returns ``{"auth": {"token": "<demo token>"}}`` so a
    recipe with ``token_path: "auth.token"`` can extract the refreshed token.
    """
    try:
        data = await request.json()
    except Exception:
        data = dict(await request.form())
    if data.get("user") != _DEMO_LOGIN_USER or data.get("pass") != _DEMO_LOGIN_PASS:
        return JSONResponse({"status": "invalid_credentials"}, status_code=401)
    return JSONResponse({"auth": {"token": "demo-token-a"}})

# token -> owner label. Absent/unknown token -> unauthenticated.
_TOKENS: Dict[str, str] = {
    "token-a": "user-a",
    "token-b": "user-b",
}

# id -> (owner label, benign non-sensitive note). No PII, no credentials.
_RECORDS: Dict[int, Dict[str, str]] = {
    1: {"owner": "user-a", "note": "account-a private note alpha"},
    2: {"owner": "user-b", "note": "account-b private note beta"},
    3: {"owner": "user-a", "note": "account-a private note gamma"},
}


def _enforce() -> bool:
    return os.environ.get("SHIGOKU_DEMO_AUTHZ_ENFORCE", "") == "1"


def _resolve_user(
    token: Optional[str], authorization: Optional[str] = None
) -> Optional[str]:
    # X-Auth-Token first; fall back to a standard "Authorization: Bearer <tok>"
    # scheme so a caller can use an auth header that a scanner's unauth probe
    # strips (Authorization/Cookie), while the second account can use a custom
    # header that is not stripped.
    raw = str(token or "").strip()
    if not raw:
        bearer = str(authorization or "").strip()
        if bearer.lower().startswith("bearer "):
            raw = bearer[7:].strip()
    return _TOKENS.get(raw) or None


@app.get("/")
def index():
    # Landing body links the API endpoints so extract_api_like_urls can
    # discover them (the API-probe path re-evaluates discovered /api/ URLs).
    return JSONResponse(
        {
            "status": "ok",
            "endpoints": [
                "/api/public/1",
                "/api/public/2",
                "/api/records/1",
                "/api/records/2",
                "/api/records/3",
            ],
        }
    )


@app.get("/api/public/{item_id}")
def public_item(
    item_id: int,
    x_auth_token: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
):
    """Unauthenticated-access-allowed flavor (broken access control)."""
    user = _resolve_user(x_auth_token, authorization)
    if _enforce() and user is None:
        # Secured control: this endpoint requires auth.
        return JSONResponse({"status": "unauthorized"}, status_code=401)
    rec = _RECORDS.get(item_id)
    if rec is None:
        return JSONResponse({"status": "not_found", "id": item_id}, status_code=404)
    # Path-dependent body (distinct per id); benign data only.
    return JSONResponse(
        {
            "status": "success",
            "id": item_id,
            "owner": rec["owner"],
            "note": rec["note"],
            "viewer": user or "anonymous",
        }
    )


@app.get("/api/records/{item_id}")
def record_item(
    item_id: int,
    x_auth_token: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
):
    """Cross-user BOLA flavor (broken object level authorization)."""
    user = _resolve_user(x_auth_token, authorization)
    if user is None:
        # Requires a valid token (unauthenticated access is denied).
        return JSONResponse({"status": "unauthorized"}, status_code=401)
    rec = _RECORDS.get(item_id)
    if rec is None:
        return JSONResponse({"status": "not_found", "id": item_id}, status_code=404)
    if _enforce() and rec["owner"] != user:
        # Secured control: ownership is enforced.
        return JSONResponse({"status": "forbidden", "id": item_id}, status_code=403)
    # VULNERABLE default: any valid token reads any record (no ownership check).
    return JSONResponse(
        {
            "status": "success",
            "id": item_id,
            "owner": rec["owner"],
            "note": rec["note"],
            "viewer": user,
        }
    )
