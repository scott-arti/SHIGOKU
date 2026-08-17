"""SGK-2026-0453: product-neutral filtered search app (sealed demo target).

Runs REAL SQL against SQLite and applies a configurable, product-neutral input
filter (quote strip / union block / dash-dash strip / block-comment block).
The defense toggles select which family of the generic transformation catalog
is exercised. Lives under tests/ ONLY — the production code never references
this target (product independence, plan §H).

GET /search?q=... only. SQL errors include the word "SQLite" so the payout-
grade sql_error marker vocabulary (payout_grade._SQL_ERROR_PATTERNS) fires.

Filter selection: SHIGOKU_DEMO_FILTER=strip_quote,block_union,strip_dashdash,
block_blockcomment (comma-separated; empty = undefended).

Two-decode layer: when SHIGOKU_DEMO_DOUBLE_DECODE=1 the app re-decodes the
parameter once MORE before the SQL layer (the filter sees the once-decoded
value). This models a legitimate app pattern (normalization middleware) and is
the environment in which the catalog's ENCODING transform (double
percent-encoding) is effective — plan §D "2層デコード時".
"""
import os
import re
import sqlite3
from typing import Set
from urllib.parse import unquote

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

FILTER_STRIP_QUOTE = "strip_quote"
FILTER_BLOCK_UNION = "block_union"
FILTER_STRIP_DASH = "strip_dashdash"
FILTER_BLOCK_COMMENT = "block_blockcomment"

_FILTER_NAMES = (
    FILTER_STRIP_QUOTE,
    FILTER_BLOCK_UNION,
    FILTER_STRIP_DASH,
    FILTER_BLOCK_COMMENT,
)

app = FastAPI(title="vdp filtered search app (demo target)")


def _active_filters() -> Set[str]:
    raw = os.environ.get("SHIGOKU_DEMO_FILTER", "")
    return {name.strip() for name in raw.split(",") if name.strip() in _FILTER_NAMES}


def apply_filter(value: str, active: Set[str]) -> str:
    """Pure, deterministic strip-style filter: removes dangerous characters
    from the input before it reaches the SQL layer."""
    out = str(value or "")
    if FILTER_STRIP_QUOTE in active:
        out = out.replace("'", "")
    if FILTER_STRIP_DASH in active:
        out = out.replace("--", "")
    return out


def is_blocked(value: str, active: Set[str]) -> bool:
    """Pure, deterministic block-style filter: True rejects the request."""
    if FILTER_BLOCK_UNION in active and re.search(
        r"union", str(value or ""), re.IGNORECASE
    ):
        return True
    if FILTER_BLOCK_COMMENT in active and "/*" in str(value or ""):
        return True
    return False


@app.get("/search")
def search(q: str = Query("", max_length=400)):
    active = _active_filters()
    if is_blocked(q, active):
        return JSONResponse({"status": "blocked", "data": []}, status_code=403)
    filtered = apply_filter(q, active)
    if os.environ.get("SHIGOKU_DEMO_DOUBLE_DECODE", "") == "1":
        # Second decode layer (normalization middleware) — the SQL layer sees
        # the twice-decoded value. This is what makes the double-encoded
        # (ENCODING transform) probes effective.
        filtered = unquote(filtered)
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
        conn.executemany(
            "INSERT INTO items (name) VALUES (?)",
            [("alpha",), ("beta",), ("gamma",)],
        )
        conn.commit()
        rows = conn.execute(
            "SELECT id, name FROM items WHERE name LIKE '%" + filtered + "%'"
        ).fetchall()
    except sqlite3.Error as exc:  # noqa: BLE001 — the SQL error is the point
        return JSONResponse(
            {"status": "error", "detail": "SQLite error: " + str(exc)},
            status_code=500,
        )
    finally:
        conn.close()
    return JSONResponse(
        {
            "status": "success",
            "data": [{"id": r[0], "name": r[1]} for r in rows],
            # Path/query-dependent echo (a normal search-app behavior): makes
            # the response depend on the query so the 0447 forwarding check
            # sees distinct bodies (never a "canned identical 200" trap).
            # The DISPLAY layer sanitizes quote characters (standard output
            # encoding), so the echoed value never leaks probe characters —
            # the interference classifier's baseline comparison (S1) and
            # reflection check (S2) stay meaningful.
            "query": "".join(ch for ch in filtered if ch not in "'\""),
        }
    )
