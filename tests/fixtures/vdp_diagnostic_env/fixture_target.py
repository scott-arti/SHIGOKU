"""
SGK-2026-0425 M4 — generated opaque diagnostic fixture target.

Stdlib-only ``http.server.ThreadingHTTPServer`` serving a RANDOM, OPAQUE,
product-free surface generated at startup from ``DIAG_SEED``. No product
names, no known URLs, no known payloads, no expected finding counts:

- N cases (``DIAG_CASE_COUNT``, default 3), each with:
  - ``opaque_case_id``: ``case-<16 hex>``;
  - opaque route ``/di/<8 hex>`` (8-hex segments deliberately avoid the
    production observation adapter's ``:opaque`` masking of 16+ hex segments
    so cases are never accidentally conflated);
  - a GENERIC capability family (role_diff / external_fetch / object_id /
    ownership / session_token / stored_revisit — taxonomy §7 vocabulary);
  - an actor model (owner actorA / non-owner actorB / per-case grant flag);
  - a random sensitive value (opaque hex).
- Endpoints answer GETs deterministically: ``/health`` (200), ``/`` (index
  linking every case route), ``<route>`` (401 unauthenticated / 200 owner /
  200|403 non-owner). Non-GET methods are always 405.

Fault injection (``DIAG_FAULT_STAGE``, default ``S00`` = pass-through):
- ``S00``: pass-through; every case is served normally.
- ``S01``: the index exposes NO case links (raw producer artifact absent) —
  the genuine S01 (surface acquisition) cut.
- ``S02``: index links are ABSOLUTE hrefs carrying userinfo
  (``http://<hex>@fixture-target:8000/...``) — the genuine S02
  (observation normalization) cut: the adapter rejects userinfo URLs
  fail-closed.
- ``S03``: every case route gains a ``/diag-probe`` path segment — the
  genuine S03 (hypothesis generation) cut: the runtime's leakage denylist
  rejects the observation, so no hypothesis is generated.
- ``S04..S12``: the surface stays normal. These cuts are carried by the
  deterministic ``event_simulator.py`` until the M1 diagnostic hooks land
  (the current runtime only exercises S00..S03).

Startup writes two sealed artifacts into the private secrets dir
(``SECRETS_OUT_PATH`` — a host mktemp dir OUTSIDE the repo, never mounted
into the runtime):
- ``case_manifest.json``: opaque case ids + route map + fingerprints
  (fingerprints mirror the production adapter's ``normalize_url`` for this
  route shape, so the evaluator can join runtime events to cases);
- ``expected_path_labels.json``: ExpectedPathCaseV1 dicts per case (stage
  DAG, optional/ineligible stages, required actors/controls/evidence,
  allowed action classes) — NO route/product information.

Run: ``python fixture_target.py [--host 0.0.0.0] [--port 8000]``
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import random
import re
import secrets as _secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DIAG_SEED = int(os.environ.get("DIAG_SEED", "1"))
DIAG_CASE_COUNT = int(os.environ.get("DIAG_CASE_COUNT", "3"))
DIAG_FAULT_STAGE = os.environ.get("DIAG_FAULT_STAGE", "S00")
SECRETS_OUT_PATH = os.environ.get("SECRETS_OUT_PATH", "")
MANIFEST_BASE_URL = os.environ.get("MANIFEST_BASE_URL", "http://fixture-target:8000")
DIAG_RUN_ID = os.environ.get("DIAG_RUN_ID", "diag-run")

# Generic capability families (taxonomy §7 vocabulary — not products).
_FAMILIES = [
    "role_diff",
    "external_fetch",
    "object_id",
    "ownership",
    "session_token",
    "stored_revisit",
]

# Per-index (case 0, case 1, ...) DAG variety exercised in the sealed
# labels: one optional stage and one ineligible stage.
_SKIPPED_BY_INDEX = {
    0: ("optional", "S09"),
    1: ("ineligible", "S10"),
}

_STAGE_DEPTH = 13  # S00..S12
_ID_RE = re.compile(r"^[a-z0-9-]+$")


def _normalize_mirror(url: str) -> str:
    """Mirror of the production adapter's ``normalize_url`` for the opaque
    route shape this fixture serves (lowercased scheme/netloc, path kept,
    query parameter NAMES sorted, values dropped)."""
    parsed = urlparse(str(url))
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    query_names = sorted({k for k in parse_qs(parsed.query).keys() if k})
    normalized = f"{scheme}://{netloc}{path}"
    if query_names:
        normalized += "?" + "&".join(query_names)
    return normalized


def _linear_stage_dag() -> dict:
    """Linear S00 -> S01 -> ... -> S12 expected-path DAG."""
    stages = [f"S{i:02d}" for i in range(_STAGE_DEPTH)]
    dag = {}
    for i, stage in enumerate(stages):
        dag[stage] = {"depends_on": [stages[i - 1]]} if i else {"depends_on": []}
    return dag


def _label_for_case(case: dict) -> dict:
    """One ExpectedPathCaseV1 label (no routes, no product info)."""
    index = case["n"]
    family = case["capability_family"]
    skipped = _SKIPPED_BY_INDEX.get(index)
    optional_stages = [skipped[1]] if skipped and skipped[0] == "optional" else []
    ineligible_stages = (
        [{"stage": skipped[1], "reason": "oob_not_permitted"}]
        if skipped and skipped[0] == "ineligible"
        else []
    )
    if family == "external_fetch":
        required_actors = ["actorA"]
        required_controls = ["baseline", "attack", "inverse"]
        required_evidence = ["baseline", "attack", "unique_correlation"]
        allowed_action_classes = ["read", "compare", "read_back"]
    elif family == "role_diff":
        required_actors = ["actorA", "actorB"]
        required_controls = ["baseline", "attack", "inverse", "falsification"]
        required_evidence = ["baseline", "attack", "inverse", "owner_diff"]
        allowed_action_classes = ["read", "compare", "read_back"]
    else:
        required_actors = ["actorA"]
        required_controls = ["baseline", "attack", "inverse", "falsification"]
        required_evidence = ["baseline", "attack", "inverse", "read_back"]
        allowed_action_classes = ["read", "compare", "read_back", "browser_revisit"]
    return {
        "opaque_case_id": case["opaque_case_id"],
        "capability_family": family,
        "stage_dag": _linear_stage_dag(),
        "optional_stages": optional_stages,
        "ineligible_stages": ineligible_stages,
        "required_actors": required_actors,
        "required_controls": required_controls,
        "required_evidence": required_evidence,
        "allowed_action_classes": allowed_action_classes,
    }


def generate_cases() -> list:
    """Generate the opaque case set from DIAG_SEED (deterministic per seed)."""
    rng = random.Random(DIAG_SEED)
    cases = []
    for i in range(DIAG_CASE_COUNT):
        route = f"/di/{rng.getrandbits(32):08x}"
        if DIAG_FAULT_STAGE == "S03":
            # S03 cut: leaky path segment rejected by the runtime denylist.
            route += "/diag-probe"
        cases.append({
            "opaque_case_id": f"case-{rng.getrandbits(64):016x}",
            "route": route,
            "fingerprint": _normalize_mirror(MANIFEST_BASE_URL + route),
            "capability_family": _FAMILIES[i % len(_FAMILIES)],
            "actor_model": {
                "owner": "actorA",
                "non_owner": "actorB",
                "b_can_read": bool(rng.getrandbits(1)),
            },
            "sensitive": _secrets.token_hex(8),
            "n": i,
        })
    return cases


def write_sealed_artifacts(cases: list) -> None:
    """Write the case manifest + expected-path labels to the private dir
    (never the repo, never mounted into the runtime)."""
    if not SECRETS_OUT_PATH:
        return
    os.makedirs(SECRETS_OUT_PATH, exist_ok=True)
    manifest = {
        "schema_version": 1,
        "taxonomy_version": "v2",
        "run_id": DIAG_RUN_ID,
        "seed": DIAG_SEED,
        "case_count": DIAG_CASE_COUNT,
        "base_url": MANIFEST_BASE_URL,
        "cases": [
            {
                "opaque_case_id": c["opaque_case_id"],
                "route": c["route"],
                "fingerprint": c["fingerprint"],
                "capability_family": c["capability_family"],
                "actor_model": c["actor_model"],
            }
            for c in cases
        ],
    }
    labels = {
        "schema_version": 1,
        "taxonomy_version": "v2",
        "run_id": DIAG_RUN_ID,
        "cases": [_label_for_case(c) for c in cases],
    }
    with open(
        os.path.join(SECRETS_OUT_PATH, "case_manifest.json"), "w", encoding="utf-8"
    ) as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
    with open(
        os.path.join(SECRETS_OUT_PATH, "expected_path_labels.json"),
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(labels, handle, indent=2, sort_keys=True)


def _resolve_account(auth_header: str, accounts: dict) -> str:
    """Resolve an account id from a Basic or Bearer Authorization header."""
    header = str(auth_header or "")
    if header.startswith("Bearer "):
        token = header[len("Bearer "):].strip()
        for account, secret in accounts.items():
            if token == secret:
                return account
        return ""
    if header.startswith("Basic "):
        try:
            decoded = base64.b64decode(header[len("Basic "):].strip()).decode(
                "utf-8", errors="replace"
            )
        except Exception:
            return ""
        user, _, password = decoded.partition(":")
        if password == accounts.get(user, ""):
            return user
        return ""
    return ""


class DiagnosticFixtureHandler(BaseHTTPRequestHandler):
    """Opaque route dispatcher: the route table is generated at startup."""

    cases: list = []  # set by main() before serve_forever
    accounts: dict = {}

    def log_message(self, format, *args):  # silence default stderr logging
        pass

    def _send(self, status: int, body: str, content_type: str = "application/json",
              extra_headers: dict | None = None) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, status: int, data: dict) -> None:
        self._send(status, json.dumps(data, ensure_ascii=False))

    # ------------------------------------------------------------------
    # GET dispatch
    # ------------------------------------------------------------------

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        status = 200
        try:
            if path == "/health":
                self._send_json(200, {"status": "ok"})
            elif path == "/":
                status = self._route_index()
            else:
                case = self._case_for(path)
                if case is None:
                    self._send_json(404, {"error": "not_found"})
                    status = 404
                else:
                    status = self._route_case(case, path)
        except (BrokenPipeError, ConnectionResetError):
            return  # client went away; nothing to record
        # no access-log side channel: the fixture surface is generated
        # per-run and the runtime driver records its own observations.

    def _href_for(self, case: dict) -> str:
        if DIAG_FAULT_STAGE == "S02":
            # S02 cut: absolute href carrying userinfo — the adapter rejects
            # userinfo URLs fail-closed and the runtime never crawls them.
            netloc = urlparse(MANIFEST_BASE_URL).netloc
            return f"http://{_secrets.token_hex(4)}@{netloc}{case['route']}"
        return case["route"]

    def _route_index(self) -> int:
        if DIAG_FAULT_STAGE == "S01":
            # S01 cut: no case links in the raw producer artifact.
            html = (
                "<!doctype html><html><head><title>index</title></head>"
                "<body><h1>index</h1><pre>no links</pre></body></html>"
            )
            self._send(200, html, content_type="text/html; charset=utf-8")
            return 200
        links = [
            (self._href_for(case), f"resource-{index}")
            for index, case in enumerate(self.cases, start=1)
        ]
        plain = "\n".join(f"{label}: {href}" for href, label in links)
        anchors = "\n".join(f'<a href="{href}">{label}</a>' for href, label in links)
        html = (
            "<!doctype html><html><head><title>index</title></head>"
            f"<body><h1>index</h1><pre>{plain}</pre>{anchors}</body></html>"
        )
        self._send(200, html, content_type="text/html; charset=utf-8")
        return 200

    def _case_for(self, path: str) -> dict | None:
        for case in self.cases:
            opaque = case["route"]
            if path == opaque or path.startswith(f"{opaque}/"):
                return case
        return None

    def _route_case(self, case: dict, path: str) -> int:
        account = _resolve_account(
            self.headers.get("Authorization", ""), self.accounts
        )
        if not account:
            self._send(
                401,
                '{"error": "unauthorized"}',
                extra_headers={"WWW-Authenticate": 'Basic realm="opaque"'},
            )
            return 401
        owner = case["actor_model"]["owner"]
        if account != owner:
            if not case["actor_model"]["b_can_read"]:
                self._send_json(403, {"error": "forbidden"})
                return 403
            # granted: the non-owner receives the owner's record
        item_id = path[len(case["route"]):].strip("/") or "1"
        if not _ID_RE.match(item_id):
            self._send_json(400, {"error": "invalid_item_id"})
            return 400
        self._send_json(200, {
            "id": item_id,
            "owner": owner,
            "sensitive": case["sensitive"],
        })
        return 200

    # ------------------------------------------------------------------
    # non-GET methods: ALWAYS 405, never executed
    # ------------------------------------------------------------------

    def do_POST(self) -> None:
        self._deny("POST")

    def do_PUT(self) -> None:
        self._deny("PUT")

    def do_PATCH(self) -> None:
        self._deny("PATCH")

    def do_DELETE(self) -> None:
        self._deny("DELETE")

    def _deny(self, method: str) -> None:
        self._send_json(405, {"error": "method_not_allowed"})


def main() -> None:
    parser = argparse.ArgumentParser(description="Opaque diagnostic fixture target")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    cases = generate_cases()
    write_sealed_artifacts(cases)
    DiagnosticFixtureHandler.cases = cases
    DiagnosticFixtureHandler.accounts = {
        "actorA": _secrets.token_hex(16),
        "actorB": _secrets.token_hex(16),
    }
    server = ThreadingHTTPServer((args.host, args.port), DiagnosticFixtureHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
