"""
Lane O-1 host-side smoke tests — SGK-2026-0423.

Disposable isolated verification environment (3 containers) proof, run on
the HOST against a local stdlib fixture on 127.0.0.1:<free port>:

1. ``test_fixture_endpoints_and_405`` — fixture contract: statuses per
   endpoint, 405 for every non-GET method, and a fixture access log that
   contains zero non-GET requests.
2. ``test_runtime_driver_m3a_readonly_no_post`` — the M3a read-only
   production path (MasterConductor hook -> queue -> dispatch -> executor
   -> session -> M0 gate) driven by ``runtime_driver.py`` against the
   local fixture: exit 0, session written, M0 gate PASS, zero non-GET
   requests in the fixture log, no secrets in the session.
3. ``test_runtime_driver_kill_switch_zero_requests`` — KILL_SWITCH=1 run
   makes ZERO requests total (no crawl, nothing queued, empty fixture log).
4. ``test_evaluator_job_anonymized`` — the one-shot holdout evaluator
   against a real runtime session + host-frozen thresholds + generic
   labels: exit 0, outcome in (pass/hold/fail), fingerprint present, and
   the result JSON contains NO raw label / URL / payload strings.

Every subprocess runs with the repo venv python (``.venv/bin/python``) and
``cwd=REPO``. The smoke tests themselves only ever touch 127.0.0.1.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
FIXTURE_DIR = REPO / "tests" / "fixtures" / "vdp_isolated_env"
FIXTURE_SCRIPT = FIXTURE_DIR / "fixture_target.py"
DRIVER_SCRIPT = FIXTURE_DIR / "runtime_driver.py"
EVALUATOR_SCRIPT = FIXTURE_DIR / "evaluator_job.py"
HOST_PYTHON = REPO / ".venv" / "bin" / "python"

EVAL_VERSION = "iso-v1"

# Distinctive label strings (never present in the runtime output) used to
# prove the evaluator result is anonymized (grep-verifiable).
LABEL_URL = "http://holdout-internal.example/secret-label-path"
LABEL_PAYLOAD = "holdout-payload-token-xyz"
LABEL_PRODUCT = "holdout-product-name"

KEY_HEX = "33" * 32


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start_fixture(tmp_path: Path, port: int, log_name: str) -> subprocess.Popen:
    access_log = tmp_path / f"{log_name}.log"
    env = dict(os.environ)
    env["ACCESS_LOG_PATH"] = str(access_log)
    proc = subprocess.Popen(
        [
            str(HOST_PYTHON),
            str(FIXTURE_SCRIPT),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    # Condition-based wait (no hardcoded sleep): poll until the fixture
    # accepts TCP connections. A bare connect is NOT an HTTP request, so
    # the fixture access log stays clean for the POST=0 assertions.
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"fixture exited early with code {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                return proc
        except OSError:
            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("fixture did not become ready in time")


def _http(method: str, url: str, timeout: float = 5.0, data: bytes | None = None):
    """Minimal stdlib HTTP client for 127.0.0.1 traffic only.

    Returns ``(status, body_text)``. Redirects are NOT followed; 3xx/4xx/5xx
    are returned as status codes (urllib raises HTTPError for them).
    """
    req = urllib.request.Request(url, data=data, method=method)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # noqa: D102
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, body


def _read_log_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _non_get_lines(lines: list[str]) -> list[str]:
    """Access-log lines whose method column is not GET (``method path status``)."""
    return [line for line in lines if not re.match(r"^GET\s+", line)]


def _run_driver(
    out_dir: Path,
    base_url: str,
    access_log: Path,
    *,
    kill_switch: bool = False,
    scope_host: str = "127.0.0.1",
) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)
    env["FIXTURE_BASE_URL"] = base_url
    env["FIXTURE_SCOPE_HOST"] = scope_host
    env["OUT_DIR"] = str(out_dir)
    env["KILL_SWITCH"] = "1" if kill_switch else "0"
    env["TARGET_NAME"] = "vdp-iso-fixture"
    env["ACCESS_LOG_PATH"] = str(access_log)
    return subprocess.run(
        [str(HOST_PYTHON), str(DRIVER_SCRIPT)],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


def _run_evaluator(
    labels_path: Path,
    thresholds_path: Path,
    session_path: Path,
    result_path: Path,
) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)
    env["LABELS_PATH"] = str(labels_path)
    env["THRESHOLDS_PATH"] = str(thresholds_path)
    env["SESSION_PATH"] = str(session_path)
    env["RESULT_PATH"] = str(result_path)
    return subprocess.run(
        [str(HOST_PYTHON), str(EVALUATOR_SCRIPT)],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _freeze_thresholds(path: Path) -> None:
    """Host-side threshold freeze (Lane O-1: frozen BEFORE the evaluator).

    SGK-2026-0423 audit correction: the original set used direction="maximum"
    for recall (recall=0 passed) and trivial 0.0/1.0 bounds everywhere —
    a gamed pass. This set is directionally correct and meaningful:
    - recall is a MINIMUM (higher discovery is better; 0 confirmed → unmet),
    - false_promotion_rate / untested_rate are MAXIMA (lower is better),
    - funnel/completeness/budget are MINIMA with non-trivial bounds.
    With zero confirmed verdicts in the isolated M3a run, recall=0.0 < 0.5
    → the honest outcome is HOLD, not pass. M4 stays rejected.
    """
    from src.reporting.vdp_dataset import ThresholdMetric, freeze_thresholds

    artifact = freeze_thresholds(
        eval_version=EVAL_VERSION,
        decided_at="2026-08-04T00:00:00Z",
        metrics=[
            ThresholdMetric(
                name="evidence_completeness", value=0.2,
                formula="hypotheses_with_evidence / total_hypotheses",
                target_set="hidden_holdout", direction="minimum",
            ),
            ThresholdMetric(
                name="funnel:hypothesis_to_attempt", value=0.2,
                formula="attempts / hypotheses",
                target_set="hidden_holdout", direction="minimum",
            ),
            ThresholdMetric(
                name="untested_rate", value=0.5,
                formula="untested_verdicts / verdicts",
                target_set="hidden_holdout", direction="maximum",
            ),
            ThresholdMetric(
                name="false_promotion_rate", value=0.2,
                formula="confirmed_without_gt_match / confirmed",
                target_set="hidden_holdout", direction="maximum",
            ),
            ThresholdMetric(
                name="recall", value=0.5,
                formula="matched_ground_truth_entries / ground_truth_entries",
                target_set="hidden_holdout", direction="minimum",
            ),
            ThresholdMetric(
                name="budget_compliance", value=0.8,
                formula="within-limit budget entries / eligible entries",
                target_set="hidden_holdout", direction="minimum",
            ),
        ],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(artifact.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
    )


def _write_labels(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    labels = {
        "class": {
            "urls": [LABEL_URL],
            "payloads": [LABEL_PAYLOAD],
            "product_names": [LABEL_PRODUCT],
        },
        "ground_truth": [
            {
                "class": "public-read",
                "capability": "object_read_write_delete",
                "method": "GET",
                "endpoint": "/readonly-ok",
            },
        ],
    }
    path.write_text(json.dumps(labels, indent=2, sort_keys=True), encoding="utf-8")


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


class TestIsolatedEnv:
    def test_fixture_endpoints_and_405(self, tmp_path):
        port = _free_port()
        proc = _start_fixture(tmp_path, port, "fixture-basic")
        try:
            base = f"http://127.0.0.1:{port}"
            cases = [
                ("/", 200),
                ("/readonly-ok", 200),
                ("/items/sample-1", 200),
                ("/items/abc-123", 200),
                ("/items/Bad_Id!", 400),
                ("/rate-limited", 429),
                ("/server-error", 500),
                ("/redirect-out-of-scope", 302),
                ("/search?q=probe", 200),
                ("/missing-path", 404),
            ]
            for path, expected in cases:
                status, body = _http("GET", f"{base}{path}", timeout=5)
                assert status == expected, f"GET {path}: {status} != {expected}"

            # POST/PUT/PATCH/DELETE must ALWAYS answer 405 and never execute.
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                status, _ = _http(method, f"{base}/readonly-ok", data=b"x=1")
                assert status == 405, f"{method} /readonly-ok: {status} != 405"
            status, _ = _http("POST", f"{base}/items/sample-1", data=b"x=1")
            assert status == 405
            status, _ = _http("DELETE", f"{base}/", data=b"")
            assert status == 405

            # /readonly-ok body is the documented generic payload.
            _, body = _http("GET", f"{base}/readonly-ok")
            assert json.loads(body) == {"status": "ok", "data": "public-test-data"}

            log_lines = _read_log_lines(tmp_path / "fixture-basic.log")
            assert log_lines, "fixture access log must not be empty"
            # Every non-GET line must be a 405 denial (nothing executed);
            # the ZERO-non-GET proof for the driver's own traffic lives in
            # the driver smoke tests against a fresh log.
            non_get = _non_get_lines(log_lines)
            assert non_get, "the 405 probe requests must be recorded"
            assert all(line.endswith(" 405") for line in non_get), (
                f"non-GET requests were executed (not denied): {non_get}"
            )
            assert any(line.startswith("GET / ") for line in log_lines)
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def test_runtime_driver_m3a_readonly_no_post(self, tmp_path):
        port = _free_port()
        proc = _start_fixture(tmp_path, port, "fixture-driver")
        try:
            out_dir = tmp_path / "out"
            access_log = tmp_path / "fixture-driver.log"
            result = _run_driver(
                out_dir, f"http://127.0.0.1:{port}", access_log
            )
            assert result.returncode == 0, (
                f"driver failed (rc={result.returncode})\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )

            # --- session written + M0 gate PASS printed by the driver ---
            sessions = sorted(out_dir.glob("session_*.json"))
            assert sessions, "driver must write a session file"
            session_path = sessions[-1]
            session_text = session_path.read_text(encoding="utf-8")
            session = json.loads(session_text)

            assert "m0_gate_pass" in result.stdout, (
                "driver must report the M0 gate verdict"
            )

            # --- fixture access log: ZERO non-GET methods (the POST=0 proof) ---
            log_lines = _read_log_lines(access_log)
            assert log_lines, "fixture access log must not be empty"
            assert _non_get_lines(log_lines) == [], (
                f"non-GET requests observed in fixture log: {_non_get_lines(log_lines)}"
            )

            # --- run_summary.json: hypotheses > 0, verdicts non-empty,
            # 429/500/timeout/redirect endpoints present in observations ---
            summary_path = out_dir / "run_summary.json"
            assert summary_path.exists()
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            assert summary["hypotheses_count"] > 0
            assert sum(summary["verdicts_by_status"].values()) > 0, (
                "verdicts must be non-empty (candidates)"
            )
            assert summary["m0_gate"]["passed"] is True
            assert summary["non_get_violations"] == 0
            assert summary["fixture_log_non_get"] == 0

            observations = {obs["path"]: obs["status"] for obs in summary["observations"]}
            assert "/rate-limited" in observations
            assert "/server-error" in observations
            assert "/slow" in observations
            assert "/redirect-out-of-scope" in observations
            assert observations["/rate-limited"] == 429
            assert observations["/server-error"] == 500
            assert observations["/slow"] == "timeout"
            assert observations["/redirect-out-of-scope"] == 302

            # --- no secrets in the session (key hex / Authorization / Cookie) ---
            assert KEY_HEX not in session_text
            assert KEY_HEX not in summary_path.read_text(encoding="utf-8")
            assert "Authorization" not in session_text
            assert "Cookie" not in session_text
            assert re.search(r"signing_key|private_key|seed", session_text, re.IGNORECASE) is None

            # --- session structure survives the canonical round trip ---
            vdp = session.get("vdp_contract", {})
            assert vdp.get("vdp_active") is True
            assert vdp.get("hypotheses")
            assert vdp.get("attempts")
            assert vdp.get("evidence_records")
            assert vdp.get("verdicts")
            assert vdp.get("next_actions")
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def test_runtime_driver_kill_switch_zero_requests(self, tmp_path):
        port = _free_port()
        proc = _start_fixture(tmp_path, port, "fixture-kill")
        try:
            out_dir = tmp_path / "out-kill"
            access_log = tmp_path / "fixture-kill.log"
            result = _run_driver(
                out_dir, f"http://127.0.0.1:{port}", access_log, kill_switch=True
            )
            assert result.returncode == 0, (
                f"kill-switch driver failed (rc={result.returncode})\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
            assert "kill_switch_stop" in result.stdout
            assert "0-queued" in result.stdout
            assert "0-requests" in result.stdout

            # The kill-switch run must make ZERO requests total: the fixture
            # access log stays empty (no crawl, nothing queued, no dispatch).
            log_lines = _read_log_lines(access_log)
            assert log_lines == [], (
                f"kill-switch run made requests: {log_lines}"
            )

            summary = json.loads(
                (out_dir / "run_summary.json").read_text(encoding="utf-8")
            )
            assert summary["kill_switch"] is True
            assert summary["hypotheses_count"] == 0
            assert summary["requests_made"] == 0
            assert summary["observations"] == []
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def test_evaluator_job_anonymized(self, tmp_path):
        port = _free_port()
        proc = _start_fixture(tmp_path, port, "fixture-eval")
        try:
            out_dir = tmp_path / "out-eval"
            access_log = tmp_path / "fixture-eval.log"
            result = _run_driver(out_dir, f"http://127.0.0.1:{port}", access_log)
            assert result.returncode == 0, (
                f"driver failed (rc={result.returncode})\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
            sessions = sorted(out_dir.glob("session_*.json"))
            assert sessions

            # Thresholds are frozen HOST-side (before the evaluator reads
            # them) and labels are the hidden-holdout artifact.
            thresholds_path = out_dir / "eval" / "thresholds_v1.json"
            _freeze_thresholds(thresholds_path)
            labels_path = tmp_path / "labels" / "labels.json"
            _write_labels(labels_path)
            result_path = out_dir / "eval" / "holdout_result_iso.json"

            eval_result = _run_evaluator(
                labels_path, thresholds_path, sessions[-1], result_path
            )
            assert eval_result.returncode == 0, (
                f"evaluator failed (rc={eval_result.returncode})\n"
                f"stdout:\n{eval_result.stdout}\nstderr:\n{eval_result.stderr}"
            )
            assert "iso_eval:outcome" in eval_result.stdout

            assert result_path.exists()
            result_text = result_path.read_text(encoding="utf-8")
            result_data = json.loads(result_text)
            assert result_data["outcome"] in ("pass", "hold", "fail")
            # Deterministic expectation with the corrected MEANINGFUL frozen
            # thresholds: the isolated M3a run has zero confirmed verdicts
            # (recall=0.0 < 0.5 minimum) -> the honest outcome is HOLD, never
            # a gamed pass. recall is recorded (0.0) for the audit trail.
            assert result_data["outcome"] == "hold", result_data
            assert result_data["metrics"]["recall"]["value"] == 0.0
            assert result_data["metrics"]["recall"]["met"] is False
            assert result_data["metrics"]["untested_rate"]["met"] is True
            assert result_data["threshold_fingerprint"]
            assert result_data["artifact_hash"]
            assert result_data["runner_version"] == "vdp-iso-evaluator-0.1.0"
            assert result_data["feature_flags"] == {
                "stage": "m3a",
                "network": "internal-only",
            }
            assert result_data["leakage_hits"] == []

            # Anonymized: the result JSON contains NO raw label strings,
            # no runtime URLs, and no key material.
            assert LABEL_URL not in result_text
            assert LABEL_PAYLOAD not in result_text
            assert LABEL_PRODUCT not in result_text
            assert "127.0.0.1" not in result_text
            assert KEY_HEX not in result_text
        finally:
            proc.terminate()
            proc.wait(timeout=10)
