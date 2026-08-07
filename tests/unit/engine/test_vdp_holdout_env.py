"""
SGK-2026-0423 Lane P-2 — random/opaque isolated holdout environment (TDD).

Host-side tests (127.0.0.1 only, zero external network):

1. the fixture generates opaque routes + account credentials at startup and
   enforces the method/auth contract (405/401/200/403, access log);
2. the runtime driver runs the REAL MC production path against the fixture
   with the account env vars — the cross-account comparison confirms
   EXACTLY the granted routes (2), the denied route stays candidate, no
   non-GET ever leaves the runtime, and the driver source contains no
   route-specific branching literals;
3. the evaluator (privileged reader) produces a PASS outcome with zero
   leakage and an anonymized result artifact;
4. the MC wiring attaches auth_a_id/auth_b_id to comparison-capable specs
   and feeds account_credentials into the executor (full dispatch proof);
5. unset env vars leave the existing behavior unchanged.
"""
from __future__ import annotations

import json
import os
import re
import socket as _socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from src.reporting.vdp_dataset import ThresholdArtifact, ThresholdMetric, freeze_thresholds

from tests.core.engine.test_master_conductor_vdp_follow_up import (
    _new_mc,
    _scope,
)

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "vdp_holdout_env"

_DUMMY_LLM_ENV = {
    "DEEPSEEK_API_KEY": "iso-fixture-dummy",
    "OPENAI_API_KEY": "iso-fixture-dummy",
    "DEEPINFRA_API_KEY": "iso-fixture-dummy",
    "WANDB_API_KEY": "iso-fixture-dummy",
    "Cerebras_API_KEY": "iso-fixture-dummy",
    "ANY_LLM_API_KEY": "iso-fixture-dummy",
}


def _free_port() -> int:
    sock = _socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _non_get_count(access_log: Path) -> int:
    if not access_log.exists():
        return 0
    count = 0
    for line in access_log.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not re.match(r"^GET\s+", line):
            count += 1
    return count


def _start_fixture(tmp_path) -> tuple:
    """Start the holdout fixture on 127.0.0.1 and wait for the hold out."""
    port = _free_port()
    secrets_out = tmp_path / "secret.json"
    access_log = tmp_path / "access.log"
    env = dict(os.environ)
    env["SECRETS_OUT_PATH"] = str(secrets_out)
    env["ACCESS_LOG_PATH"] = str(access_log)
    proc = subprocess.Popen(
        [
            sys.executable,
            str(FIXTURE_DIR / "holdout_fixture_target.py"),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    holdout = None
    for _ in range(200):
        if secrets_out.exists():
            try:
                holdout = json.loads(secrets_out.read_text(encoding="utf-8"))
                break
            except json.JSONDecodeError:
                pass
        if proc.poll() is not None:
            err = proc.stderr.read().decode() if proc.stderr else ""
            raise RuntimeError(f"fixture exited early: {err}")
        time.sleep(0.05)
    assert holdout is not None, "fixture did not write the hold out"
    return proc, port, holdout, access_log


def _stop(proc) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def _iso_v2_thresholds() -> ThresholdArtifact:
    """iso-v2 thresholds — SAME VALUES as iso-v1 (eval_version differs)."""
    return freeze_thresholds(
        eval_version="iso-v2",
        decided_at="2026-08-05T00:00:00Z",
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
                formula="matched_ground_truth / ground_truth",
                target_set="hidden_holdout", direction="minimum",
            ),
            ThresholdMetric(
                name="budget_compliance", value=0.8,
                formula="within-limit budget entries / eligible entries",
                target_set="hidden_holdout", direction="minimum",
            ),
        ],
    )


def _write_thresholds(tmp_path) -> Path:
    path = tmp_path / "thresholds_v1.json"
    path.write_text(
        json.dumps(_iso_v2_thresholds().to_dict(), sort_keys=True, indent=2),
        encoding="utf-8",
    )
    return path


class TestHoldoutFixture:
    def test_fixture_generates_opaque_routes_and_405(self, tmp_path):
        """3 opaque routes (1 granted, 1 denied, 1 public), generic index
        anchors, auth contract, 405 on state-changing methods, and a clean
        access log (GETs only so far).

        Route count 3 is deliberate: the production hypothesis generator
        caps same-target hypotheses at 3 (diversity budget) and the M0
        gate's exact-set contract allows ONE confirmed verdict per session
        — exactly these three routes become hypotheses deterministically."""
        proc, port, holdout, access_log = _start_fixture(tmp_path)
        try:
            routes = holdout["routes"]
            assert len(routes) == 3
            assert sum(1 for r in routes if r["b_can_read"]) == 1
            assert sum(1 for r in routes if r["kind"] == "public") == 1
            denied = [r for r in routes if r["kind"] == "record" and not r["b_can_read"]]
            assert len(denied) == 1
            for route in routes:
                # 15-hex segments: random/opaque per startup, but shorter
                # than the 16+ hex shape the production observation adapter
                # sanitizes as ``:opaque`` (secret-shaped path segments are
                # masked) — so the routes stay distinguishable.
                assert re.fullmatch(r"/[0-9a-f]{15}", route["opaque"]), route["opaque"]

            base = f"http://127.0.0.1:{port}"
            index = urllib.request.urlopen(f"{base}/", timeout=5).read().decode()
            assert index.count("<a href=") == 3
            for i in range(1, 4):
                assert f"resource-{i}" in index

            # public route: any principal -> 200 public data
            public = next(r for r in routes if r["kind"] == "public")
            public_body = urllib.request.urlopen(
                f"{base}{public['opaque']}", timeout=5
            ).read().decode()
            assert "public" in public_body

            # record route: unauth -> 401
            record = next(r for r in routes if r["kind"] == "record")
            req = urllib.request.Request(f"{base}{record['opaque']}")
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(req, timeout=5)
            assert exc.value.code == 401

            # acct-a (Bearer) -> 200 owner record
            a_secret = holdout["accounts"]["acct-a"]
            req_a = urllib.request.Request(
                f"{base}{record['opaque']}",
                headers={"Authorization": f"Bearer {a_secret}"},
            )
            body_a = json.loads(urllib.request.urlopen(req_a, timeout=5).read().decode())
            assert body_a["owner"] == "acct-a"
            assert "sensitive" in body_a

            # acct-b -> 200 same body (granted) or 403 (denied)
            b_secret = holdout["accounts"]["acct-b"]
            req_b = urllib.request.Request(
                f"{base}{record['opaque']}",
                headers={"Authorization": f"Bearer {b_secret}"},
            )
            try:
                body_b = json.loads(urllib.request.urlopen(req_b, timeout=5).read().decode())
                assert record["b_can_read"] is True
                assert body_b == body_a
            except urllib.error.HTTPError as exc:
                assert exc.value.code == 403
                assert record["b_can_read"] is False

            # denied route: acct-b -> 403
            req_d = urllib.request.Request(
                f"{base}{denied[0]['opaque']}",
                headers={"Authorization": f"Bearer {b_secret}"},
            )
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(req_d, timeout=5)
            assert exc.value.code == 403

            # state-changing methods -> 405 (the ONE intentional non-GET)
            assert _non_get_count(access_log) == 0  # GETs only so far
            req_p = urllib.request.Request(f"{base}/", data=b"x", method="POST")
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(req_p, timeout=5)
            assert exc.value.code == 405
            assert _non_get_count(access_log) == 1  # the single 405 only
        finally:
            _stop(proc)


class TestRuntimeDriver:
    def test_runtime_driver_confirms_via_comparison_no_route_branching(self, tmp_path):
        """The driver runs the production MC path against the fixture with
        the account env vars: EXACTLY the granted route confirms, the
        denied route stays candidate (granted-only rule), zero non-GET
        anywhere, and the driver source carries no route-specific branching
        literals."""
        proc, port, holdout, access_log = _start_fixture(tmp_path)
        try:
            out_dir = tmp_path / "out"
            out_dir.mkdir()
            env = dict(os.environ)
            env.update(_DUMMY_LLM_ENV)
            env.update({
                "VDP_ACCOUNT_A_ID": "acct-a",
                "VDP_ACCOUNT_A_SECRET": holdout["accounts"]["acct-a"],
                "VDP_ACCOUNT_B_ID": "acct-b",
                "VDP_ACCOUNT_B_SECRET": holdout["accounts"]["acct-b"],
                "FIXTURE_BASE_URL": f"http://127.0.0.1:{port}",
                "FIXTURE_SCOPE_HOST": "127.0.0.1",
                "OUT_DIR": str(out_dir),
                "TARGET_NAME": "vdp-holdout",
                "ACCESS_LOG_PATH": str(access_log),
            })
            run = subprocess.run(
                [sys.executable, str(FIXTURE_DIR / "holdout_runtime_driver.py")],
                env=env,
                capture_output=True,
                text=True,
                timeout=240,
            )
            assert run.returncode == 0, (
                f"driver failed rc={run.returncode}\nstdout:\n{run.stdout}\n"
                f"stderr:\n{run.stderr}"
            )

            # session -> canonical summary (verified confirmed verdicts)
            from src.core.engine.vdp_key_registry import VdpKeyRegistry
            from src.core.engine.vdp_session_reader import read_session_compat
            from src.reporting.vdp_canonical import extract_vdp_canonical

            restored = read_session_compat(out_dir / "session_latest.json")
            assert restored is not None
            registry = VdpKeyRegistry.load(out_dir / "keys" / "registry.json")
            summary = extract_vdp_canonical(
                restored, public_key_provider=registry.public_key_provider()
            )
            confirmed = [v for v in summary.verdicts if v.status == "confirmed"]
            candidates = [v for v in summary.verdicts if v.status == "candidate"]
            assert len(confirmed) == 1  # exactly the granted route
            assert len(candidates) == 2  # denied + public stay candidate
            # granted-only rule: the denied route's hypothesis never confirms
            granted_opaque = next(
                r["opaque"] for r in holdout["routes"] if r["b_can_read"]
            )
            denied_opaque = next(
                r["opaque"]
                for r in holdout["routes"]
                if r["kind"] == "record" and not r["b_can_read"]
            )
            asset_by_hyp = {h.hypothesis_id: h.asset for h in summary.hypotheses}
            confirmed_assets = {
                asset_by_hyp.get(v.hypothesis_id) for v in confirmed
            }
            assert granted_opaque in str(list(confirmed_assets))
            denied_hyp = next(
                h.hypothesis_id
                for h in summary.hypotheses
                if denied_opaque in h.asset
            )
            denied_verdict = next(
                v for v in summary.verdicts if v.hypothesis_id == denied_hyp
            )
            assert denied_verdict.status == "candidate"

            # zero non-GET: runtime guard + fixture access log
            run_summary = json.loads(
                (out_dir / "run_summary.json").read_text(encoding="utf-8")
            )
            assert run_summary["non_get_violations"] == 0
            assert _non_get_count(access_log) == 0

            # driver source scan: NO route-specific branching literals.
            # The production state schema key "evidence_records" is the ONE
            # legitimate occurrence of the substring "records" (the MC's
            # runtime-state contract, not a route hint) — it is excluded
            # before the scan.
            driver_src = (FIXTURE_DIR / "holdout_runtime_driver.py").read_text(
                encoding="utf-8"
            )
            scan_src = driver_src.replace('"evidence_records"', '""')
            for banned in ("records", "/public", "owner"):
                assert banned not in scan_src, f"driver leaks literal {banned!r}"
        finally:
            _stop(proc)


class TestHoldoutEvaluator:
    def test_evaluator_anonymized_and_pass(self, tmp_path):
        """Evaluator on the driver session + iso-v2 thresholds + the hold
        out -> PASS (recall 1.0, completeness met, leakage 0); the result
        artifact contains NO raw holdout values (route hex, account
        secrets, fixture sensitive values)."""
        proc, port, holdout, access_log = _start_fixture(tmp_path)
        try:
            out_dir = tmp_path / "out"
            out_dir.mkdir()
            eval_dir = out_dir / "eval"
            eval_dir.mkdir()
            thresholds_path = _write_thresholds(tmp_path)
            env = dict(os.environ)
            env.update(_DUMMY_LLM_ENV)
            env.update({
                "VDP_ACCOUNT_A_ID": "acct-a",
                "VDP_ACCOUNT_A_SECRET": holdout["accounts"]["acct-a"],
                "VDP_ACCOUNT_B_ID": "acct-b",
                "VDP_ACCOUNT_B_SECRET": holdout["accounts"]["acct-b"],
                "FIXTURE_BASE_URL": f"http://127.0.0.1:{port}",
                "FIXTURE_SCOPE_HOST": "127.0.0.1",
                "OUT_DIR": str(out_dir),
                "TARGET_NAME": "vdp-holdout",
                "ACCESS_LOG_PATH": str(access_log),
            })
            driver_run = subprocess.run(
                [sys.executable, str(FIXTURE_DIR / "holdout_runtime_driver.py")],
                env=env,
                capture_output=True,
                text=True,
                timeout=240,
            )
            assert driver_run.returncode == 0, driver_run.stderr

            result_path = out_dir / "eval" / "holdout_result_iso.json"
            eval_env = dict(os.environ)
            eval_env.update(_DUMMY_LLM_ENV)
            eval_env.update({
                "SECRETS_PATH": str(tmp_path / "secret.json"),
                "THRESHOLDS_PATH": str(thresholds_path),
                "SESSION_PATH": str(out_dir / "session_latest.json"),
                "RESULT_PATH": str(result_path),
                "REGISTRY_PATH": str(out_dir / "keys" / "registry.json"),
                "FIXTURE_BASE_URL": f"http://127.0.0.1:{port}",
            })
            eval_run = subprocess.run(
                [sys.executable, str(FIXTURE_DIR / "holdout_evaluator.py")],
                env=eval_env,
                capture_output=True,
                text=True,
                timeout=120,
            )
            assert eval_run.returncode == 0, (
                f"evaluator failed rc={eval_run.returncode}\n"
                f"stdout:\n{eval_run.stdout}\nstderr:\n{eval_run.stderr}"
            )
            assert "iso_eval:outcome:pass" in eval_run.stdout
            assert "iso_eval:leakage:0" in eval_run.stdout

            result = json.loads(result_path.read_text(encoding="utf-8"))
            assert result["outcome"] == "pass"
            assert result["leakage_hits"] == []
            assert result["metrics"]["recall"]["value"] == pytest.approx(1.0)

            # the result artifact carries NO raw holdout values
            raw = result_path.read_text(encoding="utf-8")
            for route in holdout["routes"]:
                assert route["opaque"] not in raw
            for secret in holdout["accounts"].values():
                assert secret not in raw
            # fetch a live sensitive value from the fixture and assert it is
            # absent from the result artifact too
            record = next(r for r in holdout["routes"] if r["kind"] == "record")
            a_secret = holdout["accounts"]["acct-a"]
            req_a = urllib.request.Request(
                f"http://127.0.0.1:{port}{record['opaque']}",
                headers={"Authorization": f"Bearer {a_secret}"},
            )
            body_a = json.loads(urllib.request.urlopen(req_a, timeout=5).read().decode())
            assert body_a["sensitive"] not in raw
        finally:
            _stop(proc)


class TestMcWiring:
    def test_mc_wiring_comparison_specs(self, tmp_path, monkeypatch):
        """With VDP_ACCOUNT_* set: ``_vdp_account_credentials()`` returns
        the store, the queued comparison spec carries auth_a_id/auth_b_id,
        and the dispatched executor runs the A/B comparison (evidence
        carries the cross-account facts)."""
        from types import SimpleNamespace

        from src.core.engine.vdp_follow_up import build_next_action_record
        from src.core.engine.vdp_observation_adapter import ObservationAdapter
        from src.core.models.vdp_contract import HypothesisRecord

        monkeypatch.setenv("VDP_ACCOUNT_A_ID", "acct-a")
        monkeypatch.setenv("VDP_ACCOUNT_A_SECRET", "secret-a-holdout-1")
        monkeypatch.setenv("VDP_ACCOUNT_B_ID", "acct-b")
        monkeypatch.setenv("VDP_ACCOUNT_B_SECRET", "secret-b-holdout-2")

        mc = _new_mc(
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=False, capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        assert mc._vdp_account_credentials() == {
            "acct-a": "secret-a-holdout-1",
            "acct-b": "secret-b-holdout-2",
        }

        observation = ObservationAdapter().adapt_endpoint_signal({
            "url": "https://api.example.com/items",
            "method": "GET",
            "entity_type": "endpoint",
            "primary_label": "resource",
            "candidate_labels": ["object"],
            "params": [],
        })
        assert observation is not None
        hyp = HypothesisRecord(
            hypothesis_id="hyp-p2-1",
            observation_id=observation.observation_id,
            asset="https://api.example.com/items",
            capability="object_read_write_delete",
            hypothesis_text="comparison probe",
            trust_boundary="authenticated",
            actors=["acct-a", "acct-b"],
        )
        mc._vdp_state["vdp_active"] = True
        mc._vdp_state["hypotheses"] = [hyp.to_dict()]
        mc._vdp_state["verdicts"] = [{
            "verdict_id": "vrd-p2-1",
            "hypothesis_id": "hyp-p2-1",
            "status": "candidate",
            "schema_version": 1,
        }]
        na = build_next_action_record("vrd-p2-1", hyp, "authz_impact_not_proven")
        mc._vdp_state["next_actions"] = [na.to_dict()]
        mc._queue_vdp_follow_ups(
            _scope(),
            checkpoint_path=str(tmp_path / "ck.json"),
            observations=[observation],
        )
        tasks = [t for t in mc.task_queue if t.agent_type == "vdp_follow_up"]
        assert tasks
        spec = tasks[0].params["vdp_follow_up_spec"]
        assert spec["evidence_gap"] == "authz_impact_not_proven"
        assert spec["auth_a_id"] == "acct-a"
        assert spec["auth_b_id"] == "acct-b"
        # secrets never enter the spec
        assert "secret-a-holdout-1" not in json.dumps(spec)

        # dispatch: the executor receives the credential store and the
        # comparison actually runs against the fake transport
        class _AuthNet:
            def __init__(self):
                self.calls = []

            async def request(self, method, url, **kwargs):
                self.calls.append((method, url, dict(kwargs)))
                headers = kwargs.get("headers") or {}
                auth = str(headers.get("Authorization", "") or "")
                if auth == "Bearer secret-a-holdout-1":
                    body = '{"owner": "acct-a", "sensitive": "X"}'
                elif auth == "Bearer secret-b-holdout-2":
                    body = '{"sensitive": "X", "owner": "acct-a"}'
                else:
                    body = '{"error": "unauthorized"}'
                return SimpleNamespace(status=200, body=body, elapsed=0.01)

        net = _AuthNet()
        mc.network_client = net  # type: ignore[assignment]  # fake transport
        import asyncio

        result = asyncio.run(mc._dispatch(tasks[0]))
        assert result["data"]["status"] == "executed"
        evidence = mc._vdp_state["evidence_records"][-1]
        er = evidence["execution_result"]
        assert er["cross_account_compared"] is True
        assert er["authz_impact_proven"] == "true"
        assert len(net.calls) == 2  # A then B

    def test_env_unset_credentials_no_behavior_change(self, monkeypatch):
        from types import SimpleNamespace

        for var in (
            "VDP_ACCOUNT_A_ID", "VDP_ACCOUNT_A_SECRET",
            "VDP_ACCOUNT_B_ID", "VDP_ACCOUNT_B_SECRET",
        ):
            monkeypatch.delenv(var, raising=False)
        mc = _new_mc(
            _vdp_mode=SimpleNamespace(
                mode="readonly_enforce", label_leakage_denylist=[],
                kill_switch=False, capability_rules={"follow_up_probe": "allowed"},
            ),
        )
        assert mc._vdp_account_credentials() == {}
