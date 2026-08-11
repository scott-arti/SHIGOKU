"""
SGK-2026-0440 Lane A — finding-funnel swarm emit hooks.

Proves (measurement-only, additive, default-off):
- with the funnel enabled, a REAL InjectionManager dispatch (mocked
  transport only) emits F1..F4 records keyed by finding ids, and the
  MasterConductor F0 helper records target_selected for the same URL — the
  merged entry spans F0..F4 with first_failure F3
  phase2_skipped_early_return (Phase 2 skipped on early return)
- with the funnel disabled the SAME dispatch is behaviorally identical
  (stable projection equality) and no funnel records exist
- focused hook-function tests: URL-level skip points map to the exact
  reason codes, and the FindingValidator gate records F4 reached / skipped
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.agents.swarm.base_manager import BaseManagerAgent
from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.engine.finding_funnel_trace import (
    FindingFunnelRecorder,
    get_finding_funnel,
)
from src.core.engine.master_conductor import MasterConductor
from src.core.models.finding import Finding, Severity, VulnType

API_URL = "http://example.com/vulnerabilities/api/v2/user/"


class _SettingsStub:
    """Delegating settings stub: overrides ``diagnostics`` only, everything
    else (llm config, get_proxy_url, ...) comes from the real settings."""

    def __init__(self, real, diagnostics):
        self._real = real
        self.diagnostics = diagnostics

    def __getattr__(self, name):
        return getattr(self._real, name)


def _patch_settings(monkeypatch, *, enabled: bool):
    from src.core.config.settings import DiagnosticsSettings, get_settings

    real = get_settings()
    monkeypatch.setattr(
        "src.core.config.settings.get_settings",
        lambda: _SettingsStub(
            real, DiagnosticsSettings(enabled=enabled, required=False)
        ),
    )


def _mc():
    """Minimal MasterConductor via __new__ (existing test pattern)."""
    mc = object.__new__(MasterConductor)
    mc.context = SimpleNamespace(
        _total_attempts=0, _successful_attempts=0,
        bypass_methods=[], discovered_assets=[],
        target_info={},
    )
    return mc


def _auto_reverified_client() -> MagicMock:
    """Transport sequence reproducing the auto-reverified mass-assignment
    finding (mirrors test_api_minimal_check_promotes_reproducible_*)."""
    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            SimpleNamespace(status=200, body='{"user":"demo"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=204, body="", headers={"Allow": "GET,POST,PATCH,OPTIONS"}),
            SimpleNamespace(status=200, body='{"ok":true}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"ok":true}', headers={"Content-Type": "application/json"}),
        ]
    )
    return request_client


def _api_task(**overrides) -> SimpleNamespace:
    """A dispatch-ready injection task for the api path."""
    params = {
        "target": API_URL,
        "targets": [API_URL],
        "category": "api_data",
        "selection_origin": "master_conductor.recon.api_data",
        "scan_profile": "bbpt",
        "phase1_early_return_on_findings": True,
        "manager_timeout_seconds": 30,
        "per_url_timeout_seconds": 10,
        "phase1_timeout_retries": 0,
        "auth_headers": {"Authorization": "Bearer token"},
        "_context": {},
        "cookies": "",
    }
    params.update(overrides)
    return SimpleNamespace(
        id="funnel-dispatch-1",
        name="Funnel dispatch",
        target=API_URL,
        agent_type="InjectionManagerAgent",
        action="scan",
        params=params,
    )


async def _run_dispatch() -> SimpleNamespace:
    """Real InjectionManager dispatch with a mocked transport only."""
    manager = InjectionManagerAgent(config={"model": "test-model"})
    request_client = _auto_reverified_client()
    manager._resolve_request_client = MagicMock(return_value=request_client)
    with patch(
        "src.core.agents.swarm.injection.manager.resolve_risk_force_allowlist",
        return_value=set(),
    ), patch.object(
        BaseManagerAgent,
        "dispatch",
        new=AsyncMock(return_value=MagicMock(status="success", findings=[], execution_log=[])),
    ):
        result = await manager.dispatch(_api_task())
    return result


# --- stable projection for the disabled-vs-enabled comparison ---------------

_VOLATILE_KEYS = frozenset({
    "discovered_at",
    "_started_monotonic",
    "elapsed_seconds",
    "duration_seconds",
    "manager_elapsed_seconds",
})


def _scrub(obj):
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items() if k not in _VOLATILE_KEYS}
    if isinstance(obj, list):
        return [_scrub(item) for item in obj]
    return obj


def _finding_projection(finding) -> dict:
    return {
        "vuln_type": (
            finding.vuln_type.value
            if hasattr(finding.vuln_type, "value")
            else str(finding.vuln_type)
        ),
        "title": finding.title,
        "target_url": finding.target_url,
        "confidence": round(float(getattr(finding, "confidence", 0.0) or 0.0), 4),
        "tags": sorted(getattr(finding, "tags", []) or []),
    }


def _stable_result(result) -> dict:
    return {
        "status": result.status,
        "swarm_name": result.swarm_name,
        "total_specialists": result.total_specialists,
        "successful_specialists": result.successful_specialists,
        "findings": sorted(
            (_finding_projection(f) for f in result.findings),
            key=lambda p: (p["vuln_type"], p["title"], p["target_url"]),
        ),
        "execution_log": _scrub(result.execution_log),
    }


# ---------------------------------------------------------------------------
# Enabled dispatch emits F0..F4
# ---------------------------------------------------------------------------


class TestEnabledDispatch:
    async def test_real_dispatch_emits_f0_to_f4_records(self, monkeypatch):
        _patch_settings(monkeypatch, enabled=True)
        funnel = get_finding_funnel()
        assert funnel is not None
        funnel.reset()
        try:
            # F0 target_selected comes from the MasterConductor hook function
            # (the same guarded helper _create_attack_tasks_from_recon calls).
            _mc()._finding_funnel_task_event(API_URL, "F0", "reached")

            result = await _run_dispatch()

            assert result.status == "success"
            section = funnel.to_section()
            assert section is not None, "funnel must hold records after dispatch"
            # The api probe emits two manual_verify findings: the
            # auto-reverified mass-assignment candidate and the
            # unauthenticated-api-access candidate.
            assert section["summary"]["total_candidates"] == 2
            entries = {e["finding_id"]: e for e in section["entries"]}
            assert len(entries) == 2
            for entry in section["entries"]:
                # finding id is the md5 Finding.id; F0/F1 merged via attach().
                assert entry["stages"]["F0"] == "reached"
                assert entry["stages"]["F1"] == "reached"
                assert entry["stages"]["F2"] == "reached"
                # Phase 2 skipped on early return -> first failure at F3.
                assert entry["first_failure_stage"] == "F3"
                assert entry["first_failure_reason"] == "phase2_skipped_early_return"
                assert entry["producer"] == "InjectionManager"
            # The auto-reverified candidate captured independent evidence (F4);
            # the other candidate stopped at F3.
            assert any(e["stages"].get("F4") == "reached" for e in section["entries"])
            assert any(e["max_stage_reached"] == "F3" for e in section["entries"])
            assert section["summary"]["by_stage"]["F0"] == 2
            assert section["summary"]["by_reason"] == {"phase2_skipped_early_return": 2}
            assert section["summary"]["suppressed_tasks"] == 0
        finally:
            funnel.reset()


# ---------------------------------------------------------------------------
# Disabled dispatch: no records, behavior identical
# ---------------------------------------------------------------------------


class TestDisabledDispatch:
    async def test_same_dispatch_identical_with_funnel_disabled(self, monkeypatch):
        _patch_settings(monkeypatch, enabled=False)
        assert get_finding_funnel() is None

        baseline = await _run_dispatch()

        _patch_settings(monkeypatch, enabled=True)
        funnel = get_finding_funnel()
        assert funnel is not None
        funnel.reset()
        try:
            enabled_result = await _run_dispatch()
        finally:
            funnel.reset()

        # Same dispatch, same transport mocks -> behaviorally identical
        # results (volatile timing/timestamp fields scrubbed).
        assert _stable_result(baseline) == _stable_result(enabled_result)
        # No funnel records existed during the disabled run: with the flag
        # back off, the accessor returns None again.
        _patch_settings(monkeypatch, enabled=False)
        assert get_finding_funnel() is None

    async def test_disabled_dispatch_leaves_no_pending_records(self, monkeypatch):
        _patch_settings(monkeypatch, enabled=False)
        result = await _run_dispatch()
        assert result.status == "success"
        assert get_finding_funnel() is None


# ---------------------------------------------------------------------------
# Focused hook-function tests (skip points + validator gate)
# ---------------------------------------------------------------------------


class TestFocusedHooks:
    def _funnel(self, monkeypatch) -> FindingFunnelRecorder:
        _patch_settings(monkeypatch, enabled=True)
        funnel = get_finding_funnel()
        assert funnel is not None
        funnel.reset()
        return funnel

    def test_url_skip_points_map_to_reason_codes(self, monkeypatch):
        funnel = self._funnel(monkeypatch)
        try:
            from src.core.agents.swarm.injection import manager as mgr
            from src.core.engine.finding_funnel_trace import url_fingerprint

            # The manager's guarded URL-level hook functions (same code the
            # phase-1 dispatch loop calls at each skip point).
            cases = [
                ("url_skipped_dedupe", "skipped"),
                ("url_skipped_low_ssrf_score", "skipped"),
                ("url_skipped_ssrf_reachability", "skipped"),
                ("url_skipped_timeout_circuit", "skipped"),
                ("url_timeout", "failed"),
                ("url_error", "failed"),
            ]
            for i, (reason, outcome) in enumerate(cases):
                url = f"https://skip-{i}.example/x?id=1"
                funnel.record_task_event(url_fingerprint(url), "F0", "reached")
                mgr._funnel_task_event(url, "F1", outcome, reason_code=reason)
                funnel.attach(f"f-{i}", url_fingerprint(url))
            section = funnel.to_section()
            assert section is not None
            by_id = {e["finding_id"]: e for e in section["entries"]}
            for i, (reason, outcome) in enumerate(cases):
                entry = by_id[f"f-{i}"]
                assert entry["stages"]["F0"] == "reached"
                assert entry["stages"]["F1"] == outcome
                assert entry["first_failure_stage"] == "F1"
                assert entry["first_failure_reason"] == reason
        finally:
            funnel.reset()

    def test_finding_hooks_attach_and_record(self, monkeypatch):
        funnel = self._funnel(monkeypatch)
        try:
            from src.core.agents.swarm.injection import manager as mgr
            from src.core.engine.finding_funnel_trace import url_fingerprint

            finding = Finding(
                vuln_type=VulnType.XSS,
                severity=Severity.MEDIUM,
                title="Reflected XSS in search",
                description="d",
                target_url=API_URL,
            )
            # F0/F1 pending by fingerprint, then the finding-created hook.
            funnel.record_task_event(url_fingerprint(API_URL), "F0", "reached")
            mgr._funnel_task_event(API_URL, "F1", "reached")
            mgr._funnel_finding_created(finding)
            # Validator gate: passes -> F4 reached.
            mgr._funnel_finding_event(finding, "F4", "reached")
            section = funnel.to_section()
            assert section is not None
            entry = section["entries"][0]
            assert entry["finding_id"] == finding.id
            assert entry["stages"]["F0"] == "reached"
            assert entry["stages"]["F1"] == "reached"
            assert entry["stages"]["F2"] == "reached"
            assert entry["stages"]["F4"] == "reached"
        finally:
            funnel.reset()

    async def test_validator_gate_records_f4_reached_and_rejected(self, monkeypatch):
        funnel = self._funnel(monkeypatch)
        try:
            manager = InjectionManagerAgent(config={"model": "test-model"})
            good = Finding(
                vuln_type=VulnType.XSS,
                severity=Severity.MEDIUM,
                title="Good evidence finding",
                description="d",
                target_url=API_URL,
            )
            # The real FindingValidator gate requires actions + metadata.
            good.actions = [{"type": "probe"}]
            good.metadata = {
                "request_url": API_URL,
                "response_status": 200,
                "response_body_sample": "x",
            }
            bad = Finding(
                vuln_type=VulnType.XSS,
                severity=Severity.LOW,
                title="Thought-only finding",
                description="d",
                target_url=API_URL,
            )
            manager.current_context = {"findings": [good, bad]}

            valid, rejected = manager.validate_findings()
            assert rejected, "thought-only finding must be rejected (unchanged gate)"
            section = funnel.to_section()
            assert section is not None
            by_id = {e["finding_id"]: e for e in section["entries"]}
            assert by_id[good.id]["stages"]["F4"] == "reached"
            assert by_id[bad.id]["stages"]["F4"] == "skipped"
            assert by_id[bad.id]["first_failure_reason"] == "finding_validator_rejected"
        finally:
            funnel.reset()
