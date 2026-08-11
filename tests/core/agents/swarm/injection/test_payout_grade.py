"""
SGK-2026-0441 Lane A — payout-grade PoC gate tests.

Covers:
- ``evaluate_payout_grade`` PASS / fail-closed paths (reproducibility,
  firing markers, impact, unknown category, malformed input)
- ``payout_grade_stage`` / ``finding_payload`` / ``has_explicit_refute_signal`` /
  ``assert_read_only_probe`` helper contract
- ``should_auto_early_return`` payout_grade_hold predicate (Lane B
  reconciliation point)
- real-dispatch funnel emission at the early-return gate (F4 reached vs
  F4 skipped evidence_insufficient; no-op when funnel disabled)
- should_stop wiring for all five specialists (payout-grade stop trigger,
  fail-closed when no candidate state)
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.agents.swarm.injection.payout_grade import (
    PayoutGradeResult,
    assert_read_only_probe,
    evaluate_payout_grade,
    finding_payload,
    has_explicit_refute_signal,
    payout_grade_stage,
)
from src.core.engine.finding_funnel_trace import get_finding_funnel
from src.core.models.finding import Finding, Severity, VulnType

API_URL = "http://example.com/vulnerabilities/api/v2/user/"


# ---------------------------------------------------------------------------
# Finding-dict builders (Finding.to_dict() shape)
# ---------------------------------------------------------------------------


def _sqli_finding(**overrides) -> dict:
    payload = {
        "vuln_type": "sqli",
        "evidence": {},
        "additional_info": {
            "poc_request": "GET /vulnerabilities/sqli/?id=1%27 HTTP/1.1\nHost: example.com",
            "poc_response": (
                "HTTP/1.1 200\n\nYou have an error in your SQL syntax near '''"
            ),
        },
        "impact": "Attacker can extract the full user database via UNION payloads.",
        "reproduction_steps": [
            "Send GET /vulnerabilities/sqli/?id=1'",
            "Observe the SQL syntax error in the response body",
        ],
    }
    payload.update(overrides)
    return payload


def _structured_sqli_finding(**overrides) -> dict:
    payload = {
        "vuln_type": "sqli",
        "evidence": {
            "request_method": "GET",
            "request_url": "http://example.com/vulnerabilities/sqli/?id=1'",
            "response_status": 200,
            "response_body": "Fatal error: mysqli_sql_exception SQL syntax",
        },
        "additional_info": {},
        "impact": "Attacker can extract the full user database.",
        "reproduction_steps": ["Send GET /vulnerabilities/sqli/?id=1'"],
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# evaluate_payout_grade — PASS path
# ---------------------------------------------------------------------------


class TestPayoutGradePass:
    def test_sqli_poc_pair_is_payout_grade(self) -> None:
        result = evaluate_payout_grade(_sqli_finding())
        assert result.payout_grade is True
        assert result.marker == "sql_error"
        assert result.reason == "payout_grade_satisfied"
        assert result.evidence_refs == [
            "additional_info.poc_request",
            "additional_info.poc_response",
        ]

    def test_sqli_structured_evidence_is_payout_grade(self) -> None:
        result = evaluate_payout_grade(_structured_sqli_finding())
        assert result.payout_grade is True
        assert result.marker == "sql_error"
        assert result.evidence_refs == [
            "evidence.request_method",
            "evidence.request_url",
            "evidence.response_status",
            "evidence.response_body",
        ]

    def test_xss_reflected_marker(self) -> None:
        finding = {
            "vuln_type": "xss",
            "additional_info": {
                "poc_request": "GET /xss/?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\nHost: x",
                "poc_response": "HTTP/1.1 200\n\n<html><script>alert(1)</script></html>",
            },
            "impact": "Session theft via reflected XSS.",
            "reproduction_steps": ["Visit the crafted URL"],
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "reflected_payload"

    def test_xss_reflection_observed_marker(self) -> None:
        # finding-level analog of the specialist's diff == "reflected"
        finding = {
            "vuln_type": "xss",
            "additional_info": {
                "poc_request": "GET /xss/?q=canary HTTP/1.1\nHost: x",
                "poc_response": "HTTP/1.1 200\n\ncanary",
                "reflection_observed": True,
            },
            "impact": "Session theft via reflected XSS.",
            "reproduction_steps": ["Visit the crafted URL"],
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "reflected_payload"

    def test_lfi_file_content_marker(self) -> None:
        finding = {
            "vuln_type": "lfi",
            "evidence": {
                "request_method": "GET",
                "request_url": "http://example.com/page.php?f=../../etc/passwd",
                "response_status": 200,
                "response_body": (
                    "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data"
                ),
            },
            "additional_info": {},
            "impact": "Arbitrary local file disclosure.",
            "reproduction_steps": ["Send GET /page.php?f=../../etc/passwd"],
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "file_content_leak"

    def test_command_execution_marker(self) -> None:
        finding = {
            "vuln_type": "os_command_injection",
            "additional_info": {
                "poc_request": "GET /cmd?q=id HTTP/1.1\nHost: x",
                "poc_response": "HTTP/1.1 200\n\nuid=1000(www-data) gid=1000(www-data)",
            },
            "impact": "Remote command execution as www-data.",
            "reproduction_steps": ["Send GET /cmd?q=id"],
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "command_execution"

    def test_ssrf_callback_marker(self) -> None:
        finding = {
            "vuln_type": "ssrf",
            "evidence": {
                "request_method": "GET",
                "request_url": "http://example.com/fetch?url=http://169.254.169.254/latest/meta-data/",
                "response_status": 200,
                "response_body": "ami-1234567890abcdef0",
            },
            "additional_info": {},
            "impact": "Cloud metadata exposure via SSRF.",
            "reproduction_steps": ["Send the fetch URL"],
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "ssrf_callback"

    def test_authz_diff_marker(self) -> None:
        finding = {
            "vuln_type": "broken_access_control",
            "evidence": {
                "request_method": "GET",
                "request_url": API_URL,
                "response_status": 200,
                "response_body": '{"user":"demo"}',
            },
            "additional_info": {
                "authz_differential": {
                    "scenario": "unauthenticated_api_access",
                    "signals": ["auth_success", "unauth_success"],
                }
            },
            "impact": "Unauthenticated access to sensitive user data.",
            "reproduction_steps": ["GET the endpoint without credentials"],
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True
        assert result.marker == "authz_diff"


# ---------------------------------------------------------------------------
# evaluate_payout_grade — fail-closed paths
# ---------------------------------------------------------------------------


class TestPayoutGradeFailClosed:
    def test_missing_evidence_when_nothing_captured(self) -> None:
        result = evaluate_payout_grade(
            {
                "vuln_type": "sqli",
                "evidence": {},
                "additional_info": {},
                "impact": "i",
                "reproduction_steps": ["s"],
            }
        )
        assert result.payout_grade is False
        assert result.reason == "missing_evidence"
        assert result.marker is None

    def test_missing_evidence_when_structured_body_empty(self) -> None:
        finding = _structured_sqli_finding()
        finding["evidence"]["response_body"] = ""
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "missing_evidence"

    def test_missing_evidence_when_status_not_int(self) -> None:
        finding = _structured_sqli_finding()
        finding["evidence"]["response_status"] = "200"
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "missing_evidence"

    def test_not_reproducible_when_poc_pair_incomplete(self) -> None:
        finding = _sqli_finding()
        finding["additional_info"]["poc_response"] = "200 OK (no status line)"
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "not_reproducible"

    def test_no_firing_marker(self) -> None:
        finding = _sqli_finding()
        finding["additional_info"]["poc_response"] = "HTTP/1.1 200\n\nWelcome to the dashboard"
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"
        assert result.marker is None

    def test_missing_impact(self) -> None:
        finding = _sqli_finding()
        finding["impact"] = ""
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "missing_impact"
        # marker resolved before impact (deterministic ordering)
        assert result.marker == "sql_error"

    def test_missing_reproduction_steps(self) -> None:
        finding = _sqli_finding()
        finding["reproduction_steps"] = []
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "missing_impact"

    def test_vdp_style_markers_satisfy_impact(self) -> None:
        finding = _sqli_finding()
        finding["impact"] = ""
        finding["reproduction_steps"] = []
        finding["additional_info"]["state_change_verified"] = True
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is True

    def test_unknown_category(self) -> None:
        finding = _sqli_finding()
        finding["vuln_type"] = "brand_new_vuln_class"
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "unknown_category"
        assert result.marker is None

    def test_authz_marker_requires_proof(self) -> None:
        finding = {
            "vuln_type": "broken_access_control",
            "evidence": {
                "request_method": "GET",
                "request_url": API_URL,
                "response_status": 200,
                "response_body": '{"user":"demo"}',
            },
            "additional_info": {
                "authz_differential": {
                    "scenario": "unauthenticated_api_access",
                    "signals": ["auth_success"],
                }
            },
            "impact": "Unauthenticated access.",
            "reproduction_steps": ["GET without credentials"],
        }
        result = evaluate_payout_grade(finding)
        assert result.payout_grade is False
        assert result.reason == "no_firing_marker"

    def test_malformed_inputs_never_raise(self) -> None:
        for bad in (None, "string", 42, [], ("sqli",), object()):
            result = evaluate_payout_grade(bad)  # type: ignore[arg-type]
            assert result.payout_grade is False
            assert result.reason == "missing_evidence"

    def test_non_dict_nested_fields_fail_closed(self) -> None:
        result = evaluate_payout_grade(
            {"vuln_type": "sqli", "evidence": "nope", "additional_info": None}
        )
        assert result.payout_grade is False
        assert result.reason == "missing_evidence"

    def test_finding_object_input_fails_closed(self) -> None:
        # The public contract is the dict shape; objects must be projected
        # via finding_payload() first.
        finding = Finding(
            vuln_type=VulnType.SQLI,
            severity=Severity.HIGH,
            title="t",
            description="d",
            target_url="http://example.com/",
        )
        result = evaluate_payout_grade(finding)  # type: ignore[arg-type]
        assert result.payout_grade is False


# ---------------------------------------------------------------------------
# Helper contract
# ---------------------------------------------------------------------------


class TestHelperContract:
    def test_payout_grade_stage(self) -> None:
        ok = PayoutGradeResult(True, "payout_grade_satisfied", [], "sql_error")
        no = PayoutGradeResult(False, "missing_impact", [], None)
        assert payout_grade_stage("f-1", ok) == "F4"
        assert payout_grade_stage("f-1", no) is None

    def test_finding_payload_projects_finding_object(self) -> None:
        finding = Finding(
            vuln_type=VulnType.SQLI,
            severity=Severity.HIGH,
            title="t",
            description="d",
            target_url="http://example.com/",
        )
        payload = finding_payload(finding)
        assert payload["vuln_type"] == "sqli"
        assert isinstance(payload["evidence"], dict)
        assert isinstance(payload["additional_info"], dict)

    def test_finding_payload_fail_closed(self) -> None:
        assert finding_payload(None) == {}
        assert finding_payload(42) == {}

    def test_refute_signal_only_explicit(self) -> None:
        assert has_explicit_refute_signal({"additional_info": {"falsification": True}}) is True
        assert (
            has_explicit_refute_signal(
                {"additional_info": {"payload_delivery": {"delivered": False}}}
            )
            is True
        )
        assert has_explicit_refute_signal({"additional_info": {}}) is False
        # absence of delivery is NOT a refutation
        assert has_explicit_refute_signal({"additional_info": {"delivered": False}}) is False
        assert has_explicit_refute_signal(None) is False

    def test_read_only_probe_guard(self) -> None:
        assert assert_read_only_probe("GET", "http://example.com/") is True
        assert assert_read_only_probe("HEAD", "https://example.com/") is True
        assert assert_read_only_probe("OPTIONS", "http://example.com/") is True
        assert assert_read_only_probe("get", "http://example.com/") is True
        assert assert_read_only_probe("POST", "http://example.com/") is False
        assert assert_read_only_probe("PUT", "http://example.com/") is False
        assert assert_read_only_probe("DELETE", "http://example.com/") is False
        assert assert_read_only_probe("GET", "") is False
        assert assert_read_only_probe("GET", "ftp://example.com/") is False
        assert assert_read_only_probe(None, "http://example.com/") is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# should_auto_early_return payout_grade_hold predicate
# ---------------------------------------------------------------------------


def _policy_task(**params) -> SimpleNamespace:
    return SimpleNamespace(params=params)


class TestEarlyReturnPredicate:
    def _call(self, *, hold: bool) -> bool:
        from src.core.agents.swarm.injection.manager_internal.execution_policy import (
            should_auto_early_return,
        )

        return should_auto_early_return(
            _policy_task(phase1_auto_early_return_on_findings=True),
            phase1_findings=[object()],
            phase1_signals={"tool_error": False},
            phase1_vuln_types={"lfi"},
            coerce_bool=lambda value, default: bool(default if value is None else value),
            payout_grade_hold=hold,
        )

    def test_all_payout_grade_keeps_old_decision(self) -> None:
        # lfi is a fast type: payout-grade-complete run keeps early-return.
        assert self._call(hold=False) is True

    def test_any_non_payout_grade_holds_for_phase2(self) -> None:
        assert self._call(hold=True) is False

    def test_default_parameter_preserves_behavior(self) -> None:
        from src.core.agents.swarm.injection.manager_internal.execution_policy import (
            should_auto_early_return,
        )

        # without payout_grade_hold (Lane B reconciliation: default False)
        assert should_auto_early_return(
            _policy_task(phase1_auto_early_return_on_findings=True),
            phase1_findings=[object()],
            phase1_signals={"tool_error": False},
            phase1_vuln_types={"lfi"},
            coerce_bool=lambda value, default: bool(default if value is None else value),
        ) is True

    def test_hold_does_not_change_empty_or_tool_error_paths(self) -> None:
        from src.core.agents.swarm.injection.manager_internal.execution_policy import (
            should_auto_early_return,
        )

        assert should_auto_early_return(
            _policy_task(phase1_auto_early_return_on_findings=True),
            phase1_findings=[],
            phase1_signals={"tool_error": False},
            phase1_vuln_types=set(),
            coerce_bool=lambda value, default: bool(default if value is None else value),
            payout_grade_hold=False,
        ) is False
        assert should_auto_early_return(
            _policy_task(phase1_auto_early_return_on_findings=True),
            phase1_findings=[object()],
            phase1_signals={"tool_error": True},
            phase1_vuln_types={"lfi"},
            coerce_bool=lambda value, default: bool(default if value is None else value),
            payout_grade_hold=True,
        ) is False


# ---------------------------------------------------------------------------
# Real-dispatch funnel emission at the early-return gate (mirrors
# tests/unit/engine/test_finding_funnel_swarm_hooks.py transport harness)
# ---------------------------------------------------------------------------


class _SettingsStub:
    """Delegating settings stub: overrides ``diagnostics`` only."""

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


def _api_task() -> SimpleNamespace:
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
    return SimpleNamespace(
        id="payout-dispatch-1",
        name="Payout dispatch",
        target=API_URL,
        agent_type="InjectionManagerAgent",
        action="scan",
        params=params,
    )


async def _run_dispatch():
    from src.core.agents.swarm.base_manager import BaseManagerAgent
    from src.core.agents.swarm.injection.manager import InjectionManagerAgent

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
        return await manager.dispatch(_api_task())  # type: ignore[arg-type]


class TestGateFunnelEmission:
    async def test_non_payout_grade_candidates_record_f4_skipped(self, monkeypatch):
        _patch_settings(monkeypatch, enabled=True)
        funnel = get_finding_funnel()
        assert funnel is not None
        funnel.reset()
        try:
            result = await _run_dispatch()
            assert result.status == "success"
            section = funnel.to_section()
            assert section is not None
            # The api probe emits two manual_verify candidates; neither
            # carries a payout-grade PoC -> both F4 skipped at the gate.
            assert section["summary"]["total_candidates"] == 2
            for entry in section["entries"]:
                assert entry["stages"]["F2"] == "reached"
                assert entry["stages"]["F4"] == "skipped"
                assert entry["first_failure_stage"] == "F3"
                assert entry["first_failure_reason"] == "phase2_skipped_early_return"
            assert section["summary"]["by_reason"] == {"phase2_skipped_early_return": 2}
        finally:
            funnel.reset()

    async def test_payout_grade_candidate_records_f4_reached(self, monkeypatch):
        _patch_settings(monkeypatch, enabled=True)
        funnel = get_finding_funnel()
        assert funnel is not None
        funnel.reset()
        try:
            from src.core.agents.swarm.injection import manager as mgr

            real_eval = mgr.evaluate_payout_grade
            calls = {"n": 0}

            def fake_eval(payload):
                if calls["n"] == 0:
                    calls["n"] += 1
                    return PayoutGradeResult(
                        True,
                        "payout_grade_satisfied",
                        ["additional_info.poc_request", "additional_info.poc_response"],
                        "authz_diff",
                    )
                calls["n"] += 1
                return real_eval(payload)

            monkeypatch.setattr(mgr, "evaluate_payout_grade", fake_eval)
            result = await _run_dispatch()
            assert result.status == "success"
            section = funnel.to_section()
            assert section is not None
            reached = [
                e for e in section["entries"] if e["stages"].get("F4") == "reached"
            ]
            assert len(reached) == 1
            # Early-return path: no F5 stage is recorded (Phase 2 never ran).
            assert all("F5" not in e["stages"] for e in section["entries"])
        finally:
            funnel.reset()

    async def test_funnel_disabled_is_a_no_op(self, monkeypatch):
        _patch_settings(monkeypatch, enabled=False)
        assert get_finding_funnel() is None
        result = await _run_dispatch()
        assert result.status == "success"
        assert get_finding_funnel() is None


# ---------------------------------------------------------------------------
# should_stop wiring (⑤) — payout-grade stop trigger per specialist
# ---------------------------------------------------------------------------


def _step(action: str = "request"):
    from src.core.agents.swarm.thought_loop import ThoughtStep

    return ThoughtStep(turn=1, thought="", action=action, action_input="", observation="")


class TestShouldStopWiring:
    @pytest.mark.asyncio
    async def test_sqli_should_stop_on_payout_grade(self) -> None:
        from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter

        hunter = SmartSQLiHunter(config={"model": "test-model", "mode": "ctf"})
        hunter._last_poc_request = "GET /vulnerabilities/sqli/?id=1%27 HTTP/1.1\nHost: example.com"
        hunter._last_poc_response = "HTTP/1.1 200\n\nYou have an error in your SQL syntax"
        hunter.evidence = "SQL Injection confirmed in id"
        hunter.used_payloads = ["1'"]
        assert await hunter.should_stop(_step("request")) is True

    @pytest.mark.asyncio
    async def test_sqli_should_stop_fail_closed_without_candidate(self) -> None:
        from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter

        hunter = SmartSQLiHunter(config={"model": "test-model", "mode": "ctf"})
        assert await hunter.should_stop(_step("request")) is False

    @pytest.mark.asyncio
    async def test_xss_should_stop_on_payout_grade(self) -> None:
        from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter

        hunter = SmartXSSHunter()
        hunter._last_poc_request = "GET /xss/?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\nHost: example.com"
        hunter._last_poc_response = "HTTP/1.1 200\n\n<script>alert(1)</script>"
        hunter.evidence = "Reflected XSS confirmed"
        hunter.used_payloads = ["<script>alert(1)</script>"]
        assert await hunter.should_stop(_step("request")) is True

    @pytest.mark.asyncio
    async def test_lfi_should_stop_on_payout_grade(self) -> None:
        from src.core.agents.swarm.injection.smart_lfi import SmartLFIHunter

        hunter = SmartLFIHunter(config={"model": "test-model", "mode": "ctf"})
        hunter.last_delivery_evidence = {
            "request_method": "GET",
            "request_url": "http://example.com/page.php?f=../../etc/passwd",
            "response_status": 200,
            "response_body": "root:x:0:0:root:/root:/bin/bash",
            "poc_request": "GET /page.php?f=../../etc/passwd HTTP/1.1\nHost: example.com",
            "poc_response": "HTTP/1.1 200\n\nroot:x:0:0:root:/root:/bin/bash",
        }
        hunter.evidence = "LFI confirmed: /etc/passwd read"
        hunter.used_payloads = ["../../etc/passwd"]
        assert await hunter.should_stop(_step("request")) is True

    @pytest.mark.asyncio
    async def test_cmd_ssrf_should_stop_on_payout_grade(self) -> None:
        from src.core.agents.swarm.injection.smart_cmd_ssrf import SmartCmdSSRFHunter

        hunter = SmartCmdSSRFHunter(config={"model": "test-model", "mode": "ctf"})
        hunter.last_delivery_evidence = {
            "request_method": "GET",
            "request_url": "http://example.com/cmd?q=id",
            "response_status": 200,
            "response_body": "uid=1000(www-data) gid=1000(www-data)",
            "poc_request": "GET /cmd?q=id HTTP/1.1\nHost: example.com",
            "poc_response": "HTTP/1.1 200\n\nuid=1000(www-data)",
        }
        hunter.evidence = "Command injection confirmed"
        hunter.used_payloads = [";id;"]
        assert await hunter.should_stop(_step("request")) is True

    @pytest.mark.asyncio
    async def test_cmd_ssrf_should_stop_fail_closed_without_candidate(self) -> None:
        from src.core.agents.swarm.injection.smart_cmd_ssrf import SmartCmdSSRFHunter

        hunter = SmartCmdSSRFHunter(config={"model": "test-model", "mode": "ctf"})
        assert await hunter.should_stop(_step("request")) is False

    @pytest.mark.asyncio
    async def test_fuzzer_should_stop_on_payout_grade_candidate(self) -> None:
        from src.core.agents.swarm.injection.actor_critic_fuzzer import ActorCriticFuzzer

        fuzzer = ActorCriticFuzzer(target_request=MagicMock())
        # Lane B wiring hook: a caller may attach a candidate finding dict.
        setattr(fuzzer, "payout_grade_candidate", _sqli_finding())
        assert await fuzzer.should_stop(_step("request")) is True

    @pytest.mark.asyncio
    async def test_fuzzer_should_stop_fail_closed_without_candidate(self) -> None:
        from src.core.agents.swarm.injection.actor_critic_fuzzer import ActorCriticFuzzer

        fuzzer = ActorCriticFuzzer(target_request=MagicMock())
        assert await fuzzer.should_stop(_step("request")) is False
