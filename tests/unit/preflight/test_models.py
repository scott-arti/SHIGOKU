"""Tests for preflight data models.

Verifies:
- Model instantiation with defaults
- Enum values are correct
- PreflightResult pass/fail properties
- PreflightFailure structure
- ToolRequirement matrix defaults
"""

import pytest
from src.core.preflight.models import (
    PreflightResult,
    PreflightFailure,
    PreflightStatus,
    ToolRequirement,
    ToolStatus,
    ToolCategory,
    AuthProbeResult,
    AuthClassification,
    ResponseClassificationInput,
    ResponseClassificationResult,
    PreflightContext,
    PreflightSnapshot,
    ReasonCodeNamespace,
    GatePhase,
    GatePolicy,
)


class TestPreflightStatus:
    def test_pass_value(self):
        assert PreflightStatus.PASS.value == "pass"

    def test_fail_value(self):
        assert PreflightStatus.FAIL.value == "fail"


class TestPreflightFailure:
    def test_default_severity_is_critical(self):
        f = PreflightFailure(reason_code="TEST_FAIL")
        assert f.severity == "critical"

    def test_checked_at_is_set(self):
        f = PreflightFailure(reason_code="TEST_FAIL")
        assert f.checked_at > 0

    def test_evidence_defaults_to_empty_dict(self):
        f = PreflightFailure(reason_code="TEST_FAIL")
        assert f.evidence == {}

    def test_full_construction(self):
        f = PreflightFailure(
            reason_code="CAIDO_TCP_UNREACHABLE",
            severity="critical",
            category="Caido Connectivity",
            remediation="Start Caido proxy on port 8080",
            evidence={"url": "http://127.0.0.1:8080", "error": "Connection refused"},
        )
        assert f.reason_code == "CAIDO_TCP_UNREACHABLE"
        assert f.severity == "critical"
        assert f.category == "Caido Connectivity"
        assert f.remediation == "Start Caido proxy on port 8080"
        assert f.evidence["url"] == "http://127.0.0.1:8080"


class TestToolRequirement:
    def test_default_category(self):
        t = ToolRequirement(name="test-tool")
        assert t.category == ToolCategory.SCANNING
        assert t.managed is False
        assert t.minimum_version is None
        assert t.needs_templates is False

    def test_wildcard_goals_and_profiles(self):
        t = ToolRequirement(name="katana")
        assert t.required_for_goals == ["*"]
        assert t.required_for_profiles == ["*"]

    def test_specific_goals(self):
        t = ToolRequirement(
            name="dalfox",
            required_for_goals=["xss", "injection", "full"],
        )
        assert "xss" in t.required_for_goals
        assert "recon" not in t.required_for_goals

    def test_timeout_default(self):
        t = ToolRequirement(name="nuclei")
        assert t.timeout_seconds == 3.0


class TestAuthProbeResult:
    def test_default_classification_is_unknown(self):
        r = AuthProbeResult()
        assert r.classification == AuthClassification.UNKNOWN

    def test_empty_redirect_chain(self):
        r = AuthProbeResult()
        assert r.redirect_chain == []

    def test_ai_fields_default(self):
        r = AuthProbeResult()
        assert r.ai_used is False
        assert r.ai_confidence == 0.0
        assert r.ai_label == ""

    def test_authenticated_result(self):
        r = AuthProbeResult(
            classification=AuthClassification.AUTHENTICATED,
            status_code=200,
            title="Dashboard - MyApp",
            is_login_page=False,
            has_challenge=False,
        )
        assert r.classification == AuthClassification.AUTHENTICATED
        assert r.is_login_page is False


class TestResponseClassificationInput:
    def test_defaults(self):
        inp = ResponseClassificationInput()
        assert inp.title == ""
        assert inp.status_code == 0
        assert inp.top_markers == []

    def test_with_markers(self):
        inp = ResponseClassificationInput(
            title="Sign In",
            status_code=200,
            top_markers=["login", "password"],
        )
        assert "login" in inp.top_markers


class TestResponseClassificationResult:
    def test_default_label_is_unknown(self):
        r = ResponseClassificationResult()
        assert r.label == "unknown"
        assert r.confidence == 0.0

    def test_authenticated_result(self):
        r = ResponseClassificationResult(
            label="authenticated",
            confidence=0.95,
            model_used="deepseek-v4-flash",
            elapsed_ms=500.0,
        )
        assert r.label == "authenticated"
        assert r.confidence == 0.95


class TestPreflightContext:
    def test_default_gate_policy(self):
        ctx = PreflightContext()
        assert ctx.gate_policy == GatePolicy.STRICT_PROD

    def test_all_phases_active_by_default(self):
        ctx = PreflightContext()
        assert len(ctx.active_phases) == 4
        assert GatePhase.PHASE_1_DETERMINISTIC in ctx.active_phases
        assert GatePhase.PHASE_4_RESUME_HARDENING in ctx.active_phases

    def test_caido_url_default(self):
        ctx = PreflightContext()
        assert ctx.caido_url == "http://127.0.0.1:8080"

    def test_empty_cookies_and_headers(self):
        ctx = PreflightContext()
        assert ctx.cookies == {}
        assert ctx.auth_headers == {}
        assert ctx.bearer_token == ""

    def test_with_auth(self):
        ctx = PreflightContext(
            bearer_token="test-token",
            cookies={"session": "abc123"},
            auth_headers={"X-Custom": "value"},
        )
        assert ctx.bearer_token == "test-token"
        assert ctx.cookies["session"] == "abc123"


class TestPreflightSnapshot:
    def test_default_status_is_pass(self):
        s = PreflightSnapshot()
        assert s.status == PreflightStatus.PASS

    def test_empty_failures(self):
        s = PreflightSnapshot()
        assert s.failures == []

    def test_caido_fields_default_false(self):
        s = PreflightSnapshot()
        assert s.caido_tcp_ok is False
        assert s.caido_http_ok is False

    def test_empty_tool_results(self):
        s = PreflightSnapshot()
        assert s.tool_results == {}


class TestPreflightResult:
    def test_default_is_pass(self):
        r = PreflightResult()
        assert r.status == PreflightStatus.PASS
        assert r.passed is True
        assert r.failed is False

    def test_fail_result(self):
        r = PreflightResult(status=PreflightStatus.FAIL)
        assert r.passed is False
        assert r.failed is True

    def test_with_failures(self):
        f = PreflightFailure(reason_code="CAIDO_TCP_UNREACHABLE")
        r = PreflightResult(
            status=PreflightStatus.FAIL,
            failures=[f],
        )
        assert len(r.failures) == 1
        assert r.failures[0].reason_code == "CAIDO_TCP_UNREACHABLE"

    def test_resume_allowed_default(self):
        r = PreflightResult()
        assert r.resume_allowed is True


class TestEnums:
    def test_gate_policy_values(self):
        assert GatePolicy.STRICT_PROD.value == "strict-prod"
        assert GatePolicy.STRICT_DEV.value == "strict-dev"

    def test_gate_phase_values(self):
        assert GatePhase.PHASE_1_DETERMINISTIC.value == 1
        assert GatePhase.PHASE_4_RESUME_HARDENING.value == 4

    def test_reason_code_namespace_values(self):
        assert ReasonCodeNamespace.CAIDO.value == "CAIDO"
        assert ReasonCodeNamespace.TOOL.value == "TOOL"
        assert ReasonCodeNamespace.AUTH.value == "AUTH"

    def test_auth_classification_values(self):
        assert AuthClassification.AUTHENTICATED.value == "authenticated"
        assert AuthClassification.LOGIN_PAGE.value == "login_page"
        assert AuthClassification.UNKNOWN.value == "unknown"

    def test_tool_status_values(self):
        assert ToolStatus.OK.value == "ok"
        assert ToolStatus.MISSING.value == "missing"

    def test_tool_category_values(self):
        assert ToolCategory.NETWORK.value == "network"
        assert ToolCategory.SCANNING.value == "scanning"
