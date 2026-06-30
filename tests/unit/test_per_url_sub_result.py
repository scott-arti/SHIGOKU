"""Phase 8 Step 4: PerUrlSubResult schema tests.

T-5.1: URL worker は共有 context を mutate せず、per-url result を返す。
Post-join merge のみが current_context を更新する。
"""

import pytest

from src.core.models.swarm import PerUrlSubResult
from src.core.models.finding import Finding, Severity, VulnType


class TestPerUrlSubResultSchema:
    """Validate the PerUrlSubResult data model."""

    def test_default_fields(self):
        """Default instance has all required fields with sensible defaults."""
        r = PerUrlSubResult()
        assert r.source_url == ""
        assert r.origin_key == ""
        assert r.findings == []
        assert r.url_result == {}
        assert r.tested_params == []
        assert r.request_fingerprint == ""
        assert r.payload_fingerprint == ""
        assert r.error is None
        assert r.budget_decision == {}
        assert r.status == "pending"

    def test_immutable_after_return(self):
        """The sub-result can be populated and then treated as frozen by caller."""
        f = Finding(
            vuln_type=VulnType.SQLI,
            target_url="http://example.com/login",
            title="SQLi in login",
            severity=Severity.CRITICAL,
            description="Found blind SQLi",
            source_agent="sqli_specialist",
        )
        r = PerUrlSubResult(
            source_url="http://example.com/login",
            origin_key="http://example.com",
            findings=[f],
            url_result={"status_code": 200, "response_length": 1024},
            tested_params=["username", "password"],
            request_fingerprint="sha256:abc123",
            payload_fingerprint="sha256:def456",
            status="success",
            budget_decision={"allowed": True, "remaining": 99},
        )
        assert r.source_url == "http://example.com/login"
        assert r.origin_key == "http://example.com"
        assert len(r.findings) == 1
        assert r.findings[0].severity == Severity.CRITICAL
        assert r.tested_params == ["username", "password"]
        assert r.is_success is True
        assert r.is_skipped_or_rejected is False

    def test_failure_status(self):
        """Status 'failed' with error field."""
        r = PerUrlSubResult(
            source_url="http://example.com/api",
            status="failed",
            error="Connection timeout after 30s",
        )
        assert r.status == "failed"
        assert r.error is not None
        assert r.is_success is False

    def test_skipped_status(self):
        """Status 'skipped' (budget exceeded or rate-limited)."""
        r = PerUrlSubResult(
            source_url="http://example.com/api",
            status="skipped",
            budget_decision={"reason": "per_origin_budget_exceeded", "burst": 10, "used": 10},
        )
        assert r.is_skipped_or_rejected is True

    def test_rejected_status(self):
        """Status 'rejected' (unsafe or scope violation)."""
        r = PerUrlSubResult(
            source_url="http://example.com/api",
            status="rejected",
        )
        assert r.is_skipped_or_rejected is True

    def test_to_dict(self):
        """to_dict() produces serializable output without secrets."""
        f = Finding(
            vuln_type=VulnType.XSS,
            target_url="http://example.com/search",
            title="Reflected XSS",
            severity=Severity.HIGH,
            description="XSS via q param",
            source_agent="xss_specialist",
        )
        r = PerUrlSubResult(
            source_url="http://example.com/search",
            origin_key="http://example.com",
            findings=[f],
            tested_params=["q"],
            request_fingerprint="fp_req",
            payload_fingerprint="fp_pay",
            status="success",
        )
        d = r.to_dict()
        assert d["source_url"] == "http://example.com/search"
        assert d["status"] == "success"
        assert d["findings_count"] == 1
        assert d["request_fingerprint"] == "fp_req"
        assert d["error"] is None
        assert isinstance(d["findings"], list)

    def test_multiple_findings(self):
        """Worker can return multiple findings per URL."""
        f1 = Finding(
            vuln_type=VulnType.SQLI, severity=Severity.HIGH,
            title="A", description="d",
            target_url="http://example.com/a", source_agent="s",
        )
        f2 = Finding(
            vuln_type=VulnType.XSS, severity=Severity.MEDIUM,
            title="B", description="d",
            target_url="http://example.com/b", source_agent="s",
        )
        r = PerUrlSubResult(
            findings=[f1, f2],
            status="success",
        )
        assert len(r.findings) == 2
        assert r.to_dict()["findings_count"] == 2
