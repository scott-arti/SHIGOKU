"""T-2.1 / T-2.2: Forced serial vs gated parity comparator tests."""

import pytest
from src.reporting.parity_comparator import (
    compare_findings,
    extract_finding_keys,
    record_response_differential,
    ParityResult,
    FindingKey,
    ResponseDifferential,
    ALLOWED_DIFFERENTIAL_AXES,
)


def _make_session(findings_list: list) -> dict:
    """Build a minimal session dict compatible with extract_all_findings()."""
    return {
        "completed_tasks": [
            {
                "id": f"task_{i}",
                "result": {"findings": findings_list},
            }
            for i, _ in enumerate([1])
        ],
    }


def _make_finding(severity: str, finding_id: str, target: str = "", evidence_key: str = "") -> dict:
    return {
        "severity": severity,
        "id": finding_id,
        "target": target,
        "evidence_key": evidence_key or f"ev_{finding_id}",
    }


class TestFindingKey:
    def test_build_key_from_finding(self):
        f = _make_finding("High", "ssti-001", target="example.com", evidence_key="ev1")
        keys = extract_finding_keys(_make_session([f]))
        assert len(keys) == 1
        key = next(iter(keys))
        assert key.severity == "high"
        assert key.finding_id == "ssti-001"

    def test_key_equality(self):
        k1 = FindingKey(severity="high", finding_id="abc", target="t", evidence_key="e")
        k2 = FindingKey(severity="high", finding_id="abc", target="t", evidence_key="e")
        assert k1 == k2
        assert hash(k1) == hash(k2)

    def test_set_deduplication(self):
        f1 = _make_finding("High", "dup", target="a.com")
        f2 = _make_finding("High", "dup", target="a.com")
        session = _make_session([f1, f2])
        keys = extract_finding_keys(session)
        assert len(keys) == 1


class TestParityComparator:
    def test_full_parity(self):
        """T-2.1: Same findings in both paths → 100% parity."""
        findings = [
            _make_finding("High", "xss-1"),
            _make_finding("Medium", "info-leak-1"),
        ]
        serial = _make_session(findings)
        gated = _make_session(findings)
        result = compare_findings(serial, gated, high_critical_only=True)
        assert result.parity_achieved is True
        assert result.high_critical_parity is True
        assert len(result.missing_in_gated) == 0
        assert len(result.missing_in_serial) == 0

    def test_missing_in_gated(self):
        """Finding present in serial but missing in gated → no parity."""
        serial = _make_session([_make_finding("High", "sqli-1")])
        gated = _make_session([])
        result = compare_findings(serial, gated, high_critical_only=True)
        assert result.parity_achieved is False
        assert result.high_critical_parity is False
        assert len(result.missing_in_gated) == 1
        assert result.missing_in_gated[0]["id"] == "sqli-1"

    def test_missing_in_serial(self):
        """Finding in gated but not in serial → parity fails (extra finding)."""
        serial = _make_session([])
        gated = _make_session([_make_finding("High", "rce-1")])
        result = compare_findings(serial, gated, high_critical_only=True)
        assert result.parity_achieved is False
        assert len(result.missing_in_serial) == 1

    def test_medium_severity_excluded_from_hc(self):
        """Medium findings should not affect High/Critical parity with high_critical_only=True."""
        serial = _make_session([_make_finding("Medium", "info-1")])
        gated = _make_session([])
        result = compare_findings(serial, gated, high_critical_only=True)
        assert result.high_critical_parity is True
        assert result.high_critical_serial_count == 0
        assert result.high_critical_gated_count == 0
        # HC-only: empty set intersection → 100% parity for HC
        assert result.parity_percentage == 100.0

    def test_empty_sessions(self):
        result = compare_findings({}, {}, high_critical_only=True)
        assert result.parity_achieved is True
        assert result.high_critical_parity is True
        assert result.parity_percentage == 100.0

    def test_to_evidence_dict(self):
        findings = [_make_finding("Critical", "cve-1")]
        serial = _make_session(findings)
        gated = _make_session(findings)
        result = compare_findings(serial, gated, high_critical_only=True)
        evidence = result.to_evidence_dict()
        assert evidence["high_critical_parity"] == 100.0
        assert evidence["serial_gated_match"] is True
        assert evidence["blocking_differential_count"] == 0

    def test_multiple_high_critical_parity(self):
        findings = [
            _make_finding("High", "a1"),
            _make_finding("Critical", "a2"),
            _make_finding("High", "a3"),
        ]
        serial = _make_session(findings)
        gated = _make_session([findings[0], findings[1]] + [_make_finding("Low", "other")])
        result = compare_findings(serial, gated, high_critical_only=True)
        assert result.high_critical_parity is False
        assert result.high_critical_serial_count == 3
        assert result.high_critical_gated_count == 2


class TestResponseDifferential:
    def test_allowed_axes_pass(self):
        """Allowed differential axes do not block."""
        for axis in ALLOWED_DIFFERENTIAL_AXES:
            diff = record_response_differential(axis, "old", "new")
            assert diff.is_blocking() is False

    def test_unknown_axis_blocks(self):
        """Unknown differential axis is blocking."""
        diff = record_response_differential("finding_content", "a", "b")
        assert diff.is_blocking() is True

    def test_differential_values(self):
        diff = record_response_differential("body_length", 1024, 2048)
        assert diff.axis == "body_length"
        assert diff.serial_value == 1024
        assert diff.gated_value == 2048
        assert diff.allowed is True
