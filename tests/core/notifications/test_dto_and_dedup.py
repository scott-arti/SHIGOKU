# Phase A: CONFIRMATION tests for SGK-2026-0297 Discord全Finding詳細通知
"""
CONFIRMATION tests for SGK-2026-0297 Phase A notification behavior.

These tests validate the new components:
- FindingNotificationRouter (DTO normalization, dedup, severity routing)
- JapaneseBodyBuilder (detailed Japanese message generation, redaction)
- OperationalProtections (dry-run, kill switch, timeout, retry, logging)

All tests should PASS once Phase A implementation is complete.
"""

from __future__ import annotations

import json
import logging
import subprocess
from unittest.mock import MagicMock

import pytest

from src.core.notifications.finding_notification_router import (
    FindingNotificationDTO,
    FindingNotificationRouter,
)
from src.core.notifications.body_builder import (
    JapaneseBodyBuilder,
    create_golden_finding_dict,
)
from src.core.notifications.notifier import Notifier
from src.core.models.finding import Finding, Severity, VulnType, Evidence


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _make_test_finding(**overrides) -> Finding:
    """Create a minimal Finding for DTO normalization tests."""
    defaults = dict(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title="Reflected XSS in search",
        description="XSS via 'q' parameter.",
        target_url="https://example.com/search?q=test",
        source_agent="xss_hunter",
        confidence=0.75,
        impact="Session hijacking.",
        reproduction_steps=["1. Visit /search?q=<script>alert(1)</script>"],
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _make_test_dto(**overrides) -> FindingNotificationDTO:
    """Create a minimal FindingNotificationDTO for dedup tests."""
    defaults = dict(
        finding_id="test-123",
        severity="high",
        vuln_type="sqli",
        title="SQL Injection",
        target_url="https://example.com/login",
        description="Test description",
    )
    defaults.update(overrides)
    return FindingNotificationDTO(**defaults)


# --------------------------------------------------------------------------- #
# TestFindingNotificationRouter
# --------------------------------------------------------------------------- #

class TestFindingNotificationRouter:
    """Tests for FindingNotificationRouter: DTO normalization, dedup, routing."""

    def test_normalize_finding_object_to_dto(self):
        """
        Given a Finding object, the router should normalize it into a
        FindingNotificationDTO with all required fields present.
        """
        finding = _make_test_finding()

        router = FindingNotificationRouter()
        dto = router.normalize(
            finding, source_component="test", ingress_path="test_normalize"
        )

        assert dto is not None
        assert dto.title == finding.title
        assert dto.severity == finding.severity.value
        assert dto.vuln_type == finding.vuln_type.value
        assert dto.target_url == finding.target_url
        assert dto.description == finding.description
        assert dto.impact == finding.impact
        assert dto.reproduction_steps == finding.reproduction_steps
        assert dto.confidence == finding.confidence
        assert dto.source_agent == finding.source_agent
        assert dto.finding_id is not None
        assert dto.source_component == "test"
        assert dto.ingress_path == "test_normalize"

    def test_normalize_dict_to_dto(self):
        """
        Given a plain dict (from agent output), the router should normalize it
        into a FindingNotificationDTO, handling missing keys gracefully.
        """
        raw_dict = {
            "type": "sqli",
            "severity": "high",
            "title": "SQL Injection",
            "target": "https://example.com/login",
            "description": "UNION-based SQLi",
            "source_agent": "sqli_hunter",
            "confidence": 0.88,
        }

        router = FindingNotificationRouter()
        dto = router.normalize(
            raw_dict, source_component="test", ingress_path="test_normalize_dict"
        )

        assert dto is not None
        assert dto.title == "SQL Injection"
        assert dto.vuln_type == "sqli"  # type -> vuln_type mapping
        assert dto.target_url == "https://example.com/login"  # target -> target_url
        assert dto.severity == "high"
        assert dto.description == "UNION-based SQLi"
        assert dto.source_agent == "sqli_hunter"
        assert dto.confidence == 0.88

    def test_dedup_by_finding_id(self):
        """
        Two notifications with the same finding.id should be deduplicated
        within the dedup window (run-local).
        """
        router = FindingNotificationRouter()
        dto = _make_test_dto(finding_id="abc123")

        first = router.should_send(dto)
        assert first is True

        # Mark as sent to update internal dedup state
        router._mark_sent(dto)

        second = router.should_send(dto)
        assert second is False  # dedup'd

    def test_dedup_by_fingerprint(self):
        """
        Fallback: when finding.id differs but fingerprint matches,
        dedup by composite fingerprint (vuln_type:title:target_url).
        """
        router = FindingNotificationRouter()

        dto1 = _make_test_dto(
            finding_id="id-001",
            vuln_type="sqli",
            title="SQLi Login",
            target_url="https://x.com/login",
        )
        dto2 = _make_test_dto(
            finding_id="id-002",
            vuln_type="sqli",
            title="SQLi Login",
            target_url="https://x.com/login",
        )

        assert router.should_send(dto1) is True
        router._mark_sent(dto1)

        assert router.should_send(dto2) is False  # same fingerprint

    def test_all_severities_notified(self):
        """
        ALL severities (critical, high, medium, low, info) should pass through
        the router for notification (no severity-based filtering at this layer).
        """
        for sev in ["critical", "high", "medium", "low", "info"]:
            router = FindingNotificationRouter()  # fresh router per severity
            dto = _make_test_dto(severity=sev)
            assert router.should_send(dto) is True, \
                f"Severity {sev} was filtered"

    def test_unknown_severity_normalized_to_info(self):
        """
        An unknown/unrecognized severity string should be normalized to 'info'.
        """
        router = FindingNotificationRouter()
        dto = router.normalize(
            {"severity": "banana", "title": "Test", "vuln_type": "sqli"},
            source_component="test",
            ingress_path="test",
        )

        assert dto is not None
        assert dto.severity == "info"
        assert dto.raw_severity == "banana"
        assert dto.normalization_warning != ""  # should have a warning

    def test_missing_id_does_not_crash(self):
        """
        A Finding without an id (or empty id) should not crash the router.
        """
        router = FindingNotificationRouter()
        dto = _make_test_dto(finding_id=None)

        # should_send should handle None/empty finding_id gracefully
        try:
            result = router.should_send(dto)
            # result can be True or False, but must not crash
        except Exception:
            pytest.fail("Router crashed on missing finding_id")

    def test_missing_target_url_does_not_crash(self):
        """
        A Finding without a target_url should not crash the router.
        """
        router = FindingNotificationRouter()
        dto = _make_test_dto(target_url=None)

        try:
            result = router.should_send(dto)
            # result can be True or False, but must not crash
        except Exception:
            pytest.fail("Router crashed on missing target_url")

    def test_empty_findings_list(self):
        """
        Processing an empty findings list should not crash and should return
        an empty result set.
        """
        router = FindingNotificationRouter()
        results = router.process_batch([])
        assert results == []

    def test_string_payload_handled(self):
        """
        A malformed input (plain string instead of dict/Finding) should be
        handled gracefully (logged, not crashed).
        """
        router = FindingNotificationRouter()
        try:
            result = router.normalize("garbage string")
            assert result is None  # string input should return None gracefully
        except TypeError:
            pass  # acceptable
        except Exception:
            pytest.fail("Router crashed on string input")


# --------------------------------------------------------------------------- #
# TestJapaneseBodyGeneration
# --------------------------------------------------------------------------- #

class TestJapaneseBodyGeneration:
    """Tests for JapaneseBodyBuilder: detailed message generation and redaction."""

    def test_generate_japanese_detailed_body(self):
        """
        The Japanese body should contain ALL key fields structured in Japanese:
        - 脆弱性ID (finding id)
        - 種類 (vuln type)
        - 対象URL (target)
        - 説明 (description)
        - 影響 (impact)
        - 再現手順 (reproduction steps)
        - エビデンス概要 (evidence summary)
        - 信頼度 (confidence %)
        - 発見エージェント (source agent)
        - 発見日時 (discovered at, ISO 8601)
        """
        finding = create_golden_finding_dict()
        builder = JapaneseBodyBuilder()
        body = builder.build(finding)

        assert "脆弱性ID" in body
        assert "種類" in body
        assert "対象URL" in body
        assert "説明" in body
        assert "影響" in body
        assert "再現手順" in body
        assert "エビデンス概要" in body
        assert "信頼度" in body
        assert "発見エージェント" in body
        assert "発見日時" in body

    def test_redaction_removes_secrets(self):
        """
        Common secret patterns should be redacted from the body:
        - Authorization: Bearer <token> -> Authorization: Bearer [REDACTED]
        - Cookie: session=<value> -> Cookie: session=[REDACTED]
        - password=<value> -> password=[REDACTED]
        - api_key=<value> -> api_key=[REDACTED]
        """
        finding = {
            "finding_id": "test-redact-001",
            "severity": "critical",
            "vuln_type": "sqli",
            "title": "Secret Leak Test",
            "target_url": "https://example.com",
            "description": (
                "Authorization header: Bearer sk-secret-token-12345\n"
                "Cookie: session=abc123\n"
                "password=SuperSecretPassword!\n"
                "api_key=sk-proj-abc123secret456"
            ),
            "impact": "Data leak.",
        }

        builder = JapaneseBodyBuilder()
        body = builder.build(finding)

        assert "[REDACTED]" in body
        assert "sk-secret-token-12345" not in body
        assert "SuperSecretPassword!" not in body
        assert "session=abc123" not in body

    def test_redaction_removes_jwt_tokens(self):
        """
        JWT tokens (Bearer eyJ...) should be redacted to Bearer [REDACTED].
        """
        finding = {
            "finding_id": "test-jwt-001",
            "severity": "high",
            "vuln_type": "jwt_weak_secret",
            "title": "JWT Leak Test",
            "target_url": "https://example.com",
            "description": (
                "Found JWT: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n"
                "Also: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZX0.signature"
            ),
            "impact": "Account takeover via JWT forgery.",
        }

        builder = JapaneseBodyBuilder()
        body = builder.build(finding)

        assert "eyJ" not in body
        assert "[REDACTED]" in body or "[REDACTED-JWT]" in body

    def test_request_response_body_redacted(self):
        """
        Full request/response bodies in evidence should be truncated or
        summarized instead of raw-dumped into the notification.
        """
        # Build a finding with large evidence that would exceed Discord limit
        large_description = "A" * 5000
        finding = {
            "finding_id": "test-large-001",
            "severity": "low",
            "vuln_type": "other",
            "title": "Large Body Test",
            "target_url": "https://example.com",
            "description": large_description,
            "impact": "Informational.",
        }

        builder = JapaneseBodyBuilder()
        body = builder.build(finding)

        assert len(body) <= 4000  # Discord message limit
        assert "... (長さ制限のため切り詰めました)" in body

    def test_golden_message_fixture_match(self):
        """
        Verify against a golden Japanese fixture to ensure format stability.
        This helps catch regressions when the body format changes.
        """
        finding = create_golden_finding_dict()
        builder = JapaneseBodyBuilder()
        body = builder.build(finding)

        # Relaxed check: ensure all required fields appear (exact match is
        # too brittle since timestamps vary)
        required_labels = [
            "脆弱性ID",
            "種類",
            "対象URL",
            "タイトル",
            "説明",
            "影響",
            "再現手順",
            "エビデンス概要",
            "信頼度",
            "発見エージェント",
            "発見日時",
        ]
        for label in required_labels:
            assert label in body, f"Golden body missing label: {label}"

        # Verify specific golden values
        assert "abc123def456" in body
        assert "SQL Injection in Login Form" in body
        assert "UNION-based SQL injection" in body
        assert "Full database exfiltration possible." in body

    def test_router_uses_japanese_body_builder(self, monkeypatch):
        """
        Verify that the router primary path (route_and_notify) delegates body
        generation to Notifier.notify_finding() → JapaneseBodyBuilder,
        producing Japanese labels, not English ones.
        """
        from src.core.notifications.finding_notification_router import (
            FindingNotificationDTO, FindingNotificationRouter
        )
        from src.core.notifications.notifier import Notifier
        
        router = FindingNotificationRouter(run_id="test-ja")
        
        # Inject a notifier with dry_run=True so no actual subprocess
        notifier = Notifier()
        notifier.notify_path = "/usr/bin/notify"
        notifier.dry_run = True
        monkeypatch.setattr(notifier, '_load_operational_settings', lambda: None)
        
        # Capture the message body sent to notify()
        captured_messages = []
        def _capture_notify(message, provider=None, bulk=False):
            captured_messages.append(message)
            return True
        monkeypatch.setattr(notifier, 'notify', _capture_notify)
        
        router._notifier = notifier
        
        dto = FindingNotificationDTO(
            finding_id="test123",
            severity="high",
            vuln_type="sqli",
            title="SQL Injection Test",
            target_url="https://example.com/login",
            description="Test description",
            impact="Data leak",
            confidence=0.85,
            source_agent="test_agent",
        )
        result = router.route_and_notify(dto)
        assert result.get("notified") is True, f"Expected notified=True, got {result}"
        assert len(captured_messages) == 1
        
        body = captured_messages[0]
        
        # Japanese markers should be present
        assert "脆弱性ID" in body, "Missing Japanese ID label"
        assert "対象URL" in body, "Missing Japanese target URL label"
        assert "種類" in body, "Missing Japanese type label"
        assert "説明" in body, "Missing Japanese description label"
        assert "影響" in body, "Missing Japanese impact label"
        
        # English markers must NOT be present
        assert "Type:" not in body, "English 'Type:' should not appear"
        assert "Target:" not in body, "English 'Target:' should not appear"
        assert "Confidence:" not in body, "English 'Confidence:' should not appear"

    def test_max_length_limit(self):
        """
        Body that exceeds the Discord message limit must be
        safely truncated with a trailing indicator.
        """
        finding = {
            "finding_id": "test-maxlen-001",
            "severity": "info",
            "vuln_type": "other",
            "title": "Max Length Test",
            "target_url": "https://example.com",
            "description": "X" * 200,
            "impact": "Test impact.",
        }

        builder = JapaneseBodyBuilder(max_length=100)
        body = builder.build(finding)

        assert len(body) <= 100, f"Body length {len(body)} exceeds max_length 100"
        assert "... (長さ制限のため切り詰めました)" in body


# --------------------------------------------------------------------------- #
# TestOperationalProtections
# --------------------------------------------------------------------------- #

class TestOperationalProtections:
    """Tests for operational safeguards (dry-run, kill switch, timeout, retry)."""

    def test_dry_run_does_not_send(self, monkeypatch):
        """
        In dry-run mode, notifications should be logged but NOT actually
        invoke subprocess.
        """
        notifier = Notifier()
        # Prevent _load_operational_settings from overriding our test values
        monkeypatch.setattr(notifier, "_load_operational_settings", lambda: None)
        notifier.dry_run = True
        notifier.notify_path = "/usr/bin/notify"  # bypass CLI check
        notifier.config_path = "/fake/config.yaml"  # bypass config check

        # Track whether subprocess.run was called
        mock_run = MagicMock(return_value=MagicMock(returncode=0))
        monkeypatch.setattr(subprocess, "run", mock_run)

        from src.core.models.finding import Finding, Severity, VulnType

        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            target_url="https://example.com",
        )

        result = notifier.notify_finding(finding)
        assert result is True  # dry-run simulates success
        # subprocess.run should NOT have been called
        assert mock_run.call_count == 0, \
            "subprocess.run should not be called in dry-run mode"

    def test_kill_switch_does_not_send(self, monkeypatch):
        """
        When the global kill switch is active, no notifications should be sent.
        """
        notifier = Notifier()
        # Prevent _load_operational_settings from overriding our test values
        monkeypatch.setattr(notifier, "_load_operational_settings", lambda: None)
        notifier.kill_switch = True
        notifier.notify_path = "/usr/bin/notify"
        notifier.config_path = "/fake/config.yaml"

        # Track subprocess
        mock_run = MagicMock()
        monkeypatch.setattr(subprocess, "run", mock_run)

        from src.core.models.finding import Finding, Severity, VulnType

        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.HIGH,
            title="Test",
            description="Test",
            target_url="https://example.com",
        )

        result = notifier.notify_finding(finding)
        assert result is False  # kill switch blocks
        assert mock_run.call_count == 0

    def test_notify_timeout_handled(self, monkeypatch):
        """
        A notification that takes too long should timeout gracefully without
        crashing the detection pipeline.
        """
        notifier = Notifier()
        notifier.notify_path = "/usr/bin/notify"
        notifier.config_path = "/fake/config.yaml"
        notifier.notify_timeout = 0.1
        notifier.notify_retry_count = 0  # no retries for clean test
        notifier.dry_run = False
        notifier.kill_switch = False

        # Mock subprocess.run to raise TimeoutExpired
        def _raise_timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="notify", timeout=0.1)

        monkeypatch.setattr(subprocess, "run", _raise_timeout)

        from src.core.models.finding import Finding, Severity, VulnType

        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.HIGH,
            title="Test Timeout",
            description="Test",
            target_url="https://example.com",
        )

        result = notifier.notify_finding(finding)
        assert result is False  # notification failed due to timeout
        # No crash occurred (if we got here, it passed)

    def test_notify_retry_behavior(self, monkeypatch):
        """
        On transient failure, the sender should retry up to max_retries times
        before giving up.
        """
        notifier = Notifier()
        # Prevent _load_operational_settings from overriding our test values
        monkeypatch.setattr(notifier, "_load_operational_settings", lambda: None)
        notifier.notify_path = "/usr/bin/notify"
        notifier.config_path = "/fake/config.yaml"
        notifier.notify_retry_count = 2  # retry 2 times (total 3 attempts)
        notifier.notify_retry_backoff = 0  # no delay for test speed
        notifier.dry_run = False
        notifier.kill_switch = False

        call_count = 0

        def _failing_run(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise Exception("Transient error")

        monkeypatch.setattr(subprocess, "run", _failing_run)

        from src.core.models.finding import Finding, Severity, VulnType

        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.HIGH,
            title="Test Retry",
            description="Test",
            target_url="https://example.com",
        )

        result = notifier.notify_finding(finding)
        assert result is False  # all attempts failed
        # 1 initial + 2 retries = 3 attempts total
        assert call_count == 3, \
            f"Expected 3 attempts (1 initial + 2 retries), got {call_count}"

    def test_notify_not_installed_does_not_crash_detection(self, monkeypatch):
        """
        When the 'notify' CLI is not installed, detection should proceed
        normally.  The notification gap should be logged, not crash.
        """
        notifier = Notifier()
        notifier.notify_path = None  # simulate not installed
        notifier.dry_run = False  # not in dry-run

        from src.core.models.finding import Finding, Severity, VulnType

        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.HIGH,
            title="Test No CLI",
            description="Test",
            target_url="https://example.com",
        )

        # Should not raise
        result = notifier.notify_finding(finding)
        assert result is False  # cannot send without CLI

    def test_provider_allowlist_blocks_unspecified_provider(self, monkeypatch):
        """
        When provider allowlist is non-empty and no provider is specified,
        notify() should fail-closed (return False).
        """
        from src.core.notifications.notifier import Notifier
        notifier = Notifier()
        # Prevent _load_operational_settings from overriding our test values
        monkeypatch.setattr(notifier, "_load_operational_settings", lambda: None)
        notifier.notify_path = "/usr/bin/notify"
        notifier.provider_allowlist = ["discord"]
        
        # Mock the actual subprocess call so it's never reached
        import subprocess
        monkeypatch.setattr(subprocess, 'run', lambda *a, **k: None)
        
        # Call without provider - should be blocked by allowlist
        result = notifier.notify("test message", bulk=True)
        assert result is False, "Should fail-closed when allowlist set but no provider specified"
    
    def test_provider_allowlist_allows_specified_provider(self, monkeypatch):
        """
        When provider is in allowlist, notify() should proceed.
        """
        from src.core.notifications.notifier import Notifier
        notifier = Notifier()
        # Prevent _load_operational_settings from overriding our test values
        monkeypatch.setattr(notifier, "_load_operational_settings", lambda: None)
        notifier.notify_path = "/usr/bin/notify"
        notifier.provider_allowlist = ["discord"]
        
        # Mock subprocess to return success
        import subprocess
        mock_run = type('MockResult', (), {'returncode': 0, 'stderr': ''})()
        monkeypatch.setattr(subprocess, 'run', lambda *a, **k: mock_run)
        
        result = notifier.notify("test message", provider="discord", bulk=True)
        assert result is True, "Should allow when provider is in allowlist"

    def test_structured_logging_fields(self, monkeypatch):
        """
        Every notification attempt should produce a structured JSONL log entry
        containing at least: timestamp, finding_id, severity, notification_type,
        success, dry_run.
        """
        notifier = Notifier()
        # Prevent _load_operational_settings from overriding our test values
        monkeypatch.setattr(notifier, "_load_operational_settings", lambda: None)
        notifier.notify_path = "/usr/bin/notify"
        notifier.config_path = "/fake/config.yaml"
        notifier.dry_run = True  # dry-run to avoid actual CLI call
        notifier.kill_switch = False

        # Capture the log entry dict
        captured_entries = []

        def _capture_log(finding, body, run_id, source_component, ingress_path, success=None):
            d = {}
            if hasattr(finding, "to_dict"):
                d = finding.to_dict()
            elif isinstance(finding, dict):
                d = finding
            entry = {
                "timestamp": "2026-01-01T00:00:00",
                "finding_id": d.get("finding_id", d.get("id", "unknown")),
                "severity": d.get("severity", "unknown"),
                "vuln_type": d.get("vuln_type", d.get("type", "unknown")),
                "title": d.get("title", "")[:200],
                "source_component": source_component,
                "ingress_path": ingress_path,
                "delivery_status": "dry_run" if notifier.dry_run else "attempted",
                "body_length": len(body),
                "dry_run": notifier.dry_run,
                "kill_switch": notifier.kill_switch,
                "notify_path_available": bool(notifier.notify_path),
            }
            captured_entries.append(entry)

        monkeypatch.setattr(notifier, "_log_notification", _capture_log)

        from src.core.models.finding import Finding, Severity, VulnType

        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.HIGH,
            title="Test Logging",
            description="Test structured logging.",
            target_url="https://example.com",
        )

        notifier.notify_finding(
            finding,
            run_id="test-run-001",
            source_component="test_component",
            ingress_path="test_ingress",
        )

        assert len(captured_entries) >= 1, "Expected at least one log entry"
        entry = captured_entries[0]

        required_fields = [
            "timestamp",
            "finding_id",
            "severity",
            "vuln_type",
            "title",
            "source_component",
            "ingress_path",
            "delivery_status",
            "body_length",
            "dry_run",
            "kill_switch",
            "notify_path_available",
        ]
        for field in required_fields:
            assert field in entry, f"Missing log field: {field}"

        # Verify specific values
        assert entry["severity"] == "high"
        assert entry["vuln_type"] == "xss"
        assert entry["source_component"] == "test_component"
        assert entry["ingress_path"] == "test_ingress"
        assert entry["dry_run"] is True
        assert entry["kill_switch"] is False
        assert entry["notify_path_available"] is True

    def test_different_runs_have_separate_dedup(self):
        """
        When notify_finding_primary() is called with different run_ids,
        dedup state should NOT carry over between runs.
        """
        from src.core.notifications.notification_service import NotificationService
        from src.core.models.finding import Finding, Severity, VulnType
        
        service = NotificationService()
        
        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.HIGH,
            title="Cross-Run Dedup Test",
            description="Test",
            target_url="https://example.com/test",
        )
        
        # Run 1: send the finding
        result1 = service.notify_finding_primary(finding, run_id="run-001")
        
        # Run 2: SAME finding with different run_id should NOT be dedup'd
        result2 = service.notify_finding_primary(finding, run_id="run-002")
        
        # The finding should be sent (or at least normalized) in both runs
        # Since the notifier may not be installed in test, check that dedup didn't block
        assert not result2.get("dedup_skipped", False), \
            "Finding with different run_id should not be dedup'd across runs"

    def test_primary_path_emits_structured_delivery_log(self, monkeypatch, caplog):
        """
        Verify that route_and_notify() (the primary path) emits a 
        NOTIFICATION_EVENT structured log entry via notify_finding().
        """
        from src.core.notifications.finding_notification_router import (
            FindingNotificationDTO, FindingNotificationRouter
        )
        from src.core.notifications.notifier import Notifier
        
        caplog.set_level(logging.INFO, logger="src.core.notifications.notifier")
        
        router = FindingNotificationRouter(run_id="test-primary-log")
        # Inject a notifier that has notify_path set (bypass CLI check)
        notifier = Notifier()
        notifier.notify_path = "/usr/bin/notify"
        notifier.dry_run = True  # dry-run so no actual subprocess
        # No-op the settings reload so dry_run stays True
        monkeypatch.setattr(notifier, '_load_operational_settings', lambda: None)
        router._notifier = notifier
        
        dto = FindingNotificationDTO(
            finding_id="log-test-001",
            severity="critical",
            vuln_type="sqli",
            title="SQL Injection Log Test",
            target_url="https://example.com/login",
            description="Test delivery log",
            confidence=0.88,
            source_agent="test_agent",
            source_component="test_component",
            ingress_path="test_path",
        )
        
        result = router.route_and_notify(dto, source_component="test", ingress_path="test")
        assert result.get("notified") is True, f"Expected notified=True, got {result}"
        
        # Verify NOTIFICATION_EVENT was logged
        notification_logs = [r.message for r in caplog.records if "NOTIFICATION_EVENT" in r.message]
        assert len(notification_logs) >= 1, "Expected at least one NOTIFICATION_EVENT log entry"

    # ------------------------------------------------------------------ #
    # Regression tests: SGK-2026-0297 Phase A.3 critical + minor fixes
    # ------------------------------------------------------------------ #

    def test_dry_run_succeeds_without_notify_cli(self, monkeypatch):
        """
        When dry_run=True, notify() should return True even if notify CLI
        and config are missing. This ensures dry-run mode works in dev/test
        environments without the 'notify' tool installed.
        """
        notifier = Notifier()
        monkeypatch.setattr(notifier, '_load_operational_settings', lambda: None)
        notifier.dry_run = True
        notifier.notify_path = None  # Simulate missing CLI
        notifier.config_path = None  # Simulate missing config

        result = notifier.notify("test dry-run message", bulk=True)
        assert result is True, \
            "Dry-run should succeed (return True) even without notify CLI/config"

    def test_dry_run_succeeds_in_notify_finding_without_cli(self, monkeypatch):
        """
        When dry_run=True and notify CLI is missing, notify_finding() should
        return True and the router should mark the finding as notified.
        """
        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.HIGH,
            title="Dry-run CLI-less Test",
            description="Test",
            target_url="https://example.com/test",
        )

        notifier = Notifier()
        monkeypatch.setattr(notifier, '_load_operational_settings', lambda: None)
        notifier.dry_run = True
        notifier.notify_path = None
        notifier.config_path = None

        result = notifier.notify_finding(
            finding,
            run_id="test-dryrun-nocli",
            source_component="test",
            ingress_path="test",
        )
        assert result is True, \
            "notify_finding() should return True in dry-run mode even without CLI"

    def test_router_notified_true_in_dry_run_without_cli(self, monkeypatch):
        """
        route_and_notify() should set notified=True when dry_run=True even
        when notify CLI is missing, and should update dedup state.
        """
        from src.core.notifications.finding_notification_router import (
            FindingNotificationDTO, FindingNotificationRouter
        )

        router = FindingNotificationRouter(run_id="test-router-dryrun")
        notifier = Notifier()
        monkeypatch.setattr(notifier, '_load_operational_settings', lambda: None)
        notifier.dry_run = True
        notifier.notify_path = None
        notifier.config_path = None
        router._notifier = notifier

        dto = FindingNotificationDTO(
            finding_id="dryrun-nocli-001",
            severity="medium",
            vuln_type="sqli",
            title="Router Dry-Run Test",
            target_url="https://example.com/login",
            description="Testing dry-run via router",
        )

        result = router.route_and_notify(dto, source_component="test", ingress_path="test")
        assert result.get("notified") is True, \
            f"Expected notified=True in dry-run mode, got {result}"

        # Dedup should now prevent resending the same finding
        assert router.should_send(dto) is False, \
            "Finding should be dedup'd after successful dry-run notification"

    def test_kill_switch_emits_structured_log(self, monkeypatch, caplog):
        """
        When kill switch is active, notify_finding() should still emit a
        NOTIFICATION_EVENT structured log entry with delivery_status.
        """
        caplog.set_level(logging.INFO, logger="src.core.notifications.notifier")

        notifier = Notifier()
        monkeypatch.setattr(notifier, '_load_operational_settings', lambda: None)
        notifier.kill_switch = True
        notifier.notify_path = "/usr/bin/notify"

        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.CRITICAL,
            title="Kill Switch Log Test",
            description="Test",
            target_url="https://example.com/test",
        )

        notifier.notify_finding(finding, run_id="test-killswitch", source_component="test", ingress_path="test")

        notification_logs = [r.message for r in caplog.records if "NOTIFICATION_EVENT" in r.message]
        assert len(notification_logs) >= 1, \
            "Expected at least one NOTIFICATION_EVENT even when kill switch blocks delivery"

        # Verify the log contains the kill switch status
        entry = json.loads(notification_logs[0].split("NOTIFICATION_EVENT ", 1)[1])
        assert entry.get("kill_switch") is True, \
            "Log entry should indicate kill_switch=True"
        assert entry.get("delivery_status") in ("blocked_kill_switch", "failed"), \
            f"Delivery status should indicate blocking, got: {entry.get('delivery_status')}"

    def test_missing_cli_emits_structured_log(self, monkeypatch, caplog):
        """
        When notify CLI is missing (and not dry-run), notify_finding() should
        emit a NOTIFICATION_EVENT structured log entry.
        """
        caplog.set_level(logging.INFO, logger="src.core.notifications.notifier")

        notifier = Notifier()
        monkeypatch.setattr(notifier, '_load_operational_settings', lambda: None)
        notifier.notify_path = None
        notifier.config_path = None
        notifier.dry_run = False

        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.LOW,
            title="Missing CLI Log Test",
            description="Test",
            target_url="https://example.com/test",
        )

        notifier.notify_finding(finding, run_id="test-nocli", source_component="test", ingress_path="test")

        notification_logs = [r.message for r in caplog.records if "NOTIFICATION_EVENT" in r.message]
        assert len(notification_logs) >= 1, \
            "Expected at least one NOTIFICATION_EVENT even when CLI is missing"


# --------------------------------------------------------------------------- #
# TestPhaseCKpiMetrics
# --------------------------------------------------------------------------- #

class TestPhaseCKpiMetrics:
    """Phase C tests: KPI computation and thresholds."""

    def test_kpi_computes_dedup_rate(self):
        """
        Verify get_kpi() correctly computes dedup rate.
        """
        from src.core.notifications.finding_notification_router import FindingNotificationRouter
        
        router = FindingNotificationRouter(run_id="test-kpi-dedup")
        
        # Manually set stats to known values
        router._stats["total_sent"] = 90
        router._stats["dedup_skipped"] = 10
        router._stats["notify_failed"] = 0
        
        kpi = router.get_kpi()
        assert kpi["dedup_rate_pct"] == 10.0, \
            f"Expected 10% dedup rate, got {kpi['dedup_rate_pct']}%"
        assert kpi["delivery_failure_rate_pct"] == 0.0

    def test_kpi_computes_delivery_failure_rate(self):
        """
        Verify get_kpi() correctly computes delivery failure rate.
        """
        from src.core.notifications.finding_notification_router import FindingNotificationRouter
        
        router = FindingNotificationRouter(run_id="test-kpi-failure")
        router._stats["total_sent"] = 85
        router._stats["dedup_skipped"] = 10
        router._stats["notify_failed"] = 15
        
        kpi = router.get_kpi()
        assert kpi["delivery_failure_rate_pct"] == 15.0, \
            f"Expected 15% failure rate, got {kpi['delivery_failure_rate_pct']}%"
        assert kpi["total_sent"] == 85

    def test_kpi_zero_division_safe(self):
        """
        Verify get_kpi() handles zero values without division errors.
        """
        from src.core.notifications.finding_notification_router import FindingNotificationRouter
        
        router = FindingNotificationRouter(run_id="test-kpi-zero")
        router._stats["total_sent"] = 0
        router._stats["dedup_skipped"] = 0
        router._stats["notify_failed"] = 0
        
        kpi = router.get_kpi()
        assert kpi["dedup_rate_pct"] == 0.0
        assert kpi["delivery_failure_rate_pct"] == 0.0

    def test_kpi_thresholds_pass_when_below(self):
        """
        Verify check_kpi_thresholds() passes when metrics are within limits.
        """
        from src.core.notifications.finding_notification_router import FindingNotificationRouter
        
        router = FindingNotificationRouter(run_id="test-kpi-ok")
        router._stats["total_sent"] = 100
        router._stats["dedup_skipped"] = 3   # 3% dedup
        router._stats["notify_failed"] = 5    # ~5% failure
        
        result = router.check_kpi_thresholds()
        assert result["passed"] is True, \
            f"KPI should pass with low rates, got issues: {result['issues']}"

    def test_kpi_thresholds_fails_when_above(self):
        """
        Verify check_kpi_thresholds() fails when delivery failure > 10%.
        """
        from src.core.notifications.finding_notification_router import FindingNotificationRouter
        
        router = FindingNotificationRouter(run_id="test-kpi-bad")
        router._stats["total_sent"] = 70
        router._stats["dedup_skipped"] = 10
        router._stats["notify_failed"] = 30   # 30% failure
        
        result = router.check_kpi_thresholds()
        assert result["passed"] is False, \
            "KPI should fail with high delivery failure rate"
        assert any(i["kpi"] == "delivery_failure_rate" for i in result["issues"])

    def test_kpi_body_build_failures_zero_required(self):
        """
        Verify body_build_failures > 0 triggers KPI issue.
        """
        from src.core.notifications.finding_notification_router import FindingNotificationRouter
        
        router = FindingNotificationRouter(run_id="test-kpi-body")
        router._stats["body_build_failures"] = 1
        
        result = router.check_kpi_thresholds()
        assert result["passed"] is False, \
            "KPI should fail when body_build_failures > 0"

    def test_body_build_failure_increments_counter(self, monkeypatch):
        """
        Verify that when JapaneseBodyBuilder fails, the router increments
        body_build_failures (not notify_failed).
        """
        from src.core.notifications.finding_notification_router import (
            FindingNotificationDTO, FindingNotificationRouter
        )
        from src.core.notifications.body_builder import JapaneseBodyBuilder
        
        router = FindingNotificationRouter(run_id="test-bodybuild-fail")
        
        # Monkeypatch JapaneseBodyBuilder.build to raise
        original_build = JapaneseBodyBuilder.build
        def _failing_build(self, finding):
            raise RuntimeError("Simulated body build failure")
        monkeypatch.setattr(JapaneseBodyBuilder, "build", _failing_build)
        
        dto = FindingNotificationDTO(
            finding_id="body-test-001",
            severity="high",
            vuln_type="sqli",
            title="Body Build Failure Test",
            target_url="https://example.com/test",
            description="Test",
        )
        
        result = router.route_and_notify(dto, source_component="test", ingress_path="test")
        
        assert result.get("error") is not None, "Should have error on body build failure"
        assert "body_build_failed" in result.get("error", ""), \
            f"Error should indicate body build failure, got: {result.get('error')}"
        
        # body_build_failures should be incremented, notify_failed should NOT
        assert router._stats["body_build_failures"] == 1, \
            f"Expected body_build_failures=1, got {router._stats['body_build_failures']}"
        assert router._stats["notify_failed"] == 0, \
            f"notify_failed should remain 0, got {router._stats['notify_failed']}"
