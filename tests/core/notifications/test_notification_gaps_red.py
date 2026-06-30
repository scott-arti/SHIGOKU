# Phase A: GAP-FILLED CONFIRMATION tests for SGK-2026-0297 Discord全Finding詳細通知
"""
GAP-FILLED CONFIRMATION tests for SGK-2026-0297 Phase A.

These tests originally captured notification gaps (PASS = gap exists).
Now that Phase A implementation is complete, the tests have been flipped
to verify that the gaps are FILLED (PASS = gap is filled).
"""

import pytest
from unittest.mock import MagicMock

from src.core.models.finding import Finding, Severity, VulnType, Evidence
from src.core.notifications.notifier import Notifier, get_notifier
from src.core.engine.master_conductor import MasterConductor
from src.core.infra.event_bus import Event, EventType, get_event_bus
from src.core.notifications.finding_notification_router import FindingNotificationRouter


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _make_finding(
    severity: Severity = Severity.CRITICAL,
    title: str = "Test Vulnerability",
    description: str = "A test vulnerability was found.",
    target_url: str = "https://example.com/login",
    source_agent: str = "test_agent",
    confidence: float = 0.85,
    impact: str = "Account takeover possible.",
    reproduction_steps: list[str] | None = None,
) -> Finding:
    """Create a fully-populated Finding for tests."""
    return Finding(
        vuln_type=VulnType.SQLI,
        severity=severity,
        title=title,
        description=description,
        target_url=target_url,
        target_program="example",
        evidence=Evidence(
            request_method="POST",
            request_url="https://example.com/login",
            request_headers={"Authorization": "Bearer sk-secret-token-12345"},
            request_body="username=admin&password=admin",
            response_status=200,
            response_headers={"Set-Cookie": "session=abc123"},
            response_body="<html>Welcome admin</html>",
        ),
        reproduction_steps=reproduction_steps or [
            "1. POST /login with payload",
            "2. Observe 200 response with admin session",
        ],
        impact=impact,
        source_agent=source_agent,
        confidence=confidence,
        additional_info={"schema_severity": "critical"},
    )


# --------------------------------------------------------------------------- #
# TestNotificationSeverityGaps (now GAP-FILLED)
# --------------------------------------------------------------------------- #

class TestNotificationSeverityGaps:
    """Tests documenting gaps that are now FILLED in notification severity filtering."""

    def test_process_findings_notifies_all_severities(self, monkeypatch):
        """
        GAP FILLED: _process_findings now notifies ALL severities.
        The FindingNotificationRouter.process_batch receives all findings
        without severity filtering.
        """
        mc = MasterConductor()

        # Capture all findings passed to process_batch
        batched_findings: list[dict] = []

        def _capture_process_batch(
            self,
            findings,
            source_component="",
            ingress_path="",
        ):
            for f in findings:
                if isinstance(f, dict):
                    batched_findings.append(f)
                elif hasattr(f, "to_dict"):
                    batched_findings.append(f.to_dict())
                else:
                    batched_findings.append({"severity": "unknown"})
            return []

        monkeypatch.setattr(
            FindingNotificationRouter, "process_batch", _capture_process_batch
        )

        findings: list[dict] = [
            {"severity": "critical", "title": "Crit Vuln", "target": "example.com",
             "vuln_type": "sqli", "description": "crit desc"},
            {"severity": "high", "title": "High Vuln", "target": "example.com",
             "vuln_type": "xss", "description": "high desc"},
            {"severity": "medium", "title": "Med Vuln", "target": "example.com",
             "vuln_type": "idor", "description": "med desc"},
            {"severity": "low", "title": "Low Vuln", "target": "example.com",
             "vuln_type": "info", "description": "low desc"},
            {"severity": "info", "title": "Info Note", "target": "example.com",
             "vuln_type": "other", "description": "info desc"},
        ]

        mc._process_findings(findings, "https://example.com")

        # GAP FILLED: ALL 5 severities should be passed to the router
        notified_severities = {f["severity"] for f in batched_findings}
        assert notified_severities == {"critical", "high", "medium", "low", "info"}, \
            f"Expected all 5 severities, got: {notified_severities}"
        assert len(batched_findings) == 5, \
            f"Expected 5 findings batched, got {len(batched_findings)}"

    def test_process_findings_actually_sends_notifications(self, monkeypatch):
        """
        Verify that _process_findings() actually sends all severity findings
        through the notifier (or dry-run), not just normalizes them.
        """
        mc = MasterConductor()
        
        # Mock the router's route_and_notify to track calls
        route_calls = []
        def _capture_route(self, finding_input, source_component="", ingress_path=""):
            route_calls.append({
                "source_component": source_component,
                "ingress_path": ingress_path,
            })
            return {"normalized": True, "notified": True}
        
        # Monkeypatch the router method
        import src.core.notifications.finding_notification_router as router_mod
        monkeypatch.setattr(
            router_mod.FindingNotificationRouter, "route_and_notify", _capture_route
        )
        
        findings = [
            {"severity": "critical", "title": "Crit", "target": "x.com", "vuln_type": "sqli"},
            {"severity": "medium", "title": "Med", "target": "x.com", "vuln_type": "idor"},
            {"severity": "info", "title": "Info", "target": "x.com", "vuln_type": "other"},
        ]
        
        mc._process_findings(findings, "https://x.com")
        
        # All 3 should have been sent (not just critical)
        assert len(route_calls) == 3, f"Expected 3 notifications, got {len(route_calls)}"

    def test_handle_finding_sends_full_detail_notification(self, monkeypatch):
        """
        GAP FILLED: handle_finding now routes through FindingNotificationRouter.
        The old thin notify_event() call has been replaced by route_and_notify().
        handle_finding completes without error and triggers the full pipeline.
        """
        # -- monkeypatch MC constructor dependencies that touch DB / async --
        monkeypatch.setattr(
            "src.core.engine.master_conductor.MasterConductor.save_finding",
            lambda *a, **k: None,
        )
        monkeypatch.setattr(
            "src.core.engine.master_conductor.MasterConductor._run_async_safe_forget",
            lambda *a, **k: None,
        )
        monkeypatch.setattr(
            "src.core.engine.master_conductor.MasterConductor._run_async_safe",
            lambda *a, **k: None,
        )

        # -- monkeypatch event bus emit_sync to be a no-op --
        mock_emit_sync = MagicMock()
        monkeypatch.setattr(
            "src.core.infra.event_bus.EventBus.emit_sync", mock_emit_sync
        )

        # -- Capture route_and_notify calls on FindingNotificationRouter --
        route_calls = []

        def _capture_route_and_notify(
            self,
            finding_input,
            source_component="",
            ingress_path="",
        ):
            route_calls.append({
                "finding_input": finding_input,
                "source_component": source_component,
                "ingress_path": ingress_path,
            })
            return {"finding_id": "test", "normalized": True, "notified": True}

        monkeypatch.setattr(
            FindingNotificationRouter, "route_and_notify", _capture_route_and_notify
        )

        # -- construct MC and call handle_finding --
        mc = MasterConductor()
        finding = _make_finding(
            severity=Severity.CRITICAL,
            title="Critical SQL Injection",
            description="SQLi found in login form via POST parameter 'user'",
            impact="Full database compromise possible.",
            confidence=0.95,
        )

        mc.handle_finding(finding)

        # GAP FILLED: handle_finding completed without error
        assert True  # handle_finding completed without error

        # Verify route_and_notify was called with the finding
        assert len(route_calls) == 1, \
            f"Expected route_and_notify to be called once, got {len(route_calls)}"
        assert route_calls[0]["finding_input"] is finding, \
            "route_and_notify should receive the Finding object"
        assert route_calls[0]["source_component"] == "master_conductor"
        assert route_calls[0]["ingress_path"] == "handle_finding"

    def test_vuln_found_event_has_full_finding_payload(self, monkeypatch):
        """
        GAP FILLED: VULN_FOUND event now contains full finding dict.
        The event payload includes a 'finding' key with the complete
        finding.to_dict() output.
        """
        # -- monkeypatch MC constructor dependencies --
        monkeypatch.setattr(
            "src.core.engine.master_conductor.MasterConductor.save_finding",
            lambda *a, **k: None,
        )
        monkeypatch.setattr(
            "src.core.engine.master_conductor.MasterConductor._run_async_safe_forget",
            lambda *a, **k: None,
        )
        monkeypatch.setattr(
            "src.core.engine.master_conductor.MasterConductor._run_async_safe",
            lambda *a, **k: None,
        )

        # -- capture event bus emit_sync payload --
        captured_events: list[Event] = []

        def _capture_emit_sync(self, event: Event) -> None:
            captured_events.append(event)

        monkeypatch.setattr(
            "src.core.infra.event_bus.EventBus.emit_sync", _capture_emit_sync
        )

        # -- Mock route_and_notify so handle_finding doesn't try to send real notifications --
        monkeypatch.setattr(
            FindingNotificationRouter,
            "route_and_notify",
            lambda self, finding_input, source_component="", ingress_path="": {
                "finding_id": "test",
                "normalized": True,
                "notified": True,
            },
        )

        # -- construct MC and call handle_finding --
        mc = MasterConductor()
        finding = _make_finding(
            severity=Severity.CRITICAL,
            title="Critical SQL Injection",
            description="Deep description with full technical detail.",
            impact="Complete database exfiltration.",
            confidence=0.99,
        )

        mc.handle_finding(finding)

        # -- inspect VULN_FOUND event payload --
        assert len(captured_events) >= 1, "No VULN_FOUND event captured"
        vuln_event = captured_events[0]
        assert vuln_event.type == EventType.VULN_FOUND, \
            f"Expected VULN_FOUND, got {vuln_event.type}"

        payload = vuln_event.payload

        # The thin fields that ARE still present
        assert payload.get("title") == "Critical SQL Injection"
        assert payload.get("target") == "https://example.com/login"
        assert payload.get("vuln_type") == "sqli"
        assert payload.get("source_agent") == "test_agent"
        assert payload.get("schema_severity") == "critical"

        # GAP FILLED: 'finding' key now present in the event payload
        assert "finding" in payload, \
            "Full finding dict should be in event payload"
        finding_dict = payload["finding"]
        assert isinstance(finding_dict, dict), \
            f"Expected finding dict, got {type(finding_dict)}"

        # GAP FILLED: all previously-missing fields now present inside finding dict
        required_fields = [
            "description",
            "impact",
            "target_url",
            "reproduction_steps",
            "confidence",
            "id",
        ]
        for field in required_fields:
            assert field in finding_dict, \
                f"Field '{field}' should be in finding dict inside event payload, but is missing"

        # Verify actual values
        assert finding_dict.get("description") == "Deep description with full technical detail."
        assert finding_dict.get("impact") == "Complete database exfiltration."
        assert finding_dict.get("confidence") == 0.99

    def test_report_followup_does_not_duplicate_notification(self, monkeypatch):
        """
        When recommended_followup="report", handle_finding() should NOT send
        a duplicate notification. The primary notification already happened
        via route_and_notify().
        """
        monkeypatch.setattr(
            "src.core.engine.master_conductor.MasterConductor.save_finding",
            lambda *a, **k: None,
        )
        monkeypatch.setattr(
            "src.core.engine.master_conductor.MasterConductor._run_async_safe_forget",
            lambda *a, **k: None,
        )
        monkeypatch.setattr(
            "src.core.engine.master_conductor.MasterConductor._run_async_safe",
            lambda *a, **k: None,
        )
        
        # Capture event bus emit
        captured_events = []
        def _capture(self, event):
            captured_events.append(event)
        monkeypatch.setattr(
            "src.core.infra.event_bus.EventBus.emit_sync", _capture
        )
        
        mc = MasterConductor()
        
        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.CRITICAL,
            title="Critical XSS Report Followup",
            description="Test finding with report followup",
            target_url="https://example.com/search",
            source_agent="test_agent",
            recommended_followup="report",
        )
        
        # Mock get_notifier to track ALL notify calls
        all_notify_calls = []
        mock_notifier = MagicMock()
        mock_notifier.notify = MagicMock(side_effect=lambda *a, **k: all_notify_calls.append(("notify", a, k)) or True)
        mock_notifier.notify_finding = MagicMock(side_effect=lambda *a, **k: all_notify_calls.append(("notify_finding", a, k)) or True)
        mock_notifier.notify_event = MagicMock()
        mock_notifier.notify_path = "/usr/bin/notify"
        mock_notifier.dry_run = True
        mock_notifier.kill_switch = False
        mock_notifier.provider_allowlist = []
        mock_notifier._load_operational_settings = lambda: None
        
        monkeypatch.setattr(
            "src.core.engine.master_conductor.get_notifier",
            lambda: mock_notifier,
        )
        # Also patch the notifier module get_notifier (used by the router)
        monkeypatch.setattr(
            "src.core.notifications.notifier.get_notifier",
            lambda: mock_notifier,
        )
        
        mc.handle_finding(finding)
        
        # Count notify() calls (which represent actual Discord sends)
        # We expect exactly 1 notification via the primary path
        notify_calls = [c for c in all_notify_calls if c[0] == "notify"]
        assert len(notify_calls) <= 1, \
            f"Expected at most 1 notify call, got {len(notify_calls)}. " \
            f"The report followup branch should not send duplicate notifications."

    def test_process_findings_emits_delivery_log(self, monkeypatch, caplog):
        """
        Verify that _process_findings() via route_and_notify() emits
        NOTIFICATION_EVENT structured log entries.
        """
        import logging
        caplog.set_level(logging.INFO, logger="src.core.notifications.notifier")
        
        mc = MasterConductor()
        
        # Mock route_and_notify to use a real notifier in dry-run mode
        from src.core.notifications.notifier import Notifier
        notifier = Notifier()
        notifier.notify_path = "/usr/bin/notify"
        notifier.dry_run = True
        monkeypatch.setattr(notifier, '_load_operational_settings', lambda: None)
        
        # Inject this notifier into routers created during process_batch
        import src.core.notifications.finding_notification_router as router_mod
        original_init = router_mod.FindingNotificationRouter.__init__
        
        def _patched_init(self, run_id="", notifier_arg=None):
            original_init(self, run_id=run_id, notifier=notifier)
        
        monkeypatch.setattr(router_mod.FindingNotificationRouter, '__init__', _patched_init)
        
        findings = [
            {"severity": "high", "title": "Log Test Vuln", "target": "x.com", "vuln_type": "xss"},
        ]
        
        mc._process_findings(findings, "https://x.com")
        
        notification_logs = [r.message for r in caplog.records if "NOTIFICATION_EVENT" in r.message]
        assert len(notification_logs) >= 1, "Expected at least one NOTIFICATION_EVENT from _process_findings"


# --------------------------------------------------------------------------- #
# TestNotifierBodyGaps (now GAP-FILLED)
# --------------------------------------------------------------------------- #

class TestNotifierBodyGaps:
    """Tests documenting body-formatting gaps that are now FILLED."""

    def test_notify_finding_has_japanese_detailed_body(self, monkeypatch):
        """
        GAP FILLED: notify_finding now produces Japanese detailed body.
        The JapaneseBodyBuilder is used for all notification bodies.
        """
        notifier = Notifier()

        # Mock self.notify to capture the message
        captured_messages: list[str] = []

        def _capture_notify(message: str, provider=None, bulk=False) -> bool:
            captured_messages.append(message)
            return True

        monkeypatch.setattr(notifier, "notify", _capture_notify)
        # Also ensure notify_path and config_path are set so guards pass
        monkeypatch.setattr(notifier, "notify_path", "/usr/bin/notify")
        monkeypatch.setattr(notifier, "config_path", "/fake/config.yaml")

        finding = _make_finding(
            severity=Severity.HIGH,
            title="Stored XSS in Comment Field",
            description="Persistent XSS via unescaped user input in comment body.",
            impact="Session hijacking of all users viewing the comment.",
        )

        result = notifier.notify_finding(finding)
        assert result is True
        assert len(captured_messages) == 1

        message = captured_messages[0]

        # GAP FILLED: Old English format markers should NOT be present
        assert "Type:" not in message, \
            "Old English 'Type:' label should not appear in Japanese body"
        assert "Target:" not in message, \
            "Old English 'Target:' label should not appear in Japanese body"

        # GAP FILLED: Japanese detailed format markers should BE present
        japanese_markers = [
            "脆弱性ID",           # Finding ID
            "種類",               # Vuln type (in Japanese)
            "対象URL",            # Target URL (in Japanese)
            "説明",               # Description (in Japanese)
            "再現手順",           # Reproduction steps
            "影響",               # Impact
            "エビデンス概要",     # Evidence summary
            "信頼度",             # Confidence (in Japanese)
            "発見エージェント",   # Discovered by agent
            "発見日時",           # Discovered at
        ]
        for marker in japanese_markers:
            assert marker in message, \
                f"Japanese marker '{marker}' not found in message - gap should be filled"

    def test_notify_finding_redacts_secrets(self, monkeypatch):
        """
        GAP FILLED: notify_finding now redacts secrets.
        JapaneseBodyBuilder applies automatic redaction to all bodies.
        """
        notifier = Notifier()

        captured_messages: list[str] = []

        def _capture_notify(message: str, provider=None, bulk=False) -> bool:
            captured_messages.append(message)
            return True

        monkeypatch.setattr(notifier, "notify", _capture_notify)
        monkeypatch.setattr(notifier, "notify_path", "/usr/bin/notify")
        monkeypatch.setattr(notifier, "config_path", "/fake/config.yaml")

        # Create a finding with secrets in description
        finding = _make_finding(
            severity=Severity.CRITICAL,
            title="API Key Leak in Response",
            description=(
                "Authorization header: Bearer sk-proj-abc123secret456\n"
                "Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                "password=SuperSecret123!"
            ),
            impact="Attackers can impersonate admin users.",
            confidence=0.90,
        )

        result = notifier.notify_finding(finding)
        assert result is True
        assert len(captured_messages) == 1, \
            f"Expected 1 message, got {len(captured_messages)}"

        message = captured_messages[0]

        # GAP FILLED: secrets should NOT be present (they are redacted)
        secret_patterns = [
            "sk-proj-abc123secret456",
            "SuperSecret123!",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "session=eyJ",
        ]
        found_secrets = []
        for pattern in secret_patterns:
            if pattern in message:
                found_secrets.append(pattern)

        assert len(found_secrets) == 0, \
            f"Secrets should be redacted! Found: {found_secrets}"

        # GAP FILLED: redaction markers should be present
        assert "[REDACTED]" in message or "[REDACTED-JWT]" in message, \
            "Expected [REDACTED] or [REDACTED-JWT] marker in message after redaction"


# --------------------------------------------------------------------------- #
# TestNotificationMissingFieldsGaps (now GAP-FILLED)
# --------------------------------------------------------------------------- #

class TestNotificationMissingFieldsGaps:
    """Tests documenting fields that are now INCLUDED in notifications."""

    def test_notify_finding_includes_all_key_fields(
        self, monkeypatch
    ):
        """
        GAP FILLED: notify_finding now includes id, reproduction_steps,
        impact, and evidence via the JapaneseBodyBuilder.
        """
        notifier = Notifier()

        captured_messages: list[str] = []

        def _capture_notify(message: str, provider=None, bulk=False) -> bool:
            captured_messages.append(message)
            return True

        monkeypatch.setattr(notifier, "notify", _capture_notify)
        monkeypatch.setattr(notifier, "notify_path", "/usr/bin/notify")
        monkeypatch.setattr(notifier, "config_path", "/fake/config.yaml")

        finding = _make_finding(
            severity=Severity.HIGH,
            title="IDOR in User Profile",
            description="Accessing /api/user/42 returns profile of user 43.",
            impact="Unauthorized access to arbitrary user data.",
            reproduction_steps=[
                "1. Login as user A",
                "2. Request GET /api/user/43 with user A's cookie",
                "3. Observe response contains user 43's PII",
            ],
        )
        # Ensure finding.id is set
        assert hasattr(finding, "id"), "Finding must have an id for this test"
        finding_id = finding.id

        result = notifier.notify_finding(finding)
        assert result is True
        assert len(captured_messages) == 1

        message = captured_messages[0]

        # GAP FILLED: finding id is present
        assert finding_id in message, \
            f"Finding ID '{finding_id}' should be in notify_finding output"

        # GAP FILLED: reproduction_steps are present (via 再現手順 label)
        assert "再現手順" in message, \
            "Reproduction steps label '再現手順' should appear in output"
        assert "1. Login as user A" in message, \
            "Reproduction steps content should appear in output"

        # GAP FILLED: impact is present (via 影響 label)
        assert "影響" in message, \
            "'影響' (impact) label should appear in Japanese output"

        # GAP FILLED: evidence is present (via エビデンス概要 label)
        assert "エビデンス概要" in message, \
            "'エビデンス概要' (evidence summary) should appear in output"
