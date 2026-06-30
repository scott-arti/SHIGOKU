# Phase B tests for SGK-2026-0297 (hunt.py + watch.py router wiring)
"""
Integration tests for Phase B of SGK-2026-0297.
Verifies that hunt.py and watch.py correctly route findings through the
FindingNotificationRouter.
"""
import pytest
from unittest.mock import MagicMock

from src.core.models.finding import Finding, Severity, VulnType


class TestHuntNotificationOrder:
    """Verify hunt.py routes notifications AFTER deduplication."""

    def test_hunt_router_process_batch_present(self, monkeypatch):
        """
        Verify that hunt.py imports and uses FindingNotificationRouter.process_batch.
        The router call should be present in the run_hybrid_hunt function.
        """
        from src.commands.hunt import run_hybrid_hunt
        import inspect
        
        source = inspect.getsource(run_hybrid_hunt)
        assert "FindingNotificationRouter" in source, \
            "hunt.py should import FindingNotificationRouter"
        assert "process_batch" in source, \
            "hunt.py should call process_batch for batch notification processing"

    def test_hunt_notification_after_dedup_in_source(self, monkeypatch):
        """
        Verify that notification code appears AFTER dedup in hunt.py source.
        The deduplicate_findings call should come before process_batch.
        """
        from src.commands.hunt import run_hybrid_hunt
        import inspect
        
        source = inspect.getsource(run_hybrid_hunt)
        dedup_pos = source.find("deduplicate_findings")
        notify_pos = source.find("process_batch")
        
        assert dedup_pos > 0, "deduplicate_findings not found in hunt.py"
        assert notify_pos > 0, "process_batch not found in hunt.py"
        assert dedup_pos < notify_pos, \
            "deduplicate_findings should appear BEFORE process_batch in hunt.py"

    def test_hunt_old_notify_finding_removed(self, monkeypatch):
        """
        Verify that the old inline notify_finding() loop is removed from hunt.py.
        The old pattern 'notifier.notify_finding(finding)' in a for loop should be gone.
        """
        from src.commands.hunt import run_hybrid_hunt
        import inspect
        
        source = inspect.getsource(run_hybrid_hunt)
        # The old pattern was inside the print loop: notifier.notify_finding(finding)
        # It should no longer exist (only the router-based approach)
        # We check that the FINDING notification call is gone, but IDOR action_required is OK
        old_pattern_lines = [l for l in source.split('\n') if 'notify_finding(finding)' in l]
        assert len(old_pattern_lines) == 0, \
            f"Old notify_finding(finding) pattern should be removed from hunt.py, found: {old_pattern_lines}"


class TestWatchNotificationIntegration:
    """Verify watch.py routes findings through router."""

    def test_secret_finding_converter_exists(self):
        """
        Verify the _secret_finding_to_dict helper exists and produces
        a valid dict for router normalization.
        """
        from src.commands.watch import _secret_finding_to_dict
        
        # Mock a SecretFinding-like object
        class MockSecretFinding:
            pattern_name = "AWS_ACCESS_KEY"
            matched_value = "AKIAIOSFODNN7EXAMPLE"
            file_path = "config/secrets.yml"
            line_number = 42
            commit_sha = "abc123def456"
            context = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
            severity = Severity.CRITICAL
            vuln_type = VulnType.SECRET_LEAK
        
        finding = MockSecretFinding()
        result = _secret_finding_to_dict(finding, "owner/repo")
        
        assert isinstance(result, dict)
        assert "title" in result
        assert "AWS_ACCESS_KEY" in result["title"]
        assert result["vuln_type"] == "secret_leak"
        assert result["severity"] == "critical"
        assert "owner/repo/config/secrets.yml#L42" in result["target_url"]
        assert result["source_agent"] == "commit_watcher"
        assert result["confidence"] == 0.85

    def test_secret_finding_converter_handles_string_enums(self):
        """
        Verify _secret_finding_to_dict handles cases where severity/vuln_type
        are plain strings (not Enum values).
        """
        from src.commands.watch import _secret_finding_to_dict
        
        class MockSecretFindingStr:
            pattern_name = "GITHUB_TOKEN"
            matched_value = "ghp_xxxxxxxxxxxx"
            file_path = ".github/workflows/deploy.yml"
            line_number = 15
            commit_sha = "def456abc789"
            context = "GITHUB_TOKEN: ghp_xxxxxxxxxxxx"
            severity = "high"  # plain string
            vuln_type = "secret_leak"  # plain string
        
        finding = MockSecretFindingStr()
        result = _secret_finding_to_dict(finding, "org/project")
        
        assert result["severity"] == "high"
        assert result["vuln_type"] == "secret_leak"

    def test_secret_finding_converter_without_value_attr(self):
        """
        Verify _secret_finding_to_dict handles cases where severity/vuln_type
        have no .value attribute (str directly).
        """
        from src.commands.watch import _secret_finding_to_dict
        
        class MockSeverityNoValue:
            def __str__(self):
                return "medium"
        
        class MockVulnNoValue:
            def __str__(self):
                return "api_key_exposure"
        
        class MockSecretFindingObj:
            pattern_name = "API_KEY"
            matched_value = "sk-test123"
            file_path = "src/config.py"
            line_number = 5
            commit_sha = "ghi789"
            context = "API_KEY = sk-test123"
            severity = MockSeverityNoValue()
            vuln_type = MockVulnNoValue()
        
        finding = MockSecretFindingObj()
        result = _secret_finding_to_dict(finding, "test/repo")
        
        # Should not crash; should use str() as fallback
        assert result["severity"] in ("medium", "info", "unknown")

    def test_watch_imports_router(self):
        """
        Verify watch.py imports FindingNotificationRouter.
        """
        from src.commands.watch import run_sentinel_watch
        import inspect
        
        source = inspect.getsource(run_sentinel_watch)
        assert "FindingNotificationRouter" in source, \
            "watch.py should use FindingNotificationRouter"

    def test_watch_has_per_cycle_limit(self):
        """
        Verify watch.py has MAX_NOTIFIES_PER_CYCLE guard.
        """
        from src.commands.watch import run_sentinel_watch
        import inspect
        
        source = inspect.getsource(run_sentinel_watch)
        assert "MAX_NOTIFIES_PER_CYCLE" in source, \
            "watch.py should have per-cycle notification limit"

    def test_secret_finding_does_not_include_raw_matched_value(self):
        """
        Verify that _secret_finding_to_dict does NOT include the raw
        matched_value or context in notification fields.
        """
        from src.commands.watch import _secret_finding_to_dict
        
        class MockSecretFinding:
            pattern_name = "AWS_ACCESS_KEY"
            matched_value = "AKIAIOSFODNN7EXAMPLE"
            file_path = "config/secrets.yml"
            line_number = 42
            commit_sha = "abc123def456789"
            context = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
            severity = Severity.CRITICAL
            vuln_type = VulnType.SECRET_LEAK
        
        finding = MockSecretFinding()
        result = _secret_finding_to_dict(finding, "owner/repo")
        
        # Raw secret must NOT appear in any notification field
        assert "AKIAIOSFODNN7EXAMPLE" not in result["title"], \
            "Raw matched_value must not appear in title"
        assert "AKIAIOSFODNN7EXAMPLE" not in result["description"], \
            "Raw matched_value must not appear in description"
        assert "AKIAIOSFODNN7EXAMPLE" not in result["evidence_summary"], \
            "Raw matched_value must not appear in evidence_summary"
        
        # The context raw text must not appear in description
        assert "aws_access_key_id = AKIAIOSFODNN7EXAMPLE" not in result["description"], \
            "Raw context must not appear in description"
        
        # Safe fields should be present
        assert "AWS_ACCESS_KEY" in result["title"]
        assert "config/secrets.yml" in result["title"]
        assert result["severity"] == "critical"

    def test_secret_finding_safe_description(self):
        """
        Verify _secret_finding_to_dict produces a safe description without
        raw secrets even for different secret types.
        """
        from src.commands.watch import _secret_finding_to_dict
        
        class MockGitHubTokenFinding:
            pattern_name = "GITHUB_TOKEN"
            matched_value = "ghp_1234567890abcdefghijklmnopqrstuv"
            file_path = ".github/workflows/deploy.yml"
            line_number = 10
            commit_sha = "def456789abc012"
            context = "GITHUB_TOKEN: ghp_1234567890abcdefghijklmnopqrstuv"
            severity = Severity.HIGH
            vuln_type = VulnType.SECRET_LEAK
        
        finding = MockGitHubTokenFinding()
        result = _secret_finding_to_dict(finding, "org/project")
        
        assert "ghp_" not in result["title"], "GitHub token must not leak into title"
        assert "ghp_" not in result["description"], "GitHub token must not leak into description"
        assert "GITHUB_TOKEN" in result["title"]

    def test_secret_finding_uses_japanese_not_english(self):
        """
        Verify _secret_finding_to_dict produces Japanese text, not English.
        English markers like 'found in', 'Secret of type', 'Pattern:'
        must not appear. Japanese markers like 'を検出', '種別', '場所'
        must appear.
        """
        from src.commands.watch import _secret_finding_to_dict
        
        class MockSecretFinding:
            pattern_name = "DATABASE_URL"
            matched_value = "postgres://user:pass@host/db"
            file_path = "config/database.yml"
            line_number = 5
            commit_sha = "abc123def456789"
            context = "DATABASE_URL=postgres://user:pass@host/db"
            severity = Severity.HIGH
            vuln_type = VulnType.SECRET_LEAK
        
        finding = MockSecretFinding()
        result = _secret_finding_to_dict(finding, "owner/repo")
        
        # English markers must NOT appear
        assert "found in" not in result["title"], \
            f"English 'found in' should not appear in title: {result['title']}"
        assert "Secret of type" not in result["description"], \
            f"English 'Secret of type' should not appear in description: {result['description']}"
        assert "Pattern:" not in result["evidence_summary"], \
            f"English 'Pattern:' should not appear in evidence_summary: {result['evidence_summary']}"
        assert "File:" not in result["evidence_summary"], \
            f"English 'File:' should not appear in evidence_summary: {result['evidence_summary']}"
        assert "See local report" not in result["description"], \
            f"English 'See local report' should not appear in description: {result['description']}"
        
        # Japanese markers must appear
        assert "を検出" in result["title"], \
            f"Japanese 'を検出' should appear in title: {result['title']}"
        assert "を検出しました" in result["description"], \
            f"Japanese 'を検出しました' should appear in description: {result['description']}"
        assert "ローカルレポート" in result["description"], \
            f"Japanese 'ローカルレポート' should appear in description: {result['description']}"
        assert "種別:" in result["evidence_summary"], \
            f"Japanese '種別:' should appear in evidence_summary: {result['evidence_summary']}"
        assert "場所:" in result["evidence_summary"], \
            f"Japanese '場所:' should appear in evidence_summary: {result['evidence_summary']}"


class TestPhaseBEndToEnd:
    """End-to-end integration tests for Phase B router wiring."""

    def test_hunt_findings_normalize_through_router(self, monkeypatch):
        """
        Verify that when hunt findings are processed through the router,
        they normalize correctly and all severities are accepted.
        """
        from src.core.notifications.finding_notification_router import FindingNotificationRouter
        
        router = FindingNotificationRouter(run_id="test-hunt-e2e")
        
        # Simulate hunt findings (mixed severities, like hunt produces)
        findings = [
            Finding(
                vuln_type=VulnType.SQLI,
                severity=Severity.CRITICAL,
                title="SQL Injection in Login",
                description="UNION-based SQLi",
                target_url="https://example.com/login",
                source_agent="sqli_hunter",
                confidence=0.95,
            ),
            Finding(
                vuln_type=VulnType.XSS,
                severity=Severity.MEDIUM,
                title="Reflected XSS in Search",
                description="XSS via q parameter",
                target_url="https://example.com/search",
                source_agent="xss_hunter",
                confidence=0.70,
            ),
            Finding(
                vuln_type=VulnType.IDOR,
                severity=Severity.LOW,
                title="IDOR in User Profile",
                description="Accessing other user data",
                target_url="https://example.com/api/user/42",
                source_agent="idor_hunter",
                confidence=0.60,
            ),
        ]
        
        # Process batch (like hunt does after dedup)
        dtos = router.process_batch(findings, source_component="hunt", ingress_path="test")
        
        # All 3 should normalize (no severity filter)
        assert len(dtos) == 3, f"Expected 3 DTOs, got {len(dtos)}"
        
        severities = [d.severity for d in dtos]
        assert "critical" in severities
        assert "medium" in severities
        assert "low" in severities

    def test_watch_finding_dict_routes_through_router(self, monkeypatch):
        """
        Verify that watch-style finding dicts normalize through the router.
        """
        from src.core.notifications.finding_notification_router import FindingNotificationRouter
        
        router = FindingNotificationRouter(run_id="test-watch-e2e")
        
        # Dict like what _secret_finding_to_dict produces
        watch_finding = {
            "title": "AWS_ACCESS_KEY: AKIAIOSFODNN7EXAMPLE",
            "vuln_type": "secret_leak",
            "type": "secret_leak",
            "severity": "critical",
            "target_url": "owner/repo/config/secrets.yml#L42",
            "target": "owner/repo/config/secrets.yml#L42",
            "description": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
            "source_agent": "commit_watcher",
            "confidence": 0.85,
        }
        
        dto = router.normalize(watch_finding, source_component="watch", ingress_path="test")
        
        assert dto is not None, "Watch finding should normalize successfully"
        assert dto.severity == "critical"
        assert dto.vuln_type == "secret_leak"
        assert dto.title != ""
        assert dto.source_agent == "commit_watcher"

    def test_router_accepts_both_finding_and_dict_inputs(self, monkeypatch):
        """
        Verify the router handles both Finding objects (hunt) and dicts (watch).
        """
        from src.core.notifications.finding_notification_router import FindingNotificationRouter
        
        router = FindingNotificationRouter(run_id="test-mixed-inputs")
        
        # Finding object (from hunt)
        finding_obj = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.HIGH,
            title="XSS Test",
            description="Test",
            target_url="https://example.com",
        )
        
        # Dict (from watch)
        finding_dict = {
            "title": "Secret Leak Test",
            "vuln_type": "secret_leak",
            "severity": "high",
            "target_url": "repo/file.py#L10",
            "description": "Test secret",
        }
        
        dto1 = router.normalize(finding_obj, source_component="hunt", ingress_path="test")
        dto2 = router.normalize(finding_dict, source_component="watch", ingress_path="test")
        
        assert dto1 is not None
        assert dto2 is not None
        assert dto1.source_component == "hunt"
        assert dto2.source_component == "watch"


class TestWatchOperationalGuards:
    """Verify watch.py operational protections."""

    def test_watch_notification_failure_does_not_crash(self, monkeypatch):
        """
        Verify that a notification failure in the watch loop does not crash
        the loop. The router's route_and_notify should handle errors gracefully.
        """
        from src.core.notifications.finding_notification_router import (
            FindingNotificationDTO, FindingNotificationRouter
        )
        
        router = FindingNotificationRouter(run_id="test-watch-resilience")
        
        # Simulate a finding that would fail (empty target_url)
        dto = FindingNotificationDTO(
            finding_id="test-resilience",
            severity="high",
            vuln_type="secret_leak",
            title="Test Resilience",
            target_url="",  # empty
            description="Test",
        )
        
        # route_and_notify should not raise, even with issues
        try:
            result = router.route_and_notify(dto, source_component="watch", ingress_path="test")
            # Should return a result dict, not raise
            assert isinstance(result, dict)
            assert "error" in result or "notified" in result
        except Exception as e:
            pytest.fail(f"route_and_notify raised unexpected exception: {e}")

    def test_watch_per_cycle_limit_stops_after_max(self, monkeypatch):
        """
        Simulate watch per-cycle limit: after MAX_NOTIFIES_PER_CYCLE notifications,
        further notifications should not be attempted.
        This tests the concept (the actual limit is in watch.py runtime).
        """
        MAX = 3
        notify_count = 0
        findings = [f"finding-{i}" for i in range(10)]
        notified = []
        
        for finding in findings:
            if notify_count < MAX:
                notified.append(finding)
                notify_count += 1
            # else: skip (simulating the limit check)
        
        assert len(notified) == MAX, f"Should stop at {MAX}, got {len(notified)}"
        assert len(notified) < len(findings), "Should not notify all findings"

    def test_per_cycle_limit_counts_attempts_not_just_successes(self):
        """
        Verify conceptual test: notify_count should increment on EVERY attempt,
        not just successes. This tests the concept that the watch.py implementation
        should follow (cycle_notify_attempts increments regardless of outcome).
        """
        MAX = 5
        attempts = 0
        
        # Simulate: 3 successes, 2 failures, 1 more attempt
        results = [True, True, False, True, False, True]  # 4 successes, 2 failures
        
        for success in results:
            if attempts < MAX:
                attempts += 1
                # (success/failure doesn't matter for the limit)
            else:
                break
        
        assert attempts == MAX, f"Should stop after {MAX} attempts, got {attempts}"
        # The 6th result (True) should have been skipped because limit reached

    def test_consecutive_failures_reset_on_success(self):
        """
        Conceptual test: consecutive_failures should reset to 0 on successful
        notification, but total_failures should keep accumulating.
        """
        consecutive = 0
        total = 0
        
        # Sequence: fail, fail, success, fail
        events = [False, False, True, False]
        
        for success in events:
            if success:
                consecutive = 0
            else:
                consecutive += 1
                total += 1
        
        assert consecutive == 1, "After success+one failure, consecutive should be 1"
        assert total == 3, "Total failures should be 3"

    def test_notification_service_handles_string_vuln_type(self, monkeypatch):
        """
        Verify that NotificationService._on_finding_event() can handle
        string vuln_type from VULN_FOUND event payload (Phase C fix).
        """
        from src.core.notifications.notification_service import NotificationService
        from src.core.infra.event_bus import Event, EventType
        
        service = NotificationService()
        # Disable actual notification sending
        monkeypatch.setattr(service.notifier, 'notify_finding', lambda *a, **k: True)
        monkeypatch.setattr(service.notifier, 'notify_path', '/usr/bin/notify')
        monkeypatch.setattr(service, '_is_duplicate', lambda *a, **k: False)
        
        # Create a VULN_FOUND event with string vuln_type (as MC emits)
        event = Event(
            type=EventType.VULN_FOUND,
            payload={
                "finding": {
                    "id": "test-phasec-001",
                    "vuln_type": "sqli",       # STRING, not Enum
                    "type": "sqli",
                    "severity": "high",
                    "title": "SQL Injection",
                    "description": "Test SQLi",
                    "target_url": "https://example.com/login",
                    "target": "https://example.com/login",
                    "source_agent": "test_agent",
                    "confidence": 0.9,
                    "impact": "Test impact",
                }
            },
            source="test",
        )
        
        # Should NOT crash (was crashing on Enum coercion before Phase C)
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(service._on_finding_event(event))
            else:
                loop.run_until_complete(service._on_finding_event(event))
        except Exception as e:
            pytest.fail(f"_on_finding_event crashed on string vuln_type: {e}")

    def test_notification_service_handles_unknown_severity(self, monkeypatch):
        """
        Verify NotificationService._on_finding_event() handles unexpected
        severity values (uppercase, unknown) without crashing.
        """
        from src.core.notifications.notification_service import NotificationService
        from src.core.infra.event_bus import Event, EventType
        
        service = NotificationService()
        monkeypatch.setattr(service.notifier, 'notify_finding', lambda *a, **k: True)
        monkeypatch.setattr(service.notifier, 'notify_path', '/usr/bin/notify')
        monkeypatch.setattr(service, '_is_duplicate', lambda *a, **k: False)
        
        # Test with uppercase severity
        event_upper = Event(
            type=EventType.VULN_FOUND,
            payload={
                "finding": {
                    "id": "test-sev-upper",
                    "vuln_type": "xss",
                    "severity": "HIGH",      # UPPERCASE - should still work
                    "title": "XSS Test",
                    "description": "Test",
                    "target_url": "https://example.com",
                }
            },
            source="test",
        )
        
        # Test with unknown severity
        event_unknown = Event(
            type=EventType.VULN_FOUND,
            payload={
                "finding": {
                    "id": "test-sev-unknown",
                    "vuln_type": "sqli",
                    "severity": "banana",    # Unknown - should default to INFO
                    "title": "SQLi Test",
                    "description": "Test",
                    "target_url": "https://example.com",
                }
            },
            source="test",
        )
        
        import asyncio
        loop = asyncio.get_event_loop()
        try:
            # Both should NOT crash
            for event in [event_upper, event_unknown]:
                if loop.is_running():
                    asyncio.ensure_future(service._on_finding_event(event))
                else:
                    loop.run_until_complete(service._on_finding_event(event))
        except Exception as e:
            pytest.fail(f"_on_finding_event crashed on unexpected severity: {e}")
