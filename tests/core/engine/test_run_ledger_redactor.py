"""
TDD tests for run ledger redaction (Step 3).
"""
import json
import hashlib
from pathlib import Path

import pytest

from src.core.models.run_ledger import (
    RunLedgerRecorder, RunLedgerEventType,
    reset_run_ledger_recorder,
)
from src.core.engine.run_ledger_redactor import (
    RedactionResult,
    redact_content,
    redact_for_ledger,
)


# ---------------------------------------------------------------------------
# RedactionResult tests
# ---------------------------------------------------------------------------

class TestRedactionResult:
    def test_no_secrets_found(self) -> None:
        result = redact_content("This is a safe message.")
        assert result.redaction_status == "none"
        assert result.redacted_fields_count == 0

    def test_api_key_redacted(self) -> None:
        result = redact_content("Use token sk-abc123def456ghi789jkl to authenticate")
        assert result.redaction_status in ("partial", "full")
        assert result.redacted_fields_count >= 1
        assert "sk-" not in result.summary

    def test_bearer_token_redacted(self) -> None:
        result = redact_content("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGVzdCJ9.abc123")
        assert result.redaction_status in ("partial", "full")
        assert result.redacted_fields_count >= 1
        assert "eyJ" not in result.summary

    def test_basic_auth_redacted(self) -> None:
        result = redact_content("curl -u admin:SuperSecret123 https://example.com")
        assert result.redaction_status in ("partial", "full")
        assert result.redacted_fields_count >= 1
        assert "SuperSecret123" not in result.summary

    def test_cookie_redacted(self) -> None:
        result = redact_content("Cookie: session=abc123; token=secret_value;")
        assert result.redaction_status in ("partial", "full")
        assert result.redacted_fields_count >= 1
        assert "secret_value" not in result.summary

    def test_multiple_secrets_redacted(self) -> None:
        content = (
            "curl -H 'Authorization: Bearer eyJtoken' "
            "-H 'X-API-Key: sk-proj-deadbeef' "
            "https://api.example.com/data"
        )
        result = redact_content(content)
        assert result.redaction_status in ("partial", "full")
        assert result.redacted_fields_count >= 2
        assert "sk-proj-deadbeef" not in result.summary
        assert "eyJtoken" not in result.summary

    def test_fingerprint_consistent_for_same_content(self) -> None:
        r1 = redact_content("call tool scan with target https://example.com")
        r2 = redact_content("call tool scan with target https://example.com")
        assert r1.fingerprint == r2.fingerprint

    def test_fingerprint_different_for_different_content(self) -> None:
        r1 = redact_content("call tool scan with target https://example.com")
        r2 = redact_content("call tool scan with target https://example.org")
        assert r1.fingerprint != r2.fingerprint

    def test_aws_key_redacted(self) -> None:
        result = redact_content("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        assert result.redaction_status in ("partial", "full")
        assert result.redacted_fields_count >= 1
        assert "AKIAIOSFODNN7EXAMPLE" not in result.summary

    def test_non_secret_preserved(self) -> None:
        result = redact_content("Scan URL https://example.com with timeout 30")
        assert "https://example.com" in result.summary
        assert "timeout 30" in result.summary


# ---------------------------------------------------------------------------
# redact_for_ledger integration tests
# ---------------------------------------------------------------------------

class TestRedactForLedger:
    def test_redact_for_ledger_clean_content(self, tmp_path) -> None:
        """Clean content with no secrets passes through"""
        summary, fingerprint, status, count = redact_for_ledger(
            "Execute SQL injection probe on parameter 'id'"
        )
        assert summary is not None
        assert fingerprint is not None
        assert status == "none"
        assert count == 0
        assert "SQL injection" in summary

    def test_redact_for_ledger_with_secret(self, tmp_path) -> None:
        """Secret-bearing content gets redacted in summary with count"""
        summary, fingerprint, status, count = redact_for_ledger(
            "curl -H 'Authorization: Bearer secret_token_here' https://target.example.com"
        )
        assert summary is not None
        assert fingerprint is not None
        assert status == "partial"
        assert count >= 1
        assert "secret_token_here" not in summary

    def test_redact_for_ledger_truncates_long_input(self) -> None:
        """Very long input is truncated in summary"""
        long_input = "A" * 2000
        summary, _, _, _ = redact_for_ledger(long_input)
        assert len(summary) <= 500  # max summary length

    def test_redact_for_ledger_none_input(self) -> None:
        """None input returns safe defaults"""
        summary, fingerprint, status, count = redact_for_ledger(None)
        assert summary is None
        assert fingerprint is None
        assert status is None
        assert count == 0


# ---------------------------------------------------------------------------
# Integration: secret content does NOT leak into session payload
# ---------------------------------------------------------------------------

class TestNoSecretLeakage:
    def test_secret_not_in_session_payload(self) -> None:
        """Secret-bearing tool command is redacted before entering session payload"""
        recorder = RunLedgerRecorder(run_id="run001")
        raw_command = "curl -X POST -H 'X-API-Key: sk-secret123' https://target/vuln"
        summary, fp, status, count = redact_for_ledger(raw_command)
        recorder.record(
            event_type=RunLedgerEventType.TOOL_EXECUTED,
            phase="attack",
            actor_type="SwarmWorker",
            actor_name="xss",
            input_summary=summary,
            input_fingerprint=fp,
            redaction_status=status,
            redacted_fields_count=count,
        )
        payload = recorder.to_session_payload()
        session_json = json.dumps(payload)
        assert "sk-secret123" not in session_json
        assert "[REDACTED]" in session_json or "tool_executed" in session_json

    def test_secret_not_in_spool(self, tmp_path) -> None:
        """Secret-bearing content is redacted in JSONL spool"""
        from src.core.models.run_ledger import SPOOL_EVENT_THRESHOLD
        recorder = RunLedgerRecorder(run_id="run001", max_events=SPOOL_EVENT_THRESHOLD)
        for i in range(SPOOL_EVENT_THRESHOLD):
            raw = f"curl -H 'Authorization: Bearer token_{i}' https://target/check"
            summary, fp, status, count = redact_for_ledger(raw)
            recorder.record(
                event_type=RunLedgerEventType.TOOL_EXECUTED,
                phase="attack",
                actor_type="SwarmWorker",
                actor_name=f"worker_{i}",
                input_summary=summary,
                input_fingerprint=fp,
                redaction_status=status,
                redacted_fields_count=count,
            )
        spool_dir = tmp_path / "spool"
        spool_dir.mkdir()
        spool_file = recorder.flush_to_spool(str(spool_dir))
        assert spool_file is not None
        spool_content = spool_file.read_text(encoding="utf-8")
        assert "token_0" not in spool_content
        assert "token_" not in spool_content

    def test_secret_with_cookie(self) -> None:
        """Cookie secrets are redacted"""
        raw = "curl -b 'session_id=abc1234567890' https://target.example.com"
        summary, _, status, count = redact_for_ledger(raw)
        assert "abc1234567890" not in summary
        assert count >= 1
        assert status == "partial"

    def test_secret_with_basic_auth(self) -> None:
        """Basic auth credentials are redacted"""
        raw = "curl -u admin:MyPassword123 https://target.example.com/admin"
        summary, _, status, count = redact_for_ledger(raw)
        assert "MyPassword123" not in summary
        assert count >= 1
        assert status == "partial"


# ---------------------------------------------------------------------------
# Source_refs redaction (record() boundary)
# ---------------------------------------------------------------------------

class TestSourceRefsRedaction:
    def test_source_refs_with_api_key_redacted(self) -> None:
        """source_refs containing API keys are redacted at record() boundary."""
        from src.core.models.run_ledger import RunLedgerRecorder, RunLedgerEventType
        recorder = RunLedgerRecorder(run_id="sr01")
        evt = recorder.record(
            event_type=RunLedgerEventType.TOOL_EXECUTED,
            phase="attack",
            actor_type="SwarmWorker",
            actor_name="test",
            source_refs={"api_key": "sk-abc1234567890defghijklmnop", "url": "https://safe.example.com"},
        )
        assert "sk-" not in str(evt.source_refs)
        assert evt.redacted_fields_count >= 1
        assert evt.redaction_status == "partial"
        # safe values preserved
        assert "safe.example.com" in str(evt.source_refs)

    def test_source_refs_nested_dict_redacted(self) -> None:
        """Nested dicts in source_refs are recursively redacted."""
        from src.core.models.run_ledger import RunLedgerRecorder, RunLedgerEventType
        recorder = RunLedgerRecorder(run_id="sr02")
        evt = recorder.record(
            event_type=RunLedgerEventType.SWARM_DISPATCHED,
            phase="attack",
            actor_type="SwarmDispatcher",
            actor_name="test",
            source_refs={
                "swarm_config": {
                    "api_key": "sk-deadbeef1234567890abcdef",
                    "target": "https://example.com",
                },
                "headers": ["Authorization: Bearer secret_token_xyz", "Content-Type: application/json"],
            },
        )
        source_refs_str = str(evt.source_refs)
        assert "sk-deadbeef" not in source_refs_str
        assert "secret_token_xyz" not in source_refs_str
        assert "Bearer" not in source_refs_str
        assert evt.redacted_fields_count >= 2
        # safe values preserved
        assert "https://example.com" in source_refs_str

    def test_source_refs_with_cookie_redacted(self) -> None:
        """Cookie values in source_refs are redacted."""
        from src.core.models.run_ledger import RunLedgerRecorder, RunLedgerEventType
        recorder = RunLedgerRecorder(run_id="sr03")
        evt = recorder.record(
            event_type=RunLedgerEventType.LLM_CALLED,
            phase="llm",
            actor_type="LLMClient",
            actor_name="test",
            source_refs={"extra": {"cookie": "session_id=abcdef1234567890"}},
        )
        assert "abcdef1234567890" not in str(evt.source_refs)
        assert evt.redacted_fields_count >= 1

    def test_source_refs_clean_is_unchanged(self) -> None:
        """Clean source_refs with no secrets are not redacted."""
        from src.core.models.run_ledger import RunLedgerRecorder, RunLedgerEventType
        recorder = RunLedgerRecorder(run_id="sr04")
        evt = recorder.record(
            event_type=RunLedgerEventType.FINDING_CREATED,
            phase="attack",
            actor_type="SwarmWorker",
            actor_name="test",
            source_refs={"severity": "high", "count": 3, "url": "https://example.com/page"},
        )
        assert evt.redacted_fields_count == 0
        assert evt.redaction_status == "none"
        assert evt.source_refs == {"severity": "high", "count": 3, "url": "https://example.com/page"}
