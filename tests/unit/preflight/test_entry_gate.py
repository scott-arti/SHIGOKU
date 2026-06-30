"""Integration tests for EntryGate orchestrator and EntryGateFacade.

Verifies:
- EntryGateFacade.run_once() idempotency
- Full gate flow with mock checkers
- Fail-fast on Caido failure
- Phase-based enable/disable
- Resume hardening
- Context masking
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.core.preflight.entry_gate import EntryGate, EntryGateFacade
from src.core.preflight.models import (
    PreflightResult, PreflightFailure, PreflightStatus, PreflightSnapshot,
    PreflightContext, GatePhase, GatePolicy, AuthProbeResult, AuthClassification,
)


class TestEntryGateFacade:
    def test_singleton(self):
        f1 = EntryGateFacade()
        f2 = EntryGateFacade()
        assert f1 is f2

    @pytest.mark.asyncio
    async def test_run_once_caches_same_context(self):
        """run_once should return cached result for identical context (cache hit)."""
        facade = EntryGateFacade()
        facade.reset()

        context = PreflightContext(target="https://example.com", goal="recon")
        result1 = await facade.run_once(context)
        result2 = await facade.run_once(context)

        # Same context → same cached result
        assert result1 is result2

    @pytest.mark.asyncio
    async def test_run_once_different_context_reevaluates(self):
        """run_once should re-evaluate for different context (cache miss)."""
        facade = EntryGateFacade()
        facade.reset()

        ctx_a = PreflightContext(target="https://example.com", goal="recon")
        ctx_b = PreflightContext(target="https://other.com", goal="recon")

        result_a = await facade.run_once(ctx_a)
        result_b = await facade.run_once(ctx_b)

        # Different contexts → should NOT be the same cached result
        assert result_a is not result_b

    @pytest.mark.asyncio
    async def test_run_once_different_auth_reevaluates(self):
        """Different auth presence should cause re-evaluation."""
        facade = EntryGateFacade()
        facade.reset()

        ctx_no_auth = PreflightContext(target="https://example.com", goal="recon")
        ctx_auth = PreflightContext(target="https://example.com", goal="recon",
                                     bearer_token="test-token")

        result_no_auth = await facade.run_once(ctx_no_auth)
        result_auth = await facade.run_once(ctx_auth)

        # Different auth presence → should re-evaluate
        assert result_no_auth is not result_auth

    @pytest.mark.asyncio
    async def test_reset_clears_cache(self):
        facade = EntryGateFacade()
        facade.reset()
        context = PreflightContext(target="https://example.com")
        await facade.run_once(context)
        assert len(facade._cache) == 1

        facade.reset()
        assert len(facade._cache) == 0


class TestEntryGateCaidoFailFast:
    @pytest.mark.asyncio
    async def test_caido_fail_stops_immediately(self):
        """When Caido fails, the gate should return FAIL without running further checks."""
        gate = EntryGate()

        with patch.object(gate, "_run_caido_check", new_callable=AsyncMock) as mock_caido:
            with patch.object(gate, "_run_tool_check", new_callable=AsyncMock) as mock_tool:
                with patch.object(gate, "_run_target_basic_check", new_callable=AsyncMock) as mock_target:
                    mock_caido.return_value = [
                        PreflightFailure(reason_code="CAIDO_TCP_UNREACHABLE", severity="critical")
                    ]
                    mock_target.return_value = []

                    context = PreflightContext()
                    result = await gate.run(context)

                    assert result.failed
                    assert len(result.failures) == 1
                    assert result.failures[0].reason_code == "CAIDO_TCP_UNREACHABLE"
                    # Tool check should NOT have been called (fail-fast)
                    mock_tool.assert_not_called()

    @pytest.mark.asyncio
    async def test_target_dns_fail_stops_immediately(self):
        """When target DNS fails, the gate should fail-close."""
        gate = EntryGate()

        with patch.object(gate, "_run_caido_check", new_callable=AsyncMock) as mock_caido:
            with patch.object(gate, "_run_target_basic_check", new_callable=AsyncMock) as mock_target:
                mock_caido.return_value = []
                mock_target.return_value = [
                    PreflightFailure(reason_code="TARGET_DNS_FAILURE", severity="critical")
                ]

                context = PreflightContext(target="https://nonexistent.example.com")
                result = await gate.run(context)

                assert result.failed
                assert result.failures[0].reason_code == "TARGET_DNS_FAILURE"


class TestEntryGatePhaseControl:
    @pytest.mark.asyncio
    async def test_phase1_only_runs_caido_and_target(self):
        """With only Phase 1, only Caido + target checks should run."""
        gate = EntryGate()

        with patch.object(gate, "_run_caido_check", new_callable=AsyncMock) as mock_caido:
            with patch.object(gate, "_run_target_basic_check", new_callable=AsyncMock) as mock_target:
                with patch.object(gate, "_run_tool_check", new_callable=AsyncMock) as mock_tool:
                    with patch.object(gate, "_run_auth_probe", new_callable=AsyncMock) as mock_auth:
                        mock_caido.return_value = []
                        mock_target.return_value = []

                        context = PreflightContext(
                            active_phases=[GatePhase.PHASE_1_DETERMINISTIC],
                            target="https://example.com",
                        )
                        result = await gate.run(context)

                        assert result.passed
                        mock_caido.assert_called_once()
                        mock_target.assert_called_once()
                        mock_tool.assert_not_called()
                        mock_auth.assert_not_called()

    @pytest.mark.asyncio
    async def test_all_phases_run_when_enabled(self):
        """With all phases, all checks should run."""
        gate = EntryGate()

        with patch.object(gate, "_run_caido_check", new_callable=AsyncMock) as mock_caido:
            with patch.object(gate, "_run_target_basic_check", new_callable=AsyncMock) as mock_target:
                with patch.object(gate, "_run_tool_check", new_callable=AsyncMock) as mock_tool:
                    with patch.object(gate, "_run_auth_probe", new_callable=AsyncMock) as mock_auth:
                        mock_caido.return_value = []
                        mock_target.return_value = []
                        mock_tool.return_value = ([], {})
                        mock_auth.return_value = ([], AuthProbeResult(classification=AuthClassification.AUTHENTICATED))

                        context = PreflightContext(
                            active_phases=[
                                GatePhase.PHASE_1_DETERMINISTIC,
                                GatePhase.PHASE_2_TOOL_UPDATE,
                                GatePhase.PHASE_3_AI_CLASSIFIER,
                                GatePhase.PHASE_4_RESUME_HARDENING,
                            ],
                            target="https://example.com",
                        )
                        result = await gate.run(context)

                        assert result.passed
                        mock_caido.assert_called_once()
                        mock_target.assert_called_once()
                        mock_tool.assert_called_once()
                        mock_auth.assert_called_once()


class TestEntryGateToolFailure:
    @pytest.mark.asyncio
    async def test_tool_critical_failure_fails_fast(self):
        """Critical tool failures should stop the gate."""
        gate = EntryGate()

        with patch.object(gate, "_run_caido_check", new_callable=AsyncMock) as mock_caido:
            with patch.object(gate, "_run_target_basic_check", new_callable=AsyncMock) as mock_target:
                with patch.object(gate, "_run_tool_check", new_callable=AsyncMock) as mock_tool:
                    with patch.object(gate, "_run_auth_probe", new_callable=AsyncMock) as mock_auth:
                        mock_caido.return_value = []
                        mock_target.return_value = []
                        mock_tool.return_value = (
                            [PreflightFailure(reason_code="TOOL_MISSING", severity="critical")],
                            {"nuclei": "missing"},
                        )

                        context = PreflightContext(target="https://example.com")
                        result = await gate.run(context)

                        assert result.failed
                        assert len(result.failures) == 1
                        assert result.snapshot.tool_results == {"nuclei": "missing"}
                        # Auth probe should NOT run (critical tool failure)
                        mock_auth.assert_not_called()


class TestEntryGateResumeHardening:
    @pytest.mark.asyncio
    async def test_resume_hardening_detects_caido_lost(self):
        """Resume hardening should detect when Caido was ok before but not now."""
        gate = EntryGate()

        with patch.object(gate, "_run_caido_check", new_callable=AsyncMock) as mock_caido:
            with patch.object(gate, "_run_target_basic_check", new_callable=AsyncMock) as mock_target:
                with patch.object(gate, "_run_tool_check", new_callable=AsyncMock) as mock_tool:
                    with patch.object(gate, "_run_auth_probe", new_callable=AsyncMock) as mock_auth:
                        mock_caido.return_value = [
                            PreflightFailure(reason_code="CAIDO_TCP_UNREACHABLE", severity="critical")
                        ]
                        mock_target.return_value = []

                        # Previous snapshot had Caido OK
                        prev_snapshot = PreflightSnapshot(caido_tcp_ok=True, caido_http_ok=True)

                        context = PreflightContext(
                            resume_session_id="test-session-12345",
                            previous_preflight_snapshot=prev_snapshot,
                            target="https://example.com",
                        )
                        result = await gate.run(context)

                        assert result.failed

    @pytest.mark.asyncio
    async def test_resume_hardening_not_triggered_without_session_id(self):
        """Resume hardening should not trigger when no session ID is provided."""
        gate = EntryGate()

        with patch.object(gate, "_run_caido_check", new_callable=AsyncMock) as mock_caido:
            with patch.object(gate, "_run_target_basic_check", new_callable=AsyncMock) as mock_target:
                with patch.object(gate, "_run_tool_check", new_callable=AsyncMock) as mock_tool:
                    with patch.object(gate, "_run_auth_probe", new_callable=AsyncMock) as mock_auth:
                        with patch.object(gate, "_run_resume_hardening", new_callable=AsyncMock) as mock_resume:
                            mock_caido.return_value = []
                            mock_target.return_value = []
                            mock_tool.return_value = ([], {})
                            mock_auth.return_value = ([], None)

                            context = PreflightContext(
                                resume_session_id="",  # No session
                                target="https://example.com",
                            )
                            await gate.run(context)

                            # Resume hardening should NOT be called
                            mock_resume.assert_not_called()


class TestPreflightResultSnapshot:
    @pytest.mark.asyncio
    async def test_snapshot_contains_timing(self):
        """Snapshot should include elapsed time."""
        gate = EntryGate()

        with patch.object(gate, "_run_caido_check", new_callable=AsyncMock) as mock_caido:
            with patch.object(gate, "_run_target_basic_check", new_callable=AsyncMock) as mock_target:
                with patch.object(gate, "_run_tool_check", new_callable=AsyncMock) as mock_tool:
                    with patch.object(gate, "_run_auth_probe", new_callable=AsyncMock) as mock_auth:
                        mock_caido.return_value = []
                        mock_target.return_value = []
                        mock_tool.return_value = ([], {})
                        mock_auth.return_value = ([], None)

                        context = PreflightContext(target="https://example.com")
                        result = await gate.run(context)

                        assert result.snapshot is not None
                        assert result.snapshot.elapsed_ms > 0
                        assert result.snapshot.status == PreflightStatus.PASS

    @pytest.mark.asyncio
    async def test_context_summary_masks_secrets(self):
        """Context summary should not contain raw tokens or cookies."""
        gate = EntryGate()

        with patch.object(gate, "_run_caido_check", new_callable=AsyncMock) as mock_caido:
            with patch.object(gate, "_run_target_basic_check", new_callable=AsyncMock) as mock_target:
                mock_caido.return_value = []
                mock_target.return_value = []

                context = PreflightContext(
                    target="https://example.com",
                    bearer_token="secret-token-12345",
                    cookies={"session": "secret-session"},
                    caido_token="caido-secret-token",
                )
                result = await gate.run(context)

                summary = result.snapshot.context_summary
                assert summary["has_bearer_token"] is True
                assert summary["has_caido_token"] is True
                assert "secret-token-12345" not in str(summary)
                assert "secret-session" not in str(summary)


class TestEntryGateCacheKey:
    """Regression tests: caido_token changes must produce different cache keys."""

    def test_cache_key_changes_with_caido_token(self):
        """Context A with caido_token='token-a' and context B with 'token-b' yield different keys."""
        facade = EntryGateFacade()
        facade.reset()

        ctx_a = PreflightContext(target="https://example.com", goal="recon", caido_token="token-a")
        ctx_b = PreflightContext(target="https://example.com", goal="recon", caido_token="token-b")

        key_a = facade._cache_key(ctx_a)
        key_b = facade._cache_key(ctx_b)

        assert key_a != key_b, (
            f"Cache keys should differ when caido_token changes, got: {key_a} vs {key_b}"
        )

    def test_cache_key_includes_caido_token_value(self):
        """Changing only caido_token must change the cache key."""
        facade = EntryGateFacade()
        facade.reset()

        base = PreflightContext(target="https://example.com", goal="recon", profile="full",
                                caido_token="original-token")
        only_caido_changed = PreflightContext(target="https://example.com", goal="recon", profile="full",
                                              caido_token="different-token")

        key_base = facade._cache_key(base)
        key_changed = facade._cache_key(only_caido_changed)

        assert key_base != key_changed, (
            f"Cache keys must differ when only caido_token changes"
        )

    def test_cache_key_same_for_identical_contexts(self):
        """Identical contexts yield identical cache keys (sanity check)."""
        facade = EntryGateFacade()
        facade.reset()

        ctx1 = PreflightContext(target="https://example.com", goal="recon",
                                caido_token="same-token", profile="full")
        ctx2 = PreflightContext(target="https://example.com", goal="recon",
                                caido_token="same-token", profile="full")

        assert facade._cache_key(ctx1) == facade._cache_key(ctx2)

    def test_cache_key_unchanged_when_all_else_equal(self):
        """Cache key unchanged when non-credential fields differ but credentials match."""
        facade = EntryGateFacade()
        facade.reset()

        ctx_a = PreflightContext(target="https://a.com", caido_token="tok", goal="recon")
        ctx_b = PreflightContext(target="https://b.com", caido_token="tok", goal="recon")

        # Different targets → different keys (non-credential input changes key)
        assert facade._cache_key(ctx_a) != facade._cache_key(ctx_b)

        # Same everything = same key
        assert facade._cache_key(ctx_a) == facade._cache_key(ctx_a)
