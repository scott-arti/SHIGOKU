"""
Unit tests for ExecutionSafeguardService, PayloadRiskPolicy, MethodRiskPolicy,
SafeguardDecision, and integration with SmartRequest / SmartSQLiHunter.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from src.core.security.execution_safeguard import (
    SafeguardDecision,
    PayloadRiskPolicy,
    MethodRiskPolicy,
    ExecutionSafeguardService,
    get_execution_safeguard,
    reset_execution_safeguard,
)
from src.core.security.request_guard import RequestGuard, reset_request_guard


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_singletons():
    """Reset singletons between tests."""
    reset_execution_safeguard()
    reset_request_guard()
    yield
    reset_execution_safeguard()
    reset_request_guard()


@pytest.fixture
def mock_hitl():
    return AsyncMock(return_value=True)


@pytest.fixture
def request_guard_bugbounty(mock_hitl):
    return RequestGuard(mode="bugbounty", hitl_callback=mock_hitl)


@pytest.fixture
def request_guard_ctf():
    return RequestGuard(mode="ctf")


@pytest.fixture
def safeguard_bugbounty(request_guard_bugbounty):
    return ExecutionSafeguardService(
        mode="bugbounty",
        request_guard=request_guard_bugbounty,
    )


@pytest.fixture
def safeguard_ctf(request_guard_ctf):
    return ExecutionSafeguardService(
        mode="ctf",
        request_guard=request_guard_ctf,
    )


@pytest.fixture
def safeguard_bugbounty_no_hitl():
    """Bug Bounty safeguard without HITL callback (fail-closed)."""
    guard = RequestGuard(mode="bugbounty", hitl_callback=None)
    return ExecutionSafeguardService(mode="bugbounty", request_guard=guard)


# ---------------------------------------------------------------------------
# SafeguardDecision tests
# ---------------------------------------------------------------------------

class TestSafeguardDecision:
    def test_allow_factory(self):
        d = SafeguardDecision.allow(reason_code="test_code", message="test msg")
        assert d.allowed is True
        assert d.requires_hitl is False
        assert d.reason_code == "test_code"
        assert d.matched_rules == []
        assert d.message == "test msg"

    def test_deny_factory(self):
        d = SafeguardDecision.deny(
            reason_code="denied",
            matched_rules=["rule1", "rule2"],
            message="blocked",
        )
        assert d.allowed is False
        assert d.requires_hitl is False
        assert d.reason_code == "denied"
        assert d.matched_rules == ["rule1", "rule2"]
        assert d.message == "blocked"

    def test_hitl_required_factory(self):
        d = SafeguardDecision.hitl_required(reason_code="need_human", message="needs approval")
        assert d.allowed is False
        assert d.requires_hitl is True
        assert d.reason_code == "need_human"

    def test_default_dataclass(self):
        d = SafeguardDecision()
        assert d.allowed is True
        assert d.requires_hitl is False
        assert d.reason_code == ""
        assert d.matched_rules == []
        assert d.message == ""


# ---------------------------------------------------------------------------
# PayloadRiskPolicy tests
# ---------------------------------------------------------------------------

class TestPayloadRiskPolicy:
    def test_none_payload_allowed(self):
        policy = PayloadRiskPolicy(mode="bugbounty")
        d = policy.evaluate(None)
        assert d.allowed is True
        assert d.reason_code == "payload_none"

    def test_empty_string_allowed(self):
        policy = PayloadRiskPolicy(mode="bugbounty")
        d = policy.evaluate("")
        # Empty string is treated as no payload (falsy check)
        assert d.allowed is True
        assert d.reason_code == "payload_none"

    def test_benign_sqli_payload_allowed_in_bugbounty(self):
        """Simple SELECT/SLEEP probe must NOT be blocked by destructive pattern check."""
        policy = PayloadRiskPolicy(mode="bugbounty")
        d = policy.evaluate("1' OR 1=1--")
        assert d.allowed is True
        assert d.reason_code == "payload_clean"

    def test_delete_from_blocked_in_bugbounty(self):
        policy = PayloadRiskPolicy(mode="bugbounty")
        d = policy.evaluate("1'; DELETE FROM users--")
        assert d.allowed is False
        assert d.reason_code == "destructive_sql_payload_blocked"
        assert "sql_delete_from" in d.matched_rules

    def test_update_set_blocked_in_bugbounty(self):
        policy = PayloadRiskPolicy(mode="bugbounty")
        d = policy.evaluate("1'; UPDATE users SET admin=1--")
        assert d.allowed is False
        assert d.reason_code == "destructive_sql_payload_blocked"
        assert "sql_update_set" in d.matched_rules

    def test_insert_into_blocked_in_bugbounty(self):
        policy = PayloadRiskPolicy(mode="bugbounty")
        d = policy.evaluate("1'; INSERT INTO users VALUES(1,'admin')--")
        assert d.allowed is False
        assert d.reason_code == "destructive_sql_payload_blocked"
        assert "sql_insert_into" in d.matched_rules

    def test_drop_table_blocked_in_bugbounty(self):
        policy = PayloadRiskPolicy(mode="bugbounty")
        d = policy.evaluate("1'; DROP TABLE users--")
        assert d.allowed is False
        assert d.reason_code == "destructive_sql_payload_blocked"
        assert "sql_drop_table" in d.matched_rules

    def test_truncate_blocked_in_bugbounty(self):
        policy = PayloadRiskPolicy(mode="bugbounty")
        d = policy.evaluate("1'; TRUNCATE logs--")
        assert d.allowed is False
        assert d.reason_code == "destructive_sql_payload_blocked"
        assert "sql_truncate" in d.matched_rules

    def test_alter_table_blocked_in_bugbounty(self):
        policy = PayloadRiskPolicy(mode="bugbounty")
        d = policy.evaluate("1'; ALTER TABLE users ADD COLUMN x INT--")
        assert d.allowed is False
        assert d.reason_code == "destructive_sql_payload_blocked"
        assert "sql_alter" in d.matched_rules

    def test_destructive_payload_allowed_in_ctf(self):
        """Destructive SQL payload must be allowed in CTF mode."""
        policy = PayloadRiskPolicy(mode="ctf")
        d = policy.evaluate("1'; DELETE FROM users--")
        assert d.allowed is True
        assert d.reason_code == "ctf_mode_payload_permissive"

    def test_case_insensitive_matching(self):
        policy = PayloadRiskPolicy(mode="bugbounty")
        d = policy.evaluate("1'; delete from users--")
        assert d.allowed is False
        assert "sql_delete_from" in d.matched_rules

    def test_dict_payload_normalised(self):
        """Dict payloads should be flattened to string for matching."""
        policy = PayloadRiskPolicy(mode="bugbounty")
        d = policy.evaluate({"id": "1", "query": "DELETE FROM users"})
        assert d.allowed is False
        assert "sql_delete_from" in d.matched_rules

    def test_time_based_detection_not_blocked_by_default(self):
        """Time-based payloads must be detected but NOT blocked by default."""
        policy = PayloadRiskPolicy(mode="bugbounty")
        assert policy.is_time_based_payload("1' AND SLEEP(5)--") is True
        assert policy.is_time_based_payload("1; WAITFOR DELAY '0:0:5'--") is True
        d = policy.evaluate("1' AND SLEEP(5)--")
        assert d.allowed is True  # not blocked

    def test_time_based_block_when_enabled(self):
        policy = PayloadRiskPolicy(mode="bugbounty")
        policy.set_time_based_block(True)
        d = policy.evaluate("1' AND SLEEP(5)--")
        assert d.allowed is False
        assert d.reason_code == "time_based_payload_blocked"

    def test_non_time_payload_not_detected_as_time_based(self):
        policy = PayloadRiskPolicy(mode="bugbounty")
        assert policy.is_time_based_payload("1' OR 1=1--") is False


# ---------------------------------------------------------------------------
# MethodRiskPolicy tests
# ---------------------------------------------------------------------------

class TestMethodRiskPolicy:
    def test_get_is_safe_in_bugbounty(self):
        policy = MethodRiskPolicy(mode="bugbounty")
        d = policy.evaluate("GET")
        assert d.allowed is True
        assert d.reason_code == "safe_method"

    def test_post_requires_hitl_in_bugbounty(self):
        policy = MethodRiskPolicy(mode="bugbounty")
        d = policy.evaluate("POST")
        assert d.allowed is False
        assert d.requires_hitl is True
        assert d.reason_code == "aggressive_method_requires_hitl"

    def test_put_requires_hitl_in_bugbounty(self):
        policy = MethodRiskPolicy(mode="bugbounty")
        d = policy.evaluate("PUT")
        assert d.allowed is False
        assert d.requires_hitl is True

    def test_post_allowed_in_ctf(self):
        policy = MethodRiskPolicy(mode="ctf")
        d = policy.evaluate("POST")
        assert d.allowed is True
        assert d.reason_code == "ctf_mode_method_permissive"

    def test_is_aggressive_helper(self):
        policy = MethodRiskPolicy()
        assert policy.is_aggressive("POST") is True
        assert policy.is_aggressive("DELETE") is True
        assert policy.is_aggressive("GET") is False
        assert policy.is_aggressive("HEAD") is False

    def test_default_mode_is_bugbounty(self):
        policy = MethodRiskPolicy()
        assert policy.mode == "bugbounty"


# ---------------------------------------------------------------------------
# ExecutionSafeguardService tests
# ---------------------------------------------------------------------------

class TestExecutionSafeguardService:
    # -- Default mode -------------------------------------------------------

    def test_default_mode_is_bugbounty(self):
        """Bug Bounty is the default mode unless explicitly overridden."""
        reset_execution_safeguard()
        reset_request_guard()
        svc = ExecutionSafeguardService()
        assert svc.mode == "bugbounty"

        svc_ctf = ExecutionSafeguardService(mode="ctf")
        assert svc_ctf.mode == "ctf"

    # -- GET always allowed -------------------------------------------------

    @pytest.mark.asyncio
    async def test_get_always_allowed(self, safeguard_bugbounty):
        d = await safeguard_bugbounty.evaluate("GET", "http://example.com/api/test")
        assert d.allowed is True

    @pytest.mark.asyncio
    async def test_get_always_allowed_ctf(self, safeguard_ctf):
        d = await safeguard_ctf.evaluate("GET", "http://example.com/api/test")
        assert d.allowed is True

    # -- POST with HITL callback (bugbounty) --------------------------------

    @pytest.mark.asyncio
    async def test_post_with_hitl_approved(self, safeguard_bugbounty, mock_hitl):
        mock_hitl.return_value = True
        d = await safeguard_bugbounty.evaluate("POST", "http://example.com/api/data", source_agent="test")
        assert d.allowed is True
        assert mock_hitl.call_count == 1

    @pytest.mark.asyncio
    async def test_post_with_hitl_denied(self, safeguard_bugbounty, mock_hitl):
        mock_hitl.return_value = False
        d = await safeguard_bugbounty.evaluate("POST", "http://example.com/api/data")
        assert d.allowed is False
        assert d.requires_hitl is True
        assert d.reason_code == "hitl_endpoint_denied"

    @pytest.mark.asyncio
    async def test_post_endpoint_approval_cached(self, safeguard_bugbounty, mock_hitl):
        """Same normalised endpoint should be cached (no second HITL call)."""
        mock_hitl.return_value = True
        d1 = await safeguard_bugbounty.evaluate("POST", "http://example.com/api/users/123")
        assert d1.allowed is True
        assert mock_hitl.call_count == 1

        d2 = await safeguard_bugbounty.evaluate("POST", "http://example.com/api/users/456")
        assert d2.allowed is True
        assert mock_hitl.call_count == 1  # cached

    # -- Bug Bounty without HITL callback: fail-closed ----------------------

    @pytest.mark.asyncio
    async def test_post_bugbounty_no_callback_blocked(self, safeguard_bugbounty_no_hitl):
        """POST/PUT/DELETE/PATCH in bugbounty without callback is blocked.
        When a RequestGuard is present but has no HITL callback, the guard
        itself returns False and the safeguard reports hitl_endpoint_denied."""
        d = await safeguard_bugbounty_no_hitl.evaluate("POST", "http://example.com/api/data")
        assert d.allowed is False
        assert d.reason_code in ("hitl_endpoint_denied", "no_hitl_callback_bugbounty")

    @pytest.mark.asyncio
    async def test_put_bugbounty_no_callback_blocked(self, safeguard_bugbounty_no_hitl):
        d = await safeguard_bugbounty_no_hitl.evaluate("PUT", "http://example.com/api/data")
        assert d.allowed is False
        assert d.reason_code in ("hitl_endpoint_denied", "no_hitl_callback_bugbounty")

    @pytest.mark.asyncio
    async def test_delete_bugbounty_no_callback_blocked(self, safeguard_bugbounty_no_hitl):
        d = await safeguard_bugbounty_no_hitl.evaluate("DELETE", "http://example.com/api/data")
        assert d.allowed is False
        assert d.reason_code in ("hitl_endpoint_denied", "no_hitl_callback_bugbounty")

    @pytest.mark.asyncio
    async def test_patch_bugbounty_no_callback_blocked(self, safeguard_bugbounty_no_hitl):
        d = await safeguard_bugbounty_no_hitl.evaluate("PATCH", "http://example.com/api/data")
        assert d.allowed is False
        assert d.reason_code in ("hitl_endpoint_denied", "no_hitl_callback_bugbounty")

    @pytest.mark.asyncio
    async def test_bugbounty_no_request_guard_at_all_fail_closed(self):
        """When no RequestGuard is provided at all, fail-closed in bugbounty."""
        svc = ExecutionSafeguardService(mode="bugbounty", request_guard=None)
        d = await svc.evaluate("POST", "http://example.com/api/data")
        assert d.allowed is False
        assert d.reason_code == "no_hitl_callback_bugbounty"

    # -- CTF mode: permissive -----------------------------------------------

    @pytest.mark.asyncio
    async def test_post_ctf_allowed_without_callback(self, safeguard_ctf):
        """CTF mode with no callback should allow POST."""
        d = await safeguard_ctf.evaluate("POST", "http://example.com/api/data")
        assert d.allowed is True

    @pytest.mark.asyncio
    async def test_post_ctf_destructive_payload_allowed(self, safeguard_ctf):
        """Destructive payload in CTF mode should be allowed."""
        d = await safeguard_ctf.evaluate("POST", "http://example.com/api/data",
                                          payload="1'; DELETE FROM users--")
        assert d.allowed is True

    # -- Destructive SQL payload blocked in bugbounty -----------------------

    @pytest.mark.asyncio
    async def test_destructive_sql_blocked_in_bugbounty(self, safeguard_bugbounty, mock_hitl):
        """Destructive SQL payload blocked even if endpoint is approved."""
        mock_hitl.return_value = True
        d = await safeguard_bugbounty.evaluate(
            "POST", "http://example.com/api/data",
            payload="1'; DROP TABLE users--",
        )
        assert d.allowed is False
        assert d.reason_code == "destructive_sql_payload_blocked"

    @pytest.mark.asyncio
    async def test_safe_sqli_payload_with_approved_endpoint(self, safeguard_bugbounty, mock_hitl):
        """Safe SQLi probe payload + approved endpoint = allowed."""
        mock_hitl.return_value = True
        d = await safeguard_bugbounty.evaluate(
            "POST", "http://example.com/api/data",
            payload="1' OR 1=1--",
        )
        assert d.allowed is True

    # -- Fail-closed on safeguard evaluation exception -----------------------

    @pytest.mark.asyncio
    async def test_safeguard_exception_fail_closed_in_bugbounty(self):
        """Safeguard exceptions must fail closed in bugbounty mode."""
        # Create a RequestGuard that raises on check()
        bad_guard = MagicMock()
        bad_guard.check = AsyncMock(side_effect=RuntimeError("simulated failure"))

        svc = ExecutionSafeguardService(mode="bugbounty", request_guard=bad_guard)
        d = await svc.evaluate("POST", "http://example.com/api/data")
        assert d.allowed is False
        assert d.reason_code == "safeguard_hitl_exception"

    @pytest.mark.asyncio
    async def test_unhandled_evaluate_exception_fail_closed(self):
        """Unhandled exception in evaluate() must fail closed in bugbounty."""
        # Cause an exception inside evaluate by passing None url with a method
        # that triggers a code path. We'll mock the payload policy to raise.
        bad_policy = MagicMock()
        bad_policy.evaluate = MagicMock(side_effect=RuntimeError("payload check panic"))

        svc = ExecutionSafeguardService(
            mode="bugbounty",
            payload_policy=bad_policy,
        )
        d = await svc.evaluate("GET", "http://example.com/api/test", payload="test")
        assert d.allowed is False
        assert d.reason_code == "safeguard_evaluate_exception"

    # -- reason_code and matched_rules populated ----------------------------

    @pytest.mark.asyncio
    async def test_decision_has_reason_code(self, safeguard_bugbounty_no_hitl):
        d = await safeguard_bugbounty_no_hitl.evaluate("POST", "http://example.com/x")
        assert d.reason_code != ""
        assert isinstance(d.reason_code, str)

    @pytest.mark.asyncio
    async def test_destructive_payload_has_matched_rules(self, safeguard_bugbounty, mock_hitl):
        mock_hitl.return_value = True
        d = await safeguard_bugbounty.evaluate(
            "POST", "http://example.com/x",
            payload="1'; DELETE FROM users; DROP TABLE logs--",
        )
        assert len(d.matched_rules) >= 2
        assert "sql_delete_from" in d.matched_rules
        assert "sql_drop_table" in d.matched_rules


# ---------------------------------------------------------------------------
# Singleton factory tests
# ---------------------------------------------------------------------------

class TestSingletonFactory:
    def test_get_execution_safeguard_creates_singleton(self):
        reset_execution_safeguard()
        reset_request_guard()
        svc1 = get_execution_safeguard(mode="bugbounty")
        svc2 = get_execution_safeguard(mode="bugbounty")
        assert svc1 is svc2

    def test_mode_change_resets_singleton(self):
        reset_execution_safeguard()
        reset_request_guard()
        svc1 = get_execution_safeguard(mode="bugbounty")
        svc2 = get_execution_safeguard(mode="ctf")
        assert svc1 is not svc2
        assert svc2.mode == "ctf"

    def test_hitl_callback_update(self):
        reset_execution_safeguard()
        reset_request_guard()
        cb1 = AsyncMock(return_value=True)
        cb2 = AsyncMock(return_value=False)
        svc1 = get_execution_safeguard(mode="bugbounty", hitl_callback=cb1)
        svc2 = get_execution_safeguard(mode="bugbounty", hitl_callback=cb2)
        assert svc1 is svc2  # same mode, same singleton
        assert svc1._request_guard.hitl_callback is cb2


# ---------------------------------------------------------------------------
# SmartRequest integration tests
# ---------------------------------------------------------------------------

class TestSmartRequestIntegration:
    @pytest.mark.asyncio
    async def test_smart_request_uses_safeguard_path(self):
        """SmartRequest should call ExecutionSafeguardService when provided."""
        from src.core.infra.smart_request import SmartRequest

        # Mock network client
        mock_client = AsyncMock()
        resp = MagicMock(status=200, headers={}, body="OK")
        mock_client.request.return_value = resp

        # Create safeguard with HITL that approves
        guard = RequestGuard(mode="bugbounty", hitl_callback=AsyncMock(return_value=True))
        svc = ExecutionSafeguardService(mode="bugbounty", request_guard=guard)

        smart = SmartRequest(mock_client, execution_safeguard=svc)
        with patch.object(asyncio, "sleep", AsyncMock()):
            result = await smart.request("GET", "http://example.com")
        assert result["status"] == 200

    @pytest.mark.asyncio
    async def test_smart_request_blocks_destructive_payload(self):
        """SmartRequest should block when safeguard says no."""
        from src.core.infra.smart_request import SmartRequest

        mock_client = AsyncMock()
        guard = RequestGuard(mode="bugbounty", hitl_callback=AsyncMock(return_value=True))
        svc = ExecutionSafeguardService(mode="bugbounty", request_guard=guard)

        smart = SmartRequest(mock_client, execution_safeguard=svc)
        result = await smart.request(
            "POST", "http://example.com/api",
            data="1'; DELETE FROM users--",
        )
        assert result["status"] == 0
        assert "Blocked by ExecutionSafeguard" in result["error"]

    @pytest.mark.asyncio
    async def test_smart_request_legacy_guard_fallback(self):
        """SmartRequest should fall back to request_guard when no safeguard."""
        from src.core.infra.smart_request import SmartRequest

        mock_client = AsyncMock()
        resp = MagicMock(status=200, headers={}, body="OK")
        mock_client.request.return_value = resp

        guard = RequestGuard(mode="bugbounty", hitl_callback=AsyncMock(return_value=True))
        smart = SmartRequest(mock_client, request_guard=guard)
        with patch.object(asyncio, "sleep", AsyncMock()):
            result = await smart.request("GET", "http://example.com")
        assert result["status"] == 200


# ---------------------------------------------------------------------------
# SmartSQLiHunter integration test
# ---------------------------------------------------------------------------

class TestSmartSQLiHunterIntegration:
    def test_smart_sqli_default_mode_is_bugbounty(self):
        """SmartSQLiHunter must default to bugbounty mode."""
        reset_execution_safeguard()
        reset_request_guard()

        # get_execution_safeguard is imported inside __init__, so patch at source
        with patch('src.core.agents.swarm.injection.smart_sqli.LLMClient', autospec=True), \
             patch('src.core.agents.swarm.injection.smart_sqli.AsyncNetworkClient', autospec=True), \
             patch('src.core.security.execution_safeguard.get_execution_safeguard') as mock_get_safeguard, \
             patch('src.core.agents.swarm.injection.smart_sqli.SmartRequest') as mock_smart_req, \
             patch('src.core.agents.swarm.injection.smart_sqli.Specialist.__init__', return_value=None), \
             patch('src.core.agents.swarm.injection.smart_sqli.ThoughtLoop.__init__', return_value=None):

            from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter

            mock_safeguard = MagicMock()
            mock_get_safeguard.return_value = mock_safeguard

            SmartSQLiHunter()

            # Should have called get_execution_safeguard with mode="bugbounty"
            mock_get_safeguard.assert_called_once_with(mode="bugbounty")

            # SmartRequest should be created with execution_safeguard
            call_kwargs = mock_smart_req.call_args[1]
            assert 'execution_safeguard' in call_kwargs
            assert call_kwargs['execution_safeguard'] is mock_safeguard

    def test_smart_sqli_ctf_mode_override(self):
        """SmartSQLiHunter should honour explicit ctf mode from config."""
        reset_execution_safeguard()
        reset_request_guard()

        with patch('src.core.agents.swarm.injection.smart_sqli.LLMClient', autospec=True), \
             patch('src.core.agents.swarm.injection.smart_sqli.AsyncNetworkClient', autospec=True), \
             patch('src.core.security.execution_safeguard.get_execution_safeguard') as mock_get_safeguard, \
             patch('src.core.agents.swarm.injection.smart_sqli.SmartRequest'), \
             patch('src.core.agents.swarm.injection.smart_sqli.Specialist.__init__', return_value=None), \
             patch('src.core.agents.swarm.injection.smart_sqli.ThoughtLoop.__init__', return_value=None):

            from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter

            mock_safeguard = MagicMock()
            mock_get_safeguard.return_value = mock_safeguard

            SmartSQLiHunter(config={"mode": "ctf"})
            mock_get_safeguard.assert_called_once_with(mode="ctf")


# ---------------------------------------------------------------------------
# Regression: mixed-mode singleton flip
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mode_change_does_not_flip_previous_safeguard_guard():
    """Bug Bounty safeguard must stay fail-closed after a later CTF init.

    get_execution_safeguard(mode='bugbounty') creates a safeguard whose
    internal RequestGuard has mode='bugbounty'.  A later call with
    mode='ctf' must NOT mutate that guard's mode on previously-created
    safeguard instances (the old safeguard keeps its own RequestGuard
    reference).  Regression for GH finding: mixed bugbounty/ctf
    initializations silently disabling HITL.
    """
    # 1. Initialise in Bug Bounty mode with a denying callback
    async def deny_callback(task_info: dict) -> bool:
        return False

    bb_safeguard = get_execution_safeguard(mode="bugbounty", hitl_callback=deny_callback)
    bb_guard = bb_safeguard.request_guard
    assert bb_guard is not None
    assert bb_guard.mode == "bugbounty"

    # 2. POST should be denied in Bug Bounty (fail-closed)
    decision_before = await bb_safeguard.evaluate(
        method="POST", url="http://example.com/api/users", source_agent="test",
    )
    assert not decision_before.allowed, (
        f"POST should be denied before CTF init, got allowed={decision_before.allowed} "
        f"reason={decision_before.reason_code}"
    )

    # 3. Now initialise a CTF-mode safeguard
    ctf_safeguard = get_execution_safeguard(mode="ctf")
    assert ctf_safeguard.mode == "ctf"

    # 4. The original Bug Bounty guard must still be in Bug Bounty mode
    assert bb_guard.mode == "bugbounty", (
        f"Bug Bounty RequestGuard mode was flipped to {bb_guard.mode}! "
        "CTF init should not mutate the previous guard's mode."
    )

    # 5. POST through the ORIGINAL Bug Bounty safeguard must still be denied
    decision_after = await bb_safeguard.evaluate(
        method="POST", url="http://example.com/api/users", source_agent="test",
    )
    assert not decision_after.allowed, (
        f"POST should STILL be denied after CTF init, got allowed={decision_after.allowed} "
        f"reason={decision_after.reason_code} — fail-closed guarantee broken!"
    )

    # 6. The CTF safeguard should allow POST (permissive mode)
    decision_ctf = await ctf_safeguard.evaluate(
        method="POST", url="http://example.com/api/items", source_agent="test",
    )
    assert decision_ctf.allowed, (
        f"POST should be allowed in CTF mode, got allowed={decision_ctf.allowed} "
        f"reason={decision_ctf.reason_code}"
    )
