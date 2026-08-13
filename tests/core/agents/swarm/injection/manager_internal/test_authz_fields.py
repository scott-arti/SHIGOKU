"""
SGK-2026-0448 lever 2 tests: mechanical impact/reproduction_steps for authz
findings (helper unit tests + idor.py wiring test).

Note on the manager.py site-2 guard (`object_ab_idor_probe`): both probes
there are authenticated (object A vs object B), yet `build_authz_differential`
labels any successful "test" response `unauth_success`, so signals like
["auth_success", "unauth_success", "body_length_close",
 "object_ab_param_mutation"] WOULD satisfy `authz_signals_satisfied` — the
helper cannot distinguish that scenario from a real unauth differential. The
guard is therefore the ABSENCE of the call at that site (see manager.py), not
the predicate. This file deliberately has no test wiring site 2.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.core.agents.swarm.injection.manager_internal.authz_fields import (
    authz_signals_satisfied,
    build_authz_impact_and_reproduction_steps,
)
from src.core.agents.swarm.logic.idor import IdorHunterSpecialist
from src.core.agents.swarm.logic.response_comparator import ComparisonResult
from src.core.models.finding import Severity


class MockResponse:
    def __init__(self, status, text):
        self.status = status
        self.text = text
        self.headers = {}

    def __await__(self):
        async def _async_wrapper():
            return self
        return _async_wrapper().__await__()


def _result(*, vulnerable=True, signals):
    return ComparisonResult(
        is_vulnerable=vulnerable,
        confidence=0.9,
        signals=list(signals),
        severity_hint=Severity.HIGH,
        report="=== IDOR Diagnostic Report ===",
    )


def test_helper_both_ok_branch_fills_impact_and_steps() -> None:
    # auth_success AND unauth_success -> "unauthenticated access is allowed"
    # branch, with the two statuses labeled in their real roles.
    impact, steps = build_authz_impact_and_reproduction_steps(
        scenario="unauthenticated_api_access",
        url="https://example.com/api/users/1",
        method="GET",
        authenticated_status=200,
        unauthenticated_status=200,
        signals=["auth_success", "unauth_success", "auth_json_like"],
    )

    assert impact is not None
    assert steps is not None
    assert len(steps) == 3
    assert "https://example.com/api/users/1" in impact
    assert "allowed" in impact
    assert "both requests succeeded" in impact
    # Statuses appear in their labeled roles (order-aware).
    assert "authenticated GET" in impact
    assert "without authentication headers returns status 200" in impact
    assert impact.index("authenticated GET") < impact.index("without authentication headers")
    # GET-only language in every step; no product tokens / extra claims.
    for step in steps:
        assert "POST" not in step
        assert "PUT" not in step
        assert "DELETE" not in step
    assert "juice" not in impact.lower()
    assert "juice" not in " ".join(steps).lower()


def test_helper_status_improved_with_auth_branch_fills() -> None:
    # Only status_improved_with_auth -> "requires authentication" branch.
    impact, steps = build_authz_impact_and_reproduction_steps(
        scenario="authenticated_overposting_requires_auth_context",
        url="https://example.com/api/items",
        method="POST",
        authenticated_status=200,
        unauthenticated_status=401,
        signals=["status_improved_with_auth"],
    )

    assert impact is not None
    assert len(steps) == 3
    assert "https://example.com/api/items" in impact
    assert "requires authentication" in impact
    assert "POST" in impact
    assert "401" in impact
    assert "200" in impact
    # The unauthenticated request is described as denied, not allowed.
    assert "allowed" not in impact
    # The two request steps carry the method; the compare step is method-free.
    assert "POST" in steps[0]
    assert "POST" in steps[1]


def test_helper_fail_closed_when_signals_insufficient() -> None:
    assert build_authz_impact_and_reproduction_steps(
        scenario="unauthenticated_api_access",
        url="https://example.com/api/users/1",
        method="GET",
        authenticated_status=200,
        unauthenticated_status=200,
        signals=["auth_success"],
    ) == (None, None)
    assert build_authz_impact_and_reproduction_steps(
        scenario="unauthenticated_api_access",
        url="https://example.com/api/users/1",
        method="GET",
        authenticated_status=200,
        unauthenticated_status=200,
        signals=[],
    ) == (None, None)
    assert build_authz_impact_and_reproduction_steps(
        scenario="unauthenticated_api_access",
        url="https://example.com/api/users/1",
        method="GET",
        authenticated_status=200,
        unauthenticated_status=200,
        signals=None,
    ) == (None, None)


def test_authz_signals_satisfied_predicate() -> None:
    assert authz_signals_satisfied(["auth_success", "unauth_success"]) is True
    assert authz_signals_satisfied(["status_improved_with_auth"]) is True
    assert authz_signals_satisfied(["auth_success"]) is False
    assert authz_signals_satisfied([]) is False
    assert authz_signals_satisfied(None) is False


def test_site2_guard_predicate_cannot_distinguish_object_ab() -> None:
    # manager.py site 2 (`object_ab_idor_probe`) is NOT wired because both
    # probes are authenticated; the signal set below WOULD satisfy the
    # predicate, which is exactly why the guard must be the absence of the
    # call at that site rather than the helper itself.
    assert authz_signals_satisfied(
        ["auth_success", "unauth_success", "body_length_close", "object_ab_param_mutation"]
    ) is True


@pytest.mark.asyncio
async def test_run_unauth_check_wires_impact_when_signals_satisfied() -> None:
    """idor.py wiring: authz_differential signals satisfy the marker
    requirement -> the Finding carries a mechanical impact + 3 steps.

    The network client is mocked (baseline 200 / unauth 200, both json-like).
    ResponseComparator.compare is stubbed because the real comparator emits
    diagnostic strings (e.g. "[+0.15] status_match: ..."), never the
    auth_success/unauth_success tokens the payout-grade marker requires.
    """
    agent = IdorHunterSpecialist({"mode": "ctf"})
    agent._workspace_instance = MagicMock()
    mock_client = MagicMock()
    body = '{"id": 1, "name": "Alice"}'
    mock_client.request.side_effect = [MockResponse(200, body), MockResponse(200, body)]

    with patch("src.core.agents.swarm.logic.idor.ResponseComparator") as mock_cmp_cls:
        mock_cmp_cls.return_value.compare = AsyncMock(
            return_value=_result(signals=["auth_success", "unauth_success", "auth_json_like"])
        )
        finding = await agent._run_unauth_check(
            mock_client,
            "https://example.com/api/users/1",
            "GET",
            {"Authorization": "Bearer x"},
            {},
            None,
            False,
        )

    assert finding is not None
    assert finding.impact
    assert len(finding.reproduction_steps) == 3
    assert "https://example.com/api/users/1" in finding.impact


@pytest.mark.asyncio
async def test_run_unauth_check_fail_closed_when_unauth_signal_absent() -> None:
    """idor.py wiring: test response 401 with only auth_success (no
    unauth_success) -> the marker requirement is not met -> impact stays
    empty (fail-closed, bar unchanged)."""
    agent = IdorHunterSpecialist({"mode": "ctf"})
    agent._workspace_instance = MagicMock()
    mock_client = MagicMock()
    body = '{"id": 1, "name": "Alice"}'
    mock_client.request.side_effect = [
        MockResponse(200, body),
        MockResponse(401, '{"error": "unauthorized"}'),
    ]

    with patch("src.core.agents.swarm.logic.idor.ResponseComparator") as mock_cmp_cls:
        mock_cmp_cls.return_value.compare = AsyncMock(
            return_value=_result(signals=["auth_success"])
        )
        finding = await agent._run_unauth_check(
            mock_client,
            "https://example.com/api/users/1",
            "GET",
            {"Authorization": "Bearer x"},
            {},
            None,
            False,
        )

    assert finding is not None
    assert finding.impact == ""
    assert finding.reproduction_steps == []


def test_authz_fields_module_importable() -> None:
    """Manager.py wiring uses the same helper; the helper module itself must
    stay importable from the manager_internal package (manager sites are
    covered by the same helper + the sealed-run re-verification)."""
    from src.core.agents.swarm.injection.manager_internal import authz_fields

    assert callable(authz_fields.build_authz_impact_and_reproduction_steps)
