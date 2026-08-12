"""SGK-2026-0447 B4: sealed-run GET-only enforcement -> needs_human mapping.

Verifies that when the network boundary blocks a non-GET mass-assignment
probe (``ReadonlyEnforcedError``), the injection manager:

- maps it to a needs_human finding (``additional_info["hybrid_final_state"]
  == "needs_human"``, ``readonly_enforced: True``),
- puts a ``NEEDS_HUMAN`` record into the candidate ledger (judge-free
  direct put; never confirmed, thresholds unchanged),
- emits exactly one blocked probe (no duplicate findings).

Transport (``request_client``) is mocked; the GET/HEAD/OPTIONS reads succeed
while POST/PUT/PATCH raise ``ReadonlyEnforcedError`` exactly like the real
``AsyncNetworkClient`` boundary.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.infra.network_client import ReadonlyEnforcedError
from src.core.models.finding import VulnType
from src.core.validation.candidate_ledger import CandidateLedger
from src.core.validation.candidate_lifecycle import LifecycleState

API_URL = "http://target.test/api/users"


class _FakeReadonlyClient:
    """Transport mirroring the sealed-run boundary: GET/HEAD/OPTIONS succeed,
    state-changing methods raise ReadonlyEnforcedError."""

    def __init__(self) -> None:
        self.calls: list = []

    async def request(self, method: str, url: str, **kwargs):
        self.calls.append((method, url))
        if str(method or "").upper() in ("POST", "PUT", "PATCH"):
            raise ReadonlyEnforcedError(
                f"Request blocked by sealed-run GET-only enforcement: {method}"
            )
        return SimpleNamespace(
            status=200,
            body='{"users": [{"id": 1, "role": "user"}]}',
            headers={
                "Content-Type": "application/json",
                "Allow": "GET,POST,OPTIONS",
            },
        )


def _make_manager(ledger):
    """A real InjectionManagerAgent with an injected candidate ledger and a
    minimal current_context (findings list append target)."""
    with patch("src.core.infra.proxy_manager.get_proxy_manager", return_value=None):
        manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {
        "target": API_URL,
        "params": {},
        "auth_headers": {"Authorization": "Bearer token"},
        "findings": [],
        "url_results": [],
        "scan_profile": "bbpt",
    }
    manager._t3_candidate_ledger = ledger
    return manager


class TestMassAssignmentReadonlyEnforced:
    @pytest.mark.asyncio
    async def test_blocked_probe_maps_to_needs_human_and_ledger(self, tmp_path):
        """(d) Blocked mass-assignment probe -> needs_human finding +
        NEEDS_HUMAN ledger record; exactly one blocked non-GET send."""
        ledger = CandidateLedger.open(str(tmp_path / "candidate_ledger.json"))
        manager = _make_manager(ledger)
        client = _FakeReadonlyClient()
        manager._resolve_request_client = MagicMock(return_value=client)

        await manager._run_api_minimal_check(url=API_URL, base_params={})

        # needs_human finding was emitted (readonly_enforced marker).
        readonly_findings = [
            f
            for f in manager.current_context["findings"]
            if f.additional_info.get("readonly_enforced") is True
        ]
        assert len(readonly_findings) == 1
        finding = readonly_findings[0]
        assert finding.additional_info["hybrid_final_state"] == "needs_human"
        assert finding.vuln_type == VulnType.MASS_ASSIGNMENT
        assert finding.evidence.response_status == 0
        assert finding.evidence.response_body == "blocked: readonly_get_only_enforced"

        # Ledger got a NEEDS_HUMAN record (reason stable code).
        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.NEEDS_HUMAN
        assert record.reason == "readonly_get_only_enforced"

        # Exactly one blocked non-GET send: the first probe.  Rechecks never
        # fire after the block (probe_status=0 skips them), so no duplicates.
        non_get_calls = [
            (m, u) for (m, u) in client.calls if str(m or "").upper() in ("POST", "PUT", "PATCH")
        ]
        assert len(non_get_calls) == 1
        assert non_get_calls[0][0] == "POST"

    @pytest.mark.asyncio
    async def test_run_survives_ledger_write_failure(self, tmp_path):
        """A failing ledger put must not break the run (persistence boundary
        is best-effort; the finding itself is still emitted)."""
        broken_ledger = MagicMock()
        broken_ledger.put.side_effect = RuntimeError("disk full (test)")
        manager = _make_manager(broken_ledger)
        client = _FakeReadonlyClient()
        manager._resolve_request_client = MagicMock(return_value=client)

        await manager._run_api_minimal_check(url=API_URL, base_params={})

        readonly_findings = [
            f
            for f in manager.current_context["findings"]
            if f.additional_info.get("readonly_enforced") is True
        ]
        assert len(readonly_findings) == 1
        assert readonly_findings[0].additional_info["hybrid_final_state"] == "needs_human"
