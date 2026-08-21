"""
SGK-2026-0445 T3 — hybrid judge + lifecycle wiring on the Phase-2 merge gate.

Proves (additive, OFF by default):
- OFF: the merge gate behaves exactly as before (only the 0441 F4/F5
  payout_grade emits; no poc_judge construction, no reproduction checker,
  no candidate ledger open, no ``hybrid_final_state`` mark).
- ON (FakePoCJudge / FakeReproductionChecker injected):
  * CONFIRMED (3-condition AND via mocks) -> ledger record confirmed,
    F5 hybrid_confirmed emit, additional_info hybrid_final_state=confirmed,
    run-end ledger save.
  * INCONCLUSIVE -> F5 hybrid_parked emit + ledger inconclusive_parked.
  * NEEDS_HUMAN -> F5 hybrid_needs_human emit + ledger needs_human.
  * JudgeBudgetExhausted / PoCJudge ValueError -> ai_judge=None re-run ->
    needs_more (never confirmed, fail-closed).
  * already terminal/parked in the ledger -> judgement skipped (zero judge
    calls for that finding).
- REASON_CODES additions pass the strict vocabulary validation, and the
  ledger path reuses the ProjectManager projects-base-dir resolution.

All fixtures are product-independent (target.example style URLs).
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.agents.swarm.base_manager import BaseManagerAgent
from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.engine.finding_funnel_trace import FindingFunnelRecorder
from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.validation import (
    AiJudgement,
    CandidateLedger,
    CandidateLifecycleManager,
    CandidateRecord,
    JudgeBudgetExhausted,
    LifecycleState,
    ReproductionOutcome,
)

API_URL = "http://target.example/vulnerabilities/api/v2/user/"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class _FakePoCJudge:
    """Scripted poc_judge stand-in (records the findings it judged)."""

    def __init__(self, outcome: str = "positive"):
        self.outcome = outcome
        self.calls = 0
        self.called_finding_ids: list = []

    def judge(self, finding):
        self.calls += 1
        self.called_finding_ids.append(str(getattr(finding, "id", "") or ""))
        if self.outcome == "exhausted":
            raise JudgeBudgetExhausted("poc_judge budget exhausted (test)")
        if self.outcome == "bad_json":
            raise ValueError("PoCJudge: LLM response is not valid JSON")
        if self.outcome == "inconclusive":
            return AiJudgement(
                payout_grade=False,
                is_real=True,
                has_actual_impact=False,
                counter_evidence=False,
                needs_human=False,
                reason_masked="ai_no_prize_grade (test)",
            )
        if self.outcome == "needs_human":
            return AiJudgement(
                payout_grade=True,
                is_real=True,
                has_actual_impact=True,
                counter_evidence=False,
                needs_human=True,
                reason_masked="ai_needs_human (test)",
            )
        return AiJudgement(
            payout_grade=True,
            is_real=True,
            has_actual_impact=True,
            counter_evidence=False,
            needs_human=False,
            reason_masked="hybrid_confirmed (test)",
        )


class _FakeReproductionChecker:
    def __init__(self, status: str = "matched"):
        self.status = status
        self.calls = 0

    def check(self, finding):
        self.calls += 1
        if self.status == "matched":
            return ReproductionOutcome("matched", "reproduction_marker_matched:xss")
        if self.status == "mismatched":
            return ReproductionOutcome("mismatched", "reproduction_marker_mismatch")
        return ReproductionOutcome("not_run", "reproduction_pending")


class _ScriptedPoCJudge:
    """judge 呼び出し順に outcome を返す（SGK-2026-0452 再試行シーケンス検証用）。

    outcomes は呼び出し順のリスト: "positive" | "reject" | "bad_json"。
    末尾の outcome が残りの呼び出しに繰り返し適用される。
    """

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0
        self.called_finding_ids: list = []

    def judge(self, finding):
        outcome = self.outcomes[min(self.calls, len(self.outcomes) - 1)]
        self.calls += 1
        self.called_finding_ids.append(str(getattr(finding, "id", "") or ""))
        if outcome == "bad_json":
            raise ValueError("PoCJudge: LLM response is not valid JSON")
        if outcome == "reject":
            return AiJudgement(
                payout_grade=False,
                is_real=True,
                has_actual_impact=False,
                counter_evidence=False,
                needs_human=False,
                reason_masked="ai_no_prize_grade (test)",
            )
        return AiJudgement(
            payout_grade=True,
            is_real=True,
            has_actual_impact=True,
            counter_evidence=False,
            needs_human=False,
            reason_masked="hybrid_confirmed (test)",
        )


def _payout_finding(title: str = "Reflected XSS in search") -> Finding:
    """A payout-grade XSS finding (mechanical floor passes)."""
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title=title,
        description="d",
        target_url=API_URL,
        evidence=Evidence(
            request_method="GET",
            request_url=f"{API_URL}?q=1",
            response_status=200,
            response_body="<script>alert(1)</script>",
        ),
        impact="Reflected XSS in the search result page",
        reproduction_steps=[f"GET {API_URL}?q=1"],
        additional_info={},
    )


def _plain_finding(title: str = "Plain candidate") -> Finding:
    """A non-payout-grade finding (no evidence -> mechanical floor fails
    -> verdict stays NEEDS_MORE)."""
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title=title,
        description="d",
        target_url=API_URL,
        additional_info={},
    )


def _seed_record(finding: Finding, *, state: LifecycleState = LifecycleState.NEEDS_MORE) -> CandidateRecord:
    """A ledger record for the finding (T2 first-visit contract: a new
    record always starts needs_more; the CONFIRMED/INCONCLUSIVE/NEEDS_HUMAN
    transitions apply to an existing needs_more record)."""
    return CandidateRecord(
        finding_id=finding.id,
        state=state,
        reason="seeded",
        vuln_type="xss",
        title=finding.title,
        target_url_masked="",
        evidence_summary={},
        first_seen="2026-08-12T00:00:00+00:00",
        last_investigated="2026-08-12T00:00:00+00:00",
        budget_used=1,
        resurrection_count=0,
        promise_score=0.33,
    )


def _api_task(*, phase1_early_return_on_findings: bool = False) -> SimpleNamespace:
    """A dispatch-ready injection task. ``phase1_early_return_on_findings``
    True -> the dispatch returns at the early-return branch (Phase 2 never
    runs); False -> the Phase-2 merge gate is reached with the patched
    super().dispatch."""
    params = {
        "target": API_URL,
        "targets": [API_URL],
        "category": "api_data",
        "selection_origin": "master_conductor.recon.api_data",
        "scan_profile": "bbpt",
        "phase1_early_return_on_findings": phase1_early_return_on_findings,
        "manager_timeout_seconds": 30,
        "per_url_timeout_seconds": 10,
        "phase1_timeout_retries": 0,
        "auth_headers": {"Authorization": "Bearer token"},
        "_context": {},
        "cookies": "",
    }
    return SimpleNamespace(
        id="t3-hybrid-dispatch-1",
        name="T3 hybrid dispatch",
        target=API_URL,
        agent_type="InjectionManagerAgent",
        action="scan",
        params=params,
    )


def _fake_phase1_finding_producer(manager: InjectionManagerAgent, finding: Finding):
    """A ``_process_single_url`` stand-in that reports exactly one Phase-1
    finding (appended to the manager's current_context, as the real
    specialists do). Transport/Phase-2 machinery stays mocked."""

    async def _fake_process_single_url(
        url, vuln_type, base_params, quick_mode=False, trace_context=None
    ):
        manager.current_context["findings"].append(finding)
        return {
            "findings_count": 1,
            "vuln_type": vuln_type,
            "tested_params": [],
            "probe_sent": True,
            "probe_skipped_reason": "",
            "probe_request_raw": "",
            "probe_response_raw": "",
            "reflection_observed": False,
            "xss_evidence": "",
            "blind_correlation": {},
            "unknown_profile": {},
            "comparison_checks": [],
            "auth_context_matrix": {},
            "object_ab_comparison": {},
            "schema_candidate_params": [],
            "single_request_validation": True,
            "detection_mode": "phase1",
            "delivery_state": "",
            "reason_code": "",
        }

    return _fake_process_single_url


def _install_fake_phase1(manager: InjectionManagerAgent, finding: Finding) -> None:
    """Wire the fake Phase-1 producer + transport mock into the manager."""
    manager._process_single_url = _fake_phase1_finding_producer(manager, finding)
    if manager.network_client is not None:
        # SGK-2026-0452 (承認E): checker 構築は _resolve_request_client() を
        # 使うため、network_client が設定済みならそれを返す（replay send が
        # 実 client で試行される）。
        manager._resolve_request_client = MagicMock(return_value=manager.network_client)
    else:
        manager._resolve_request_client = MagicMock(return_value=_auto_reverified_client())


def _auto_reverified_client() -> MagicMock:
    """Transport sequence reproducing the existing api-probe phase-1 path
    (mirrors tests/unit/engine/test_finding_funnel_swarm_hooks.py)."""
    request_client = MagicMock()
    request_client.request = AsyncMock(
        side_effect=[
            SimpleNamespace(status=200, body='{"user":"demo"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=401, body='{"error":"unauthorized"}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=204, body="", headers={"Allow": "GET,POST,PATCH,OPTIONS"}),
            SimpleNamespace(status=200, body='{"ok":true}', headers={"Content-Type": "application/json"}),
            SimpleNamespace(status=200, body='{"ok":true}', headers={"Content-Type": "application/json"}),
        ]
    )
    return request_client


async def _run_dispatch(manager: InjectionManagerAgent, *, phase2_findings: list):
    """Real InjectionManager dispatch; transport + Phase-2 super().dispatch
    mocked only. Returns the merged SwarmResult."""
    request_client = _auto_reverified_client()
    manager._resolve_request_client = MagicMock(return_value=request_client)
    with patch(
        "src.core.agents.swarm.injection.manager.resolve_risk_force_allowlist",
        return_value=set(),
    ), patch.object(
        BaseManagerAgent,
        "dispatch",
        new=AsyncMock(
            return_value=MagicMock(
                status="success", findings=phase2_findings, execution_log=[]
            )
        ),
    ):
        return await manager.dispatch(_api_task())


def _spy_funnel_events(monkeypatch) -> list:
    """Record every ``_funnel_finding_event`` call (module-level spy)."""
    import src.core.agents.swarm.injection.manager as mgr

    calls: list = []

    def _spy(finding, stage, outcome, reason_code=None, block_reasons=None):
        calls.append(
            {
                "finding_id": str(getattr(finding, "id", "") or ""),
                "stage": stage,
                "outcome": outcome,
                "reason_code": reason_code,
            }
        )

    monkeypatch.setattr(mgr, "_funnel_finding_event", _spy)
    return calls


def _hybrid_emits(calls: list, finding_id: str) -> list:
    return [
        c for c in calls
        if c["finding_id"] == finding_id
        and c["stage"] == "F5"
        and c["reason_code"] and c["reason_code"].startswith("hybrid_")
    ]


# ---------------------------------------------------------------------------
# OFF: byte-identical to the 0441 gate alone
# ---------------------------------------------------------------------------


class TestT3Off:
    async def test_off_runs_only_the_existing_gate(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SHIGOKU_WORKSPACE_PROJECTS_DIR", str(tmp_path))
        calls = _spy_funnel_events(monkeypatch)
        manager = InjectionManagerAgent(config={"model": "test-model"})
        assert manager._t3_hybrid_active() is False

        # The wiring must never construct judge/checker or open a ledger.
        # The validation symbols are function-lazy (circular-import fix):
        # the manager module must not bind them at module level, and the
        # classes defined in src.core.validation must never be instantiated.
        import src.core.agents.swarm.injection.manager as mgr

        assert not hasattr(mgr, "PoCJudge")
        assert not hasattr(mgr, "SealedReproductionChecker")
        manager._open_candidate_ledger = MagicMock()
        with patch(
            "src.core.validation.finding_validator.PoCJudge"
        ) as judge_cls, patch(
            "src.core.validation.sealed_reproduction_checker.SealedReproductionChecker"
        ) as checker_cls:
            payout = _payout_finding()
            result = await _run_dispatch(manager, phase2_findings=[payout])

        assert result.status == "success"
        judge_cls.assert_not_called()
        checker_cls.assert_not_called()
        manager._open_candidate_ledger.assert_not_called()

        # Only the 0441 emits: F5 payout_grade_poc for the payout-grade
        # finding; no hybrid reason codes, no hybrid_final_state mark.
        f5 = [
            c for c in calls
            if c["stage"] == "F5" and c["finding_id"] == payout.id
        ]
        assert f5, "payout-grade finding must keep the existing F5 emit"
        assert all(c["reason_code"] == "payout_grade_poc" for c in f5)
        assert not _hybrid_emits(calls, payout.id)
        assert "hybrid_final_state" not in payout.additional_info
        assert payout.additional_info.get("payout_grade") is True
        assert not list(tmp_path.rglob("candidate_ledger.json"))


# ---------------------------------------------------------------------------
# ON: verdict -> lifecycle -> funnel emit -> ledger save
# ---------------------------------------------------------------------------


class TestT3On:
    def _manager(self, *, judge, checker=None, ledger=None, hybrid=True):
        return InjectionManagerAgent(
            config={"model": "test-model"},
            hybrid_enabled=hybrid,
            poc_judge=judge,
            reproduction_checker=checker,
            candidate_ledger=ledger,
        )

    async def test_confirmed_writes_ledger_and_emits_hybrid_confirmed(self, monkeypatch, tmp_path):
        calls = _spy_funnel_events(monkeypatch)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        ledger.put(_seed_record(finding))  # second visit -> CONFIRMED applies
        judge = _FakePoCJudge("positive")
        checker = _FakeReproductionChecker("matched")
        manager = self._manager(judge=judge, checker=checker, ledger=ledger)

        await _run_dispatch(manager, phase2_findings=[finding])

        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.CONFIRMED
        assert record.reason == "hybrid_confirmed"
        assert (tmp_path / "candidate_ledger.json").exists(), "run-end save"
        assert finding.id in judge.called_finding_ids
        assert checker.calls == 1
        hybrid = _hybrid_emits(calls, finding.id)
        assert any(c["reason_code"] == "hybrid_confirmed" for c in hybrid)
        assert finding.additional_info.get("hybrid_final_state") == "confirmed"
        # SGK-2026-0452 (計装・承認済み): ledger confirmed に到達した finding
        # のみ F6 を emit する（funnel レイヤー・バー無関係）。
        f6 = [c for c in calls if c["finding_id"] == finding.id and c["stage"] == "F6"]
        assert any(c["reason_code"] == "hybrid_confirmed" for c in f6)

    async def test_needs_more_never_emits_f6(self, monkeypatch, tmp_path):
        """needs_more（確定に至らない）finding には F6 を emit しない。"""
        calls = _spy_funnel_events(monkeypatch)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        judge = _FakePoCJudge("bad_json")  # -> ai=None -> pending (needs_more)
        manager = self._manager(judge=judge, checker=_FakeReproductionChecker("matched"), ledger=ledger)

        await _run_dispatch(manager, phase2_findings=[finding])

        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.NEEDS_MORE
        f6 = [c for c in calls if c["finding_id"] == finding.id and c["stage"] == "F6"]
        assert not f6, "needs_more must never emit F6"

    async def test_inconclusive_parks_and_emits_hybrid_parked(self, monkeypatch, tmp_path):
        calls = _spy_funnel_events(monkeypatch)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        ledger.put(_seed_record(finding))
        judge = _FakePoCJudge("inconclusive")
        manager = self._manager(judge=judge, checker=_FakeReproductionChecker("matched"), ledger=ledger)

        await _run_dispatch(manager, phase2_findings=[finding])

        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.INCONCLUSIVE_PARKED
        assert record.reason == "ai_no_prize_grade"
        assert any(
            c["reason_code"] == "hybrid_parked"
            for c in _hybrid_emits(calls, finding.id)
        )
        assert (
            finding.additional_info.get("hybrid_final_state")
            == "inconclusive_parked"
        )

    async def test_needs_human_emits_hybrid_needs_human(self, monkeypatch, tmp_path):
        calls = _spy_funnel_events(monkeypatch)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        ledger.put(_seed_record(finding))
        judge = _FakePoCJudge("needs_human")
        manager = self._manager(judge=judge, checker=_FakeReproductionChecker("matched"), ledger=ledger)

        await _run_dispatch(manager, phase2_findings=[finding])

        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.NEEDS_HUMAN
        assert any(
            c["reason_code"] == "hybrid_needs_human"
            for c in _hybrid_emits(calls, finding.id)
        )
        assert finding.additional_info.get("hybrid_final_state") == "needs_human"

    async def test_judge_budget_exhausted_maps_to_needs_more(self, monkeypatch, tmp_path):
        calls = _spy_funnel_events(monkeypatch)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        judge = _FakePoCJudge("exhausted")
        manager = self._manager(judge=judge, checker=_FakeReproductionChecker("matched"), ledger=ledger)

        await _run_dispatch(manager, phase2_findings=[finding])

        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.NEEDS_MORE  # never confirmed
        assert not _hybrid_emits(calls, finding.id)
        assert "hybrid_final_state" not in finding.additional_info
        # first attempt raised; the ai_judge=None re-run short-circuits
        assert judge.calls >= 1

    async def test_poc_judge_value_error_maps_to_needs_more(self, monkeypatch, tmp_path):
        calls = _spy_funnel_events(monkeypatch)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        judge = _FakePoCJudge("bad_json")
        manager = self._manager(judge=judge, checker=_FakeReproductionChecker("matched"), ledger=ledger)

        await _run_dispatch(manager, phase2_findings=[finding])

        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.NEEDS_MORE  # fail-closed
        assert not _hybrid_emits(calls, finding.id)
        assert "hybrid_final_state" not in finding.additional_info

    # --- SGK-2026-0452 (承認C・2026-08-16): judge の JSON パース失敗時のみ
    # 最大1回の再試行。正当な却下は再試行しない（gaming 禁止）。
    # 注: 再試行ロジックの単体検証は wiring レベルの直接呼び出しで行う
    # （full dispatch 経路は finding が複数 pass で再判定され judge 呼び出し
    # 回数が pass 数に依存するため、再試行セマンティクスの検証には不向き）。

    def _direct_verdict(self, *, judge, finding, ledger, state=None):
        if state is not None:
            ledger.put(_seed_record(finding, state=state))
        manager = self._manager(judge=judge, checker=_FakeReproductionChecker("matched"), ledger=ledger)
        changed = manager._t3_apply_hybrid_verdict(
            finding,
            judge=judge,
            checker=_FakeReproductionChecker("matched"),
            lifecycle=CandidateLifecycleManager(),
            ledger=ledger,
        )
        return changed, ledger.get(finding.id)

    def test_legitimate_rejection_never_retried(self, tmp_path):
        """正当な payout_grade=false（却下）では judge を再試行しない:
        judge.judge は 1 回だけ呼ばれ、INCONCLUSIVE_PARKED になる。"""
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        judge = _ScriptedPoCJudge(["reject"])
        changed, record = self._direct_verdict(
            judge=judge, finding=finding, ledger=ledger,
            state=LifecycleState.NEEDS_MORE,
        )
        assert judge.calls == 1  # 再試行なし
        assert changed is True
        assert record is not None
        assert record.state == LifecycleState.INCONCLUSIVE_PARKED

    def test_bad_json_retried_once_then_confirmed(self, tmp_path):
        """壊れた JSON → judge を 1 回だけ再試行し、2 回目が正当なら
        CONFIRMED に確定する。"""
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        judge = _ScriptedPoCJudge(["bad_json", "positive"])
        changed, record = self._direct_verdict(
            judge=judge, finding=finding, ledger=ledger,
            state=LifecycleState.NEEDS_MORE,
        )
        assert judge.calls == 2  # 1回失敗 + 1回再試行
        assert changed is True
        assert record is not None
        assert record.state == LifecycleState.CONFIRMED
        assert record.reason == "hybrid_confirmed"

    def test_bad_json_twice_fail_closed_pending(self, tmp_path):
        """壊れた JSON ×2 → 再試行も失敗 → ai=None → NEEDS_MORE
        （ai_judgement_pending）。fail-closed・確定を偽装しない。"""
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        judge = _ScriptedPoCJudge(["bad_json", "bad_json"])
        changed, record = self._direct_verdict(
            judge=judge, finding=finding, ledger=ledger,
        )
        assert judge.calls == 2  # 1回失敗 + 1回再試行（両方失敗）
        assert changed is True
        assert record is not None
        assert record.state == LifecycleState.NEEDS_MORE
        assert record.reason == "ai_judgement_pending"

    @pytest.mark.asyncio
    async def test_t3_pass_builds_checker_with_resolved_network_client(self, monkeypatch, tmp_path):
        """承認E (2026-08-16): T3 pass の checker 構築は
        network_client=self._resolve_request_client() を使う（B3/B4 で
        network_client=None → disabled_no_client → reproduction_pending と
        なった事象の再発防止）。AgentFactory 経由 dispatch では
        set_network_client が呼ばれないため、フォールバックが必須。"""
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        judge = _FakePoCJudge("positive")
        # checker を注入しない → _t3_run_hybrid_pass が自前構築する
        manager = self._manager(judge=judge, checker=None, ledger=ledger)

        captured = {}

        def spy_checker(**kwargs):
            captured.update(kwargs)
            return _FakeReproductionChecker("matched")

        # SealedReproductionChecker は manager 内で関数内 import されるため、
        # 正本モジュールの属性を patch する（関数内 import は実行時に
        # モジュール属性を参照する）。
        monkeypatch.setattr(
            "src.core.validation.sealed_reproduction_checker.SealedReproductionChecker",
            spy_checker,
        )
        await _run_dispatch(manager, phase2_findings=[finding])

        assert captured.get("network_client") is not None
        assert captured.get("scope_definition") is not None
        assert captured.get("time_budget_seconds") == 600

    def test_terminal_record_skips_judgement(self, tmp_path):
        """Already terminal/parked findings are not judged again (no blind
        retry; judge calls for that finding stay zero)."""
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        ledger.put(_seed_record(finding, state=LifecycleState.CONFIRMED))
        judge = _FakePoCJudge("positive")
        manager = self._manager(judge=judge, checker=_FakeReproductionChecker("matched"), ledger=ledger)

        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.CONFIRMED
        # Direct wiring-level call: the skip guard must return before any
        # judge call (the lifecycle contract: non-needs_more is a no-op).
        changed = manager._t3_apply_hybrid_verdict(
            finding,
            judge=judge,
            checker=_FakeReproductionChecker("matched"),
            lifecycle=CandidateLifecycleManager(),
            ledger=ledger,
        )
        assert changed is False
        assert judge.calls == 0
        after = ledger.get(finding.id)
        assert after is not None
        assert after.state == LifecycleState.CONFIRMED

    def test_parked_record_skips_judgement(self, tmp_path):
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        ledger.put(_seed_record(finding, state=LifecycleState.INCONCLUSIVE_PARKED))
        judge = _FakePoCJudge("positive")
        manager = self._manager(judge=judge, checker=_FakeReproductionChecker("matched"), ledger=ledger)

        changed = manager._t3_apply_hybrid_verdict(
            finding,
            judge=judge,
            checker=_FakeReproductionChecker("matched"),
            lifecycle=CandidateLifecycleManager(),
            ledger=ledger,
        )
        assert changed is False
        assert judge.calls == 0


# ---------------------------------------------------------------------------
# T6: budget-exhausted parking emits F5 from the RECORD state
# ---------------------------------------------------------------------------


class TestT6BudgetExhaustion:
    def test_budget_exhaustion_parks_and_emits_hybrid_parked(self, monkeypatch, tmp_path):
        """verdict=NEEDS_MORE but budget_used reaches max_visits -> the
        record becomes inconclusive_parked and F5 hybrid_parked fires
        (emit is record.state-based, not verdict.state-based — run5
        regression: b7aa7f57bce4 parked without any F5 emit)."""
        calls = _spy_funnel_events(monkeypatch)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _plain_finding()  # floor fails -> verdict NEEDS_MORE
        seed = _seed_record(finding)
        seed.budget_used = 2  # this visit -> 3 == max_visits (default 3)
        seed.promise_score = 0.33  # below human_promise_threshold
        ledger.put(seed)
        judge = _FakePoCJudge("positive")
        manager = InjectionManagerAgent(
            config={"model": "test-model"},
            hybrid_enabled=True,
            poc_judge=judge,
            candidate_ledger=ledger,
        )

        changed = manager._t3_apply_hybrid_verdict(
            finding,
            judge=judge,
            checker=_FakeReproductionChecker("matched"),
            lifecycle=CandidateLifecycleManager(),
            ledger=ledger,
        )

        assert changed is True
        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.INCONCLUSIVE_PARKED
        assert record.reason == "budget_exhausted"
        assert any(
            c["reason_code"] == "hybrid_parked"
            for c in _hybrid_emits(calls, finding.id)
        )
        assert finding.additional_info.get("hybrid_final_state") == "inconclusive_parked"

    def test_needs_more_still_no_f5_emit(self, monkeypatch, tmp_path):
        """A continuing needs_more record (budget not exhausted) emits NO
        F5 (unchanged behavior)."""
        calls = _spy_funnel_events(monkeypatch)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _plain_finding()
        seed = _seed_record(finding)
        seed.budget_used = 1  # this visit -> 2 < max_visits
        ledger.put(seed)
        judge = _FakePoCJudge("positive")
        manager = InjectionManagerAgent(
            config={"model": "test-model"},
            hybrid_enabled=True,
            poc_judge=judge,
            candidate_ledger=ledger,
        )

        changed = manager._t3_apply_hybrid_verdict(
            finding,
            judge=judge,
            checker=_FakeReproductionChecker("matched"),
            lifecycle=CandidateLifecycleManager(),
            ledger=ledger,
        )

        assert changed is True
        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.NEEDS_MORE
        assert not _hybrid_emits(calls, finding.id)
        assert "hybrid_final_state" not in finding.additional_info


# ---------------------------------------------------------------------------
# Early-return path: Phase-1 confirmation point (before the early-return
# branch) must run the T3 pass — fast-types never reach the merge gate.
# ---------------------------------------------------------------------------


class TestT3EarlyReturnPath:
    def _manager(self, *, judge, checker=None, ledger=None, hybrid=True):
        return InjectionManagerAgent(
            config={"model": "test-model"},
            hybrid_enabled=hybrid,
            poc_judge=judge,
            reproduction_checker=checker,
            candidate_ledger=ledger,
        )

    async def test_early_return_path_confirms_and_emits(self, monkeypatch, tmp_path):
        """A payout-grade Phase-1 finding on the early-return path gets the
        full T3 chain: ledger confirmed + F5 hybrid_confirmed emit +
        run-end save. Phase 2 must never run."""
        calls = _spy_funnel_events(monkeypatch)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        ledger.put(_seed_record(finding))  # second visit -> CONFIRMED applies
        judge = _FakePoCJudge("positive")
        checker = _FakeReproductionChecker("matched")
        manager = self._manager(judge=judge, checker=checker, ledger=ledger)
        _install_fake_phase1(manager, finding)

        with patch(
            "src.core.agents.swarm.injection.manager.resolve_risk_force_allowlist",
            return_value=set(),
        ), patch.object(
            BaseManagerAgent,
            "dispatch",
            new=AsyncMock(
                return_value=MagicMock(status="success", findings=[], execution_log=[])
            ),
        ) as phase2_dispatch:
            result = await manager.dispatch(
                _api_task(phase1_early_return_on_findings=True)
            )

        assert result.status == "success"
        phase2_dispatch.assert_not_awaited()  # early return: Phase 2 never runs
        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.CONFIRMED
        assert record.reason == "hybrid_confirmed"
        assert judge.calls == 1
        assert checker.calls == 1
        assert any(
            c["reason_code"] == "hybrid_confirmed"
            for c in _hybrid_emits(calls, finding.id)
        )
        assert finding.additional_info.get("hybrid_final_state") == "confirmed"
        assert (tmp_path / "candidate_ledger.json").exists(), "run-end save"

    async def test_real_checker_receives_sealed_scope_and_sends(self, monkeypatch, tmp_path):
        """Without a checker injection the REAL SealedReproductionChecker is
        built with the sealed target-only scope: the replay send is actually
        attempted (not fail-closed scope_definition_not_provided) and
        CONFIRMED becomes reachable via reproduction matched."""
        calls = _spy_funnel_events(monkeypatch)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        ledger.put(_seed_record(finding))  # second visit -> CONFIRMED applies
        judge = _FakePoCJudge("positive")
        send_client = MagicMock()
        send_client.request = MagicMock(
            return_value=SimpleNamespace(
                status=200, body="<script>alert(1)</script>", headers={}
            )
        )
        manager = InjectionManagerAgent(
            config={"model": "test-model"},
            hybrid_enabled=True,
            poc_judge=judge,
            candidate_ledger=ledger,
            # reproduction_checker NOT injected -> real checker + scope
        )
        manager.network_client = send_client
        _install_fake_phase1(manager, finding)

        with patch(
            "src.core.agents.swarm.injection.manager.resolve_risk_force_allowlist",
            return_value=set(),
        ), patch.object(
            BaseManagerAgent,
            "dispatch",
            new=AsyncMock(
                return_value=MagicMock(status="success", findings=[], execution_log=[])
            ),
        ):
            result = await manager.dispatch(
                _api_task(phase1_early_return_on_findings=True)
            )

        assert result.status == "success"
        assert send_client.request.called, "replay send must be attempted"
        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.CONFIRMED
        assert record.reason == "hybrid_confirmed"
        assert any(
            c["reason_code"] == "hybrid_confirmed"
            for c in _hybrid_emits(calls, finding.id)
        )
        assert finding.additional_info.get("hybrid_final_state") == "confirmed"

    async def test_early_return_off_path_stays_byte_identical(self, monkeypatch, tmp_path):
        """OFF on the early-return path: no judge/checker construction, no
        ledger open, no hybrid emits, no ledger file — and the early-return
        decision itself is unchanged."""
        monkeypatch.setenv("SHIGOKU_WORKSPACE_PROJECTS_DIR", str(tmp_path))
        calls = _spy_funnel_events(monkeypatch)
        manager = InjectionManagerAgent(config={"model": "test-model"})
        assert manager._t3_hybrid_active() is False
        manager._open_candidate_ledger = MagicMock()
        finding = _payout_finding()
        _install_fake_phase1(manager, finding)

        with patch(
            "src.core.agents.swarm.injection.manager.resolve_risk_force_allowlist",
            return_value=set(),
        ), patch(
            "src.core.validation.finding_validator.PoCJudge"
        ) as judge_cls, patch(
            "src.core.validation.sealed_reproduction_checker.SealedReproductionChecker"
        ) as checker_cls, patch.object(
            BaseManagerAgent,
            "dispatch",
            new=AsyncMock(
                return_value=MagicMock(status="success", findings=[], execution_log=[])
            ),
        ) as phase2_dispatch:
            result = await manager.dispatch(
                _api_task(phase1_early_return_on_findings=True)
            )

        assert result.status == "success"
        phase2_dispatch.assert_not_awaited()  # early-return decision unchanged
        judge_cls.assert_not_called()
        checker_cls.assert_not_called()
        manager._open_candidate_ledger.assert_not_called()
        assert not _hybrid_emits(calls, finding.id)
        assert "hybrid_final_state" not in finding.additional_info
        assert not list(tmp_path.rglob("candidate_ledger.json"))

    async def test_phase1_confirmed_finding_skipped_at_merge_gate(self, monkeypatch, tmp_path):
        """A finding confirmed at the Phase-1 pass must NOT be judged again
        by the merge-gate pass (ledger state check): exactly one judge call
        across both passes."""
        calls = _spy_funnel_events(monkeypatch)
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        finding = _payout_finding()
        ledger.put(_seed_record(finding))
        judge = _FakePoCJudge("positive")
        checker = _FakeReproductionChecker("matched")
        manager = self._manager(judge=judge, checker=checker, ledger=ledger)
        _install_fake_phase1(manager, finding)

        # Phase 2 runs (early return off) but produces no new findings.
        result = await _run_dispatch(manager, phase2_findings=[])

        assert result.status == "success"
        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.CONFIRMED
        # judged once by the Phase-1 pass; the merge pass skipped it
        assert judge.called_finding_ids.count(finding.id) == 1
        assert checker.calls == 1

    async def test_needs_more_finding_rejudged_at_merge_gate(self, monkeypatch, tmp_path):
        """T2 T5: a needs_more finding from the Phase-1 pass is visited once
        more by the merge-gate pass (budget_used 1 -> 2)."""
        ledger = CandidateLedger(tmp_path / "candidate_ledger.json")
        judge = _FakePoCJudge("positive")
        manager = self._manager(judge=judge, checker=_FakeReproductionChecker("matched"), ledger=ledger)

        # Real api-probe phase-1 path: 2 non-payout-grade findings stay
        # needs_more after the Phase-1 pass; the merge pass re-judges them.
        result = await _run_dispatch(manager, phase2_findings=[])

        assert result.status == "success"
        records = ledger.all()
        assert len(records) == 2
        for record in records:
            assert record.state == LifecycleState.NEEDS_MORE
            assert record.budget_used == 2, "T5: one more visit at the merge pass"
        assert judge.calls == 4  # 2 findings x (phase-1 pass + merge pass)


# ---------------------------------------------------------------------------
# Sealed reproduction scope: target-only host[:port] supply
# ---------------------------------------------------------------------------


class TestSealedScope:
    def test_build_scope_for_host_port(self):
        from src.core.agents.swarm.injection.manager import (
            _build_sealed_reproduction_scope,
        )

        scope = _build_sealed_reproduction_scope("http://localhost:3000/")
        assert scope is not None
        assert scope.in_scope_domains == ["localhost:3000"]
        assert scope.strict_mode is True
        assert scope.allow_post_exploit is False
        assert scope.program_name == "sealed-reproduction"
        assert scope.in_scope_ips == []
        assert scope.out_of_scope_domains == []

    def test_build_scope_for_plain_host(self):
        from src.core.agents.swarm.injection.manager import (
            _build_sealed_reproduction_scope,
        )

        scope = _build_sealed_reproduction_scope("https://target.example/api/v1")
        assert scope is not None
        assert scope.in_scope_domains == ["target.example"]

    def test_build_scope_fail_closed_on_invalid_input(self):
        from src.core.agents.swarm.injection.manager import (
            _build_sealed_reproduction_scope,
        )

        assert _build_sealed_reproduction_scope(None) is None
        assert _build_sealed_reproduction_scope("") is None
        assert _build_sealed_reproduction_scope("not-a-url") is None
        assert _build_sealed_reproduction_scope("ftp://localhost:3000/") is None

    def test_scope_allows_only_target_itself(self):
        from src.core.agents.swarm.injection.manager import (
            _build_sealed_reproduction_scope,
        )
        from src.core.domain.scope.vdp_scope_validator import (
            revalidate_scope_for_request,
        )

        scope = _build_sealed_reproduction_scope("http://localhost:3000/")
        assert scope is not None
        # same host:port -> allowed (replay send may proceed)
        assert revalidate_scope_for_request(
            "http://localhost:3000/poc?id=1", scope_definition=scope
        ).allowed
        # different port / missing port / other host -> fail-closed blocked
        assert not revalidate_scope_for_request(
            "http://localhost:3001/poc", scope_definition=scope
        ).allowed
        assert not revalidate_scope_for_request(
            "http://localhost/poc", scope_definition=scope
        ).allowed
        assert not revalidate_scope_for_request(
            "http://other.example/poc", scope_definition=scope
        ).allowed


# ---------------------------------------------------------------------------
# Strict vocabulary + flag/path resolution
# ---------------------------------------------------------------------------


class TestT3Support:
    def test_new_reason_codes_accepted_by_strict_vocab(self):
        rec = FindingFunnelRecorder(enabled=True)
        for code in (
            "hybrid_confirmed",
            "hybrid_refuted",
            "hybrid_parked",
            "hybrid_needs_human",
            "reproduction_transport_error",
        ):
            rec.record("f-t3", "F5", "reached", reason_code=code)
        section = rec.to_section()
        assert section is not None
        assert section["entries"][0]["stages"]["F5"] == "reached"

    def test_unknown_reason_code_still_raises(self):
        rec = FindingFunnelRecorder(enabled=True)
        with pytest.raises(ValueError):
            rec.record("f-t3", "F5", "reached", reason_code="hybrid_made_up")

    def test_t3_hybrid_active_follows_settings_flag(self, monkeypatch):
        manager = InjectionManagerAgent(config={"model": "test-model"})
        monkeypatch.setattr(
            "src.core.config.settings.get_settings",
            lambda: SimpleNamespace(t3_hybrid_enabled=True),
        )
        assert manager._t3_hybrid_active() is True
        monkeypatch.setattr(
            "src.core.config.settings.get_settings",
            lambda: SimpleNamespace(t3_hybrid_enabled=False),
        )
        assert manager._t3_hybrid_active() is False

    def test_constructor_override_wins_over_settings(self, monkeypatch):
        manager = InjectionManagerAgent(
            config={"model": "test-model"}, hybrid_enabled=False
        )
        monkeypatch.setattr(
            "src.core.config.settings.get_settings",
            lambda: SimpleNamespace(t3_hybrid_enabled=True),
        )
        assert manager._t3_hybrid_active() is False

    def test_ledger_path_resolution_reuses_project_base_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SHIGOKU_WORKSPACE_PROJECTS_DIR", str(tmp_path))
        from src.core.agents.swarm.injection.manager import _resolve_candidate_ledger_path

        path = _resolve_candidate_ledger_path("https://example.com:3000/")
        assert path == str(tmp_path / "example.com:3000" / "candidate_ledger.json")
        assert _resolve_candidate_ledger_path("") is None
        assert _resolve_candidate_ledger_path(None) is None

    def test_ledger_path_normalizes_path_and_query_target(self, monkeypatch, tmp_path):
        """run5 regression: a path/query-carrying task.target must resolve
        to the host[:port] project dir so ALL findings of the run share ONE
        ledger (11 findings were previously split across 9 per-URL-path
        ledger files)."""
        monkeypatch.setenv("SHIGOKU_WORKSPACE_PROJECTS_DIR", str(tmp_path))
        from src.core.agents.swarm.injection.manager import _resolve_candidate_ledger_path

        expected = str(tmp_path / "localhost:3000" / "candidate_ledger.json")
        assert (
            _resolve_candidate_ledger_path(
                "http://localhost:3000/rest/products/search?q=test"
            )
            == expected
        )
        # same host, different path/query -> SAME ledger file
        assert (
            _resolve_candidate_ledger_path(
                "http://localhost:3000/account/security"
            )
            == expected
        )
        assert (
            _resolve_candidate_ledger_path("http://localhost:3000") == expected
        )


# ---------------------------------------------------------------------------
# SGK-2026-0455: resurrection wiring (parked records + browser evidence, T2b)
# ---------------------------------------------------------------------------


class _FakeBrowserValidator:
    """Sync browser-validator stub (``validate_xss_sync`` interface)."""

    def __init__(
        self,
        *,
        available: bool = True,
        result: bool = False,
        error: "Exception | None" = None,
    ):
        self.is_available = available
        self.result = result
        self.error = error
        self.calls: list = []

    def validate_xss_sync(self, url: str, timeout: float = 10.0):
        self.calls.append({"url": url, "timeout": timeout})
        if self.error is not None:
            raise self.error
        return self.result


def _dom_evidence_finding(title: str = "Reflected XSS in search") -> Finding:
    """Payout-grade DOM-variant XSS finding carrying browser execution evidence."""
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title=title,
        description="d",
        target_url=API_URL,
        evidence=Evidence(
            request_method="GET",
            request_url=f"{API_URL}?q=1",
            response_status=200,
            response_body="<script>alert(1)</script>",
        ),
        impact="DOM-based execution in the victim's browser",
        reproduction_steps=[f"GET {API_URL}?q=1"],
        additional_info={
            "browser_execution": {
                "dialog_observed": True,
                "executor": "playwright",
                "event": "dom_runtime_execution",
                "variant": "dom",
                "parameter": "q",
                "payload": "<img src=x onerror=alert(1)>",
                "test_url": f"{API_URL}?q=1",
            }
        },
    )


def _dom_mutation_finding(title: str = "Reflected XSS in search") -> Finding:
    """Payout-grade DOM-variant finding with dom-mutation evidence ONLY
    (real browser_execution schema: dom_mutation_observed + event
    "dom_sink_reflection", NO dialog_observed key)."""
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title=title,
        description="d",
        target_url=API_URL,
        evidence=Evidence(
            request_method="GET",
            request_url=f"{API_URL}?q=1",
            response_status=200,
            response_body="<script>alert(1)</script>",
        ),
        impact="DOM-based execution in the victim's browser",
        reproduction_steps=[f"GET {API_URL}?q=1"],
        additional_info={
            "browser_execution": {
                "executor": "playwright",
                "event": "dom_sink_reflection",
                "variant": "dom",
                "parameter": "q",
                "payload": "<img src=x onerror=alert(1)>",
                "test_url": f"{API_URL}?q=1",
                "dom_mutation_observed": True,
                # 意図的に dialog_observed キー無し（実スキーマ再現）
            }
        },
    )


def _parked_record(
    finding: Finding,
    *,
    triggers: list,
    history: "list | None" = None,
    finding_id: "str | None" = None,
) -> CandidateRecord:
    """A parked ledger record (default: matching the browser-evidence
    finding's id and trigger vocabulary)."""
    return CandidateRecord(
        finding_id=finding_id if finding_id is not None else finding.id,
        state=LifecycleState.INCONCLUSIVE_PARKED,
        reason="budget_exhausted",
        vuln_type="xss",
        title=finding.title,
        target_url_masked="",
        evidence_summary={},
        first_seen="2026-08-12T00:00:00+00:00",
        last_investigated="2026-08-12T00:00:00+00:00",
        budget_used=3,
        resurrection_count=0,
        promise_score=0.33,
        revisit_triggers=list(triggers),
        resurrection_history=list(history or []),
    )


class TestT3Resurrection:
    def _ledger(self, tmp_path) -> CandidateLedger:
        return CandidateLedger(tmp_path / "candidate_ledger.json")

    def _manager(self, *, judge, checker, ledger) -> InjectionManagerAgent:
        return InjectionManagerAgent(
            config={"model": "test-model"},
            hybrid_enabled=True,
            poc_judge=judge,
            reproduction_checker=checker,
            candidate_ledger=ledger,
        )

    def _real_dom_checker(self, validator):
        from src.core.agents.swarm.injection.manager import (
            _build_sealed_reproduction_scope,
        )
        from src.core.validation.sealed_reproduction_checker import (
            SealedReproductionChecker,
        )

        return SealedReproductionChecker(
            scope_definition=_build_sealed_reproduction_scope(API_URL),
            browser_validator=validator,
        )

    def test_parked_record_resurrected_and_confirmed_with_browser_evidence(
        self, tmp_path
    ):
        """T2b: parked record + ブラウザ証拠 finding → ``revisit``（resurrect_
        matching）経由で needs_more(budget_used=0) に復活 → DOM 再実行 matched
        → CONFIRMED まで再判定される。"""
        ledger = self._ledger(tmp_path)
        finding = _dom_evidence_finding()
        ledger.put(
            _parked_record(
                finding,
                triggers=[
                    ("vuln_type", "xss"),
                    (
                        "endpoint",
                        CandidateLifecycleManager.normalize_endpoint(API_URL),
                    ),
                    ("evidence", "browser_execution"),
                ],
            )
        )
        judge = _FakePoCJudge("positive")
        validator = _FakeBrowserValidator(result=True)
        checker = self._real_dom_checker(validator)
        manager = self._manager(judge=judge, checker=checker, ledger=ledger)

        changed = manager._t3_run_hybrid_pass(
            SimpleNamespace(target=API_URL), [finding]
        )

        assert changed is True
        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.CONFIRMED
        assert record.reason == "hybrid_confirmed"
        assert record.resurrection_count == 1
        assert record.budget_used == 1  # 復活後 (0) + 再判定 (1)
        assert judge.calls == 1
        assert validator.calls == [{"url": f"{API_URL}?q=1", "timeout": 15.0}]

    def test_non_matching_parked_record_not_resurrected(self, tmp_path):
        """T2b: トリガー非一致の parked は復活しない（blind-retry 防止）. """
        ledger = self._ledger(tmp_path)
        finding = _dom_evidence_finding()
        non_matching = _parked_record(
            finding,
            triggers=[("vuln_type", "sqli")],
            finding_id="other-finding-111",
        )
        ledger.put(non_matching)
        judge = _FakePoCJudge("positive")
        validator = _FakeBrowserValidator(result=True)
        manager = self._manager(
            judge=judge,
            checker=self._real_dom_checker(validator),
            ledger=ledger,
        )

        manager._t3_run_hybrid_pass(SimpleNamespace(target=API_URL), [finding])

        after = ledger.get("other-finding-111")
        assert after is not None
        assert after.state == LifecycleState.INCONCLUSIVE_PARKED
        assert after.resurrection_count == 0
        assert after.budget_used == 3

    def test_resurrection_history_prevents_infinite_resurrection(self, tmp_path):
        """resurrection_history 消費: 同一トークンでは再復活しない（無限ループ防止）. """
        ledger = self._ledger(tmp_path)
        finding = _dom_evidence_finding()
        consumed = _parked_record(
            finding,
            triggers=[("vuln_type", "xss"), ("evidence", "browser_execution")],
            history=[("vuln_type", "xss"), ("evidence", "browser_execution")],
        )
        ledger.put(consumed)
        judge = _FakePoCJudge("positive")
        manager = self._manager(
            judge=judge,
            checker=_FakeReproductionChecker("matched"),
            ledger=ledger,
        )

        manager._t3_run_hybrid_pass(SimpleNamespace(target=API_URL), [finding])

        after = ledger.get(finding.id)
        assert after is not None
        assert after.state == LifecycleState.INCONCLUSIVE_PARKED
        assert after.resurrection_count == 0
        assert judge.calls == 0  # 復活しない → 判定スキップ

    def test_park_side_adds_browser_evidence_trigger(self, tmp_path):
        """_park 側: ブラウザ証拠 finding の parked record の revisit_triggers に
        ("evidence","browser_execution") が載る（語彙追加のみ・基準は不変）. """
        ledger = self._ledger(tmp_path)
        finding = _dom_evidence_finding()
        seed = _seed_record(finding)
        ledger.put(seed)
        judge = _FakePoCJudge("inconclusive")
        manager = self._manager(
            judge=judge,
            checker=_FakeReproductionChecker("matched"),
            ledger=ledger,
        )

        changed = manager._t3_apply_hybrid_verdict(
            finding,
            judge=judge,
            checker=_FakeReproductionChecker("matched"),
            lifecycle=CandidateLifecycleManager(),
            ledger=ledger,
        )

        assert changed is True
        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.INCONCLUSIVE_PARKED
        assert ("evidence", "browser_execution") in record.revisit_triggers
        assert ("vuln_type", "xss") in record.revisit_triggers

    # --- SGK-2026-0455 (実走行診断): dom_mutation 経由のブラウザ証拠 ---

    def test_dom_mutation_evidence_trigger_non_empty(self):
        """dom_mutation_observed:true（dialog_observed キー無し）→ trigger 非空."""
        finding = _dom_mutation_finding()
        assert InjectionManagerAgent._t3_browser_evidence_trigger(finding) == [
            ("evidence", "browser_execution")
        ]

    def test_event_dom_sink_reflection_alone_trigger_non_empty(self):
        """event=="dom_sink_reflection" のみ（発火フラグ無し）でも証拠あり."""
        finding = _dom_evidence_finding()
        finding.additional_info = {
            "browser_execution": {
                "executor": "playwright",
                "event": "dom_sink_reflection",
                "variant": "dom",
                "test_url": f"{API_URL}?q=1",
            }
        }
        assert InjectionManagerAgent._t3_browser_evidence_trigger(finding) == [
            ("evidence", "browser_execution")
        ]

    def test_no_browser_evidence_trigger_empty(self):
        """ブラウザ実行証拠の無い finding → trigger 空（復活トリガーにしない）."""
        finding = _payout_finding()  # additional_info 無し
        assert InjectionManagerAgent._t3_browser_evidence_trigger(finding) == []
        finding.additional_info = {"browser_execution": {"event": "navigation_only"}}
        assert InjectionManagerAgent._t3_browser_evidence_trigger(finding) == []

    def test_dom_mutation_evidence_resurrects_parked_record(self, tmp_path):
        """T2b改: dom_mutation_observed:true（dialog_observed 無し）finding で
        parked XSS record が revisit 経由 needs_more(budget_used=0) に復活し、
        DOM 再実行 matched → CONFIRMED まで再判定される。"""
        ledger = self._ledger(tmp_path)
        finding = _dom_mutation_finding()
        ledger.put(
            _parked_record(
                finding,
                triggers=[
                    ("vuln_type", "xss"),
                    (
                        "endpoint",
                        CandidateLifecycleManager.normalize_endpoint(API_URL),
                    ),
                    ("evidence", "browser_execution"),
                ],
            )
        )
        judge = _FakePoCJudge("positive")
        validator = _FakeBrowserValidator(result=True)
        checker = self._real_dom_checker(validator)
        manager = self._manager(judge=judge, checker=checker, ledger=ledger)

        changed = manager._t3_run_hybrid_pass(
            SimpleNamespace(target=API_URL), [finding]
        )

        assert changed is True
        record = ledger.get(finding.id)
        assert record is not None
        assert record.state == LifecycleState.CONFIRMED
        assert record.reason == "hybrid_confirmed"
        assert record.resurrection_count == 1
        assert record.budget_used == 1  # 復活後 (0) + 再判定 (1)
        assert judge.calls == 1
        assert validator.calls == [{"url": f"{API_URL}?q=1", "timeout": 15.0}]

    def test_dom_mutation_non_matching_parked_not_resurrected(self, tmp_path):
        """トリガー非一致の parked は dom_mutation 証拠でも復活しない."""
        ledger = self._ledger(tmp_path)
        finding = _dom_mutation_finding()
        non_matching = _parked_record(
            finding,
            triggers=[("vuln_type", "sqli")],
            finding_id="other-finding-222",
        )
        ledger.put(non_matching)
        judge = _FakePoCJudge("positive")
        manager = self._manager(
            judge=judge,
            checker=self._real_dom_checker(_FakeBrowserValidator(result=True)),
            ledger=ledger,
        )

        manager._t3_run_hybrid_pass(SimpleNamespace(target=API_URL), [finding])

        after = ledger.get("other-finding-222")
        assert after is not None
        assert after.state == LifecycleState.INCONCLUSIVE_PARKED
        assert after.resurrection_count == 0
