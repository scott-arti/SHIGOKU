"""
Candidate Lifecycle Tests - SGK-2026-0444 T2

PRODUCT-INDEPENDENT fixtures: generic targets (https://target.example/),
generic titles, fake secrets only.

Covers the approved transition table (plan appendix B), D1 (INCONCLUSIVE
parks immediately, never refuted), D3 (refuted reachable ONLY via a REFUTED
verdict), the apply_verdict no-op invariant (parked/needs_human/terminal
leave ONLY via revisit), revisit trigger matching/consumption, budget
ranking, normalize_endpoint / hash_account_token, and 0439 masking at
record build time.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Optional

from src.core.agents.swarm.injection.payout_grade import PayoutGradeResult
from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.validation.candidate_lifecycle import (
    CandidateLifecycleManager,
    CandidateRecord,
    LifecycleState,
)
from src.core.validation.finding_validator import (
    HybridVerdict,
    ReproductionOutcome,
    VerdictState,
)

# ---------------------------------------------------------------------------
# Fake secrets (product-independent; used only inside URLs / masked fields)
# ---------------------------------------------------------------------------

SECRET_QUERY = "supersecretvalue123"
SECRET_SK = "sk-test-abcdefghijklmnopqrstuvwx"
SECRET_BEARER = "Bearer abcdef0123456789"
SECRET_EMAIL = "user@example.com"

_SECRET_URL = (
    "https://target.example/login?token=" + SECRET_QUERY
    + "&apikey=" + SECRET_SK
    + "&auth=" + SECRET_BEARER
    + "&contact=" + SECRET_EMAIL
)


class FakeClock:
    """Mutable injectable clock for deterministic age-based tests."""

    def __init__(self, dt: datetime):
        self.dt = dt

    def __call__(self) -> datetime:
        return self.dt

    def advance(self, **kwargs) -> None:
        self.dt = self.dt + timedelta(**kwargs)


def make_finding(
    *,
    vuln_type=VulnType.IDOR,
    title="Generic IDOR finding",
    target_url="https://target.example/account?id=7",
    request_url="https://target.example/account?id=7",
    source_agent="api_analyzer",
) -> Finding:
    """Generic product-independent XSS-free finding (floor-agnostic)."""
    return Finding(
        vuln_type=vuln_type,
        severity=Severity.MEDIUM,
        title=title,
        description="Product-independent description.",
        target_url=target_url,
        evidence=Evidence(
            request_method="GET",
            request_url=request_url,
            response_status=200,
            response_body='{"ok": true}',
        ),
        source_agent=source_agent,
    )


def make_verdict(
    state: VerdictState,
    *,
    reason: str = "some_reason",
    promise_score: float = 0.33,
    evidence_refs=("evidence.request_url",),
) -> HybridVerdict:
    """HybridVerdict with a dummy mechanical floor (verdict shape only)."""
    return HybridVerdict(
        state=state,
        reason=reason,
        mechanical_floor=PayoutGradeResult(
            True, "payout_grade_satisfied", ["evidence.request_url"], None
        ),
        ai_judgement=None,
        reproduction=ReproductionOutcome("not_run", "test"),
        evidence_refs=evidence_refs,
        promise_score=promise_score,
    )


class TestTransitionTable:
    """apply_verdict 遷移表（plan appendix B）"""

    def test_new_candidate_created_as_needs_more(self):
        """record=None → 新規 needs_more レコード（budget_used=1・時刻・
        evidence_summary・target_url_masked を記録）"""
        manager = CandidateLifecycleManager()
        finding = make_finding()

        record = manager.apply_verdict(
            None, make_verdict(VerdictState.NEEDS_MORE, reason="ai_judgement_pending",
                               promise_score=0.66), finding
        )

        assert isinstance(record, CandidateRecord)
        assert record.state == LifecycleState.NEEDS_MORE
        assert record.budget_used == 1
        assert record.reason == "ai_judgement_pending"
        assert record.promise_score == 0.66
        assert record.first_seen == record.last_investigated
        assert record.finding_id == finding.id
        assert record.vuln_type == "idor"
        assert record.title == "Generic IDOR finding"
        assert record.evidence_summary["refs"] == ["evidence.request_url"]
        assert record.evidence_summary["response_status"] == 200
        assert "[PII:" in record.evidence_summary["request_url_masked"]
        assert "[PII:" in record.target_url_masked

    def test_new_candidate_confirmed_verdict_created_confirmed(self):
        """SGK-2026-0452 (承認・2026-08-16): record=None で CONFIRMED verdict
        （3条件AND: payout_grade + poc_judge 正当受理 + reproduction matched）
        が成立した場合、新規レコードは needs_more でなく confirmed で作成
        される（B5 で reason=hybrid_confirmed のまま state=needs_more に
        留まり funnel F6 / live confirmed に到達しない事象の再発防止）。
        CONFIRMED 以外の verdict は従来どおり needs_more 起点。"""
        manager = CandidateLifecycleManager()
        finding = make_finding()

        record = manager.apply_verdict(
            None,
            make_verdict(VerdictState.CONFIRMED, reason="hybrid_confirmed", promise_score=1.0),
            finding,
        )

        assert isinstance(record, CandidateRecord)
        assert record.state == LifecycleState.CONFIRMED
        assert record.reason == "hybrid_confirmed"
        assert record.promise_score == 1.0
        assert record.budget_used == 1
        assert record.first_seen == record.last_investigated

    def test_confirmed_transition(self):
        """CONFIRMED verdict → confirmed（reason 更新・budget 加算）"""
        manager = CandidateLifecycleManager()
        record = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), make_finding())

        result = manager.apply_verdict(
            record, make_verdict(VerdictState.CONFIRMED, reason="hybrid_confirmed",
                                 promise_score=1.0), make_finding()
        )

        assert result.state == LifecycleState.CONFIRMED
        assert result.reason == "hybrid_confirmed"
        assert result.budget_used == 2

    def test_refuted_transition(self):
        """REFUTED verdict → refuted（D3: verdict 経由のみ）"""
        manager = CandidateLifecycleManager()
        record = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), make_finding())

        result = manager.apply_verdict(
            record, make_verdict(VerdictState.REFUTED, reason="explicit_refute_signal"), make_finding()
        )

        assert result.state == LifecycleState.REFUTED
        assert result.reason == "explicit_refute_signal"

    def test_needs_human_transition(self):
        """NEEDS_HUMAN verdict → needs_human"""
        manager = CandidateLifecycleManager()
        record = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), make_finding())

        result = manager.apply_verdict(
            record, make_verdict(VerdictState.NEEDS_HUMAN, reason="ai_needs_human"), make_finding()
        )

        assert result.state == LifecycleState.NEEDS_HUMAN
        assert result.reason == "ai_needs_human"

    def test_needs_more_within_budget_stays(self):
        """NEEDS_MORE 予算内 → needs_more 維持（budget_used 加算・
        reason は前回のまま・last_investigated 更新）"""
        manager = CandidateLifecycleManager()
        record = manager.apply_verdict(
            None, make_verdict(VerdictState.NEEDS_MORE, reason="ai_judgement_pending"), make_finding()
        )
        clock_before = record.last_investigated

        result = manager.apply_verdict(
            record, make_verdict(VerdictState.NEEDS_MORE, reason="reproduction_pending"), make_finding()
        )

        assert result.state == LifecycleState.NEEDS_MORE
        assert result.budget_used == 2
        assert result.reason == "ai_judgement_pending"  # 遷移しない場合は reason 不変

    def test_needs_more_exhausted_low_promise_parks(self):
        """NEEDS_MORE 予算切れ（訪問回数）+ low promise → inconclusive_parked
        （reason=budget_exhausted・triggers 記録・refuted ではない）"""
        manager = CandidateLifecycleManager(max_visits=3)
        finding = make_finding()
        record = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), finding)
        record = manager.apply_verdict(record, make_verdict(VerdictState.NEEDS_MORE), finding)

        result = manager.apply_verdict(
            record, make_verdict(VerdictState.NEEDS_MORE, promise_score=0.33), finding
        )

        assert result.state == LifecycleState.INCONCLUSIVE_PARKED
        assert result.reason == "budget_exhausted"
        assert result.budget_used == 3
        assert result.state != LifecycleState.REFUTED
        assert ("vuln_type", "idor") in result.revisit_triggers
        assert ("endpoint", "https://target.example/account") in result.revisit_triggers

    def test_needs_more_exhausted_high_promise_needs_human(self):
        """NEEDS_MORE 予算切れ + promise >= 閾値 → needs_human
        （reason=budget_exhausted）"""
        manager = CandidateLifecycleManager(max_visits=2)
        record = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), make_finding())

        result = manager.apply_verdict(
            record, make_verdict(VerdictState.NEEDS_MORE, promise_score=1.0), make_finding()
        )

        assert result.state == LifecycleState.NEEDS_HUMAN
        assert result.reason == "budget_exhausted"

    def test_inconclusive_parks_immediately(self):
        """D1: INCONCLUSIVE verdict → 即時 inconclusive_parked（refuted にしない・
        reason は verdict のもの）"""
        manager = CandidateLifecycleManager()
        record = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), make_finding())

        result = manager.apply_verdict(
            record, make_verdict(VerdictState.INCONCLUSIVE, reason="ai_no_prize_grade"), make_finding()
        )

        assert result.state == LifecycleState.INCONCLUSIVE_PARKED
        assert result.reason == "ai_no_prize_grade"
        assert result.state != LifecycleState.REFUTED

    def test_max_age_force_park(self):
        """max_age_days 超過 → 訪問回数未満でも NEEDS_MORE で棚上げ"""
        clock = FakeClock(datetime(2026, 8, 1, tzinfo=timezone.utc))
        manager = CandidateLifecycleManager(max_visits=10, now=clock)
        finding = make_finding()
        record = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), finding)

        clock.advance(days=31)
        result = manager.apply_verdict(
            record, make_verdict(VerdictState.NEEDS_MORE, promise_score=0.33), finding
        )

        assert result.state == LifecycleState.INCONCLUSIVE_PARKED
        assert result.reason == "budget_exhausted"
        assert result.budget_used == 2  # max_visits=10 には未達

    def test_apply_verdict_noop_on_non_needs_more(self):
        """invariant: needs_more 以外（parked/needs_human/終端）は apply_verdict
        no-op（同一オブジェクト・フィールド不変）"""
        manager = CandidateLifecycleManager()
        finding = make_finding()
        terminal_states = [
            LifecycleState.INCONCLUSIVE_PARKED,
            LifecycleState.NEEDS_HUMAN,
            LifecycleState.CONFIRMED,
            LifecycleState.REFUTED,
        ]
        for state in terminal_states:
            record = CandidateRecord(
                finding_id="f-x",
                state=state,
                reason="prev_reason",
                vuln_type="idor",
                title="t",
                target_url_masked="https://target.example/account",
                evidence_summary={"refs": []},
                first_seen="2026-08-01T00:00:00+00:00",
                last_investigated="2026-08-01T00:00:00+00:00",
                budget_used=3,
                resurrection_count=0,
                promise_score=0.5,
                revisit_triggers=[("endpoint", "https://target.example/account")],
                resurrection_history=[],
            )
            before = replace(record)

            result = manager.apply_verdict(
                record, make_verdict(VerdictState.CONFIRMED, reason="hybrid_confirmed"), finding
            )

            assert result is record
            assert result == before  # 完全に不変

    def test_lifecycle_never_refutes_without_refuted_verdict(self):
        """構造的保証: NEEDS_MORE 予算切れ / INCONCLUSIVE は決して refuted にしない"""
        manager = CandidateLifecycleManager(max_visits=1)
        finding = make_finding()

        exhausted = manager.apply_verdict(
            None, make_verdict(VerdictState.NEEDS_MORE, promise_score=0.33), finding
        )
        manager.apply_verdict(
            exhausted, make_verdict(VerdictState.NEEDS_MORE, promise_score=0.33), finding
        )
        inconclusive = manager.apply_verdict(
            None, make_verdict(VerdictState.NEEDS_MORE), finding
        )
        manager.apply_verdict(
            inconclusive, make_verdict(VerdictState.INCONCLUSIVE, reason="ai_no_prize_grade"), finding
        )

        assert exhausted.state != LifecycleState.REFUTED
        assert inconclusive.state != LifecycleState.REFUTED
        assert exhausted.state == LifecycleState.INCONCLUSIVE_PARKED
        assert inconclusive.state == LifecycleState.INCONCLUSIVE_PARKED


class TestDeriveTriggers:
    """derive_triggers: 製品非依存のデフォルト導出"""

    def test_full_derivation_with_dedup(self):
        """vuln_type + normalized endpoints（query除去・末尾スラッシュ除去・
        ポート保持）+ source_agent + tags・順序保持 dedup"""
        manager = CandidateLifecycleManager()
        finding = {
            "vuln_type": "idor",
            "target_url": "https://target.example/account?id=7",
            "evidence": {"request_url": "https://target.example:8443/api/users/?x=1"},
            "source_agent": "api_analyzer",
            "tags": ["idor", "second_account", "idor"],
        }

        triggers = manager.derive_triggers(finding)

        assert triggers == [
            ("vuln_type", "idor"),
            ("endpoint", "https://target.example/account"),
            ("endpoint", "https://target.example:8443/api/users"),
            ("capability", "api_analyzer"),
            ("capability", "idor"),
            ("capability", "second_account"),
        ]

    def test_none_finding_returns_empty(self):
        """finding=None → []"""
        assert CandidateLifecycleManager().derive_triggers(None) == []

    def test_invalid_endpoints_skipped(self):
        """scheme/host 欠落・空 URL はスキップ（guarded）"""
        manager = CandidateLifecycleManager()
        finding = {
            "vuln_type": "xss",
            "target_url": "target.example/api",          # scheme なし
            "evidence": {"request_url": ""},             # 空
            "source_agent": "",
            "tags": [],
        }

        assert manager.derive_triggers(finding) == [("vuln_type", "xss")]

    def test_extra_triggers_merged_at_park(self):
        """棚上げ時に extra_triggers を merge（derived と dedup）"""
        manager = CandidateLifecycleManager()
        finding = make_finding()
        record = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), finding)

        manager.apply_verdict(
            record,
            make_verdict(VerdictState.INCONCLUSIVE, reason="ai_no_prize_grade"),
            finding,
            extra_triggers=[("capability", "new_agent"), ("vuln_type", "idor")],
        )

        assert ("capability", "new_agent") in record.revisit_triggers
        # 重複は1回だけ
        assert record.revisit_triggers.count(("vuln_type", "idor")) == 1


class TestRevisit:
    """revisit: 新情報合致でのみ復活（盲目的再試行なし）"""

    def _parked_record(self, manager: CandidateLifecycleManager) -> CandidateRecord:
        finding = make_finding()
        record = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), finding)
        return manager.apply_verdict(
            record,
            make_verdict(VerdictState.INCONCLUSIVE, reason="ai_no_prize_grade"),
            finding,
        )

    def test_matching_token_resurrects(self):
        """合致トークン → 復活コピー（needs_more・budget リセット・
        resurrection_count+1・history 更新）。元レコードは不変"""
        manager = CandidateLifecycleManager()
        parked = self._parked_record(manager)
        token = ("endpoint", "https://target.example/account")
        assert token in parked.revisit_triggers

        resurrected = manager.revisit([parked], [token])

        assert len(resurrected) == 1
        revived = resurrected[0]
        assert revived.state == LifecycleState.NEEDS_MORE
        assert revived.budget_used == 0
        assert revived.resurrection_count == 1
        assert revived.resurrection_history == [token]
        assert revived.finding_id == parked.finding_id
        # 元レコードは触らない（盲目的再試行防止）
        assert parked.state == LifecycleState.INCONCLUSIVE_PARKED
        assert parked.budget_used != 0

    def test_non_matching_stays_parked(self):
        """非合致 → 復活なし・parked のまま（無変更）"""
        manager = CandidateLifecycleManager()
        parked = self._parked_record(manager)
        before = replace(parked)

        result = manager.revisit([parked], [("capability", "unrelated_agent")])

        assert result == []
        assert parked == before

    def test_consumed_token_cannot_retrigger(self):
        """消費済みトークンは再トリガー不可: 復活後は needs_more（再復活対象外）・
        再棚上げ後も history に残るため同一トークンでは復活しない"""
        manager = CandidateLifecycleManager()
        parked = self._parked_record(manager)
        token = ("endpoint", "https://target.example/account")

        first = manager.revisit([parked], [token])
        assert len(first) == 1
        # 復活コピーは needs_more → 2回目の revisit では再復活しない
        assert manager.revisit(first, [token]) == []
        # 再棚上げしても history に消費済みトークンが残る
        reparked = manager.apply_verdict(
            first[0],
            make_verdict(VerdictState.INCONCLUSIVE, reason="ai_no_prize_grade"),
            make_finding(),
        )
        assert token in reparked.revisit_triggers
        assert manager.revisit([reparked], [token]) == []

    def test_extra_triggers_honored(self):
        """park 時に merge された extra trigger でも復活できる"""
        manager = CandidateLifecycleManager()
        finding = make_finding()
        record = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), finding)
        parked = manager.apply_verdict(
            record,
            make_verdict(VerdictState.INCONCLUSIVE, reason="ai_no_prize_grade"),
            finding,
            extra_triggers=[("capability", "new_agent")],
        )

        resurrected = manager.revisit([parked], [("capability", "new_agent")])

        assert len(resurrected) == 1
        assert resurrected[0].state == LifecycleState.NEEDS_MORE

    def test_non_parked_records_never_touched(self):
        """needs_more/終端レコードは revisit 対象外（合致トークンでも無視）"""
        manager = CandidateLifecycleManager()
        finding = make_finding()
        active = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), finding)

        assert manager.revisit([active], [("vuln_type", "idor")]) == []
        assert active.state == LifecycleState.NEEDS_MORE


class TestAllocateInvestigationBudget:
    """allocate_investigation_budget: ランキング + キャップ"""

    def _record(self, finding_id, state, promise, investigated, first_seen="2026-08-01T00:00:00+00:00"):
        return CandidateRecord(
            finding_id=finding_id,
            state=state,
            reason="r",
            vuln_type="idor",
            title="t",
            target_url_masked="https://target.example/account",
            evidence_summary={"refs": []},
            first_seen=first_seen,
            last_investigated=investigated,
            budget_used=1,
            resurrection_count=0,
            promise_score=promise,
            revisit_triggers=[],
            resurrection_history=[],
        )

    def test_ranking_cap_and_state_filter(self):
        """promise desc 順・run_budget キャップ・needs_more のみ"""
        manager = CandidateLifecycleManager()
        high = self._record("h", LifecycleState.NEEDS_MORE, 1.0, "2026-08-03T00:00:00+00:00")
        mid = self._record("m", LifecycleState.NEEDS_MORE, 0.66, "2026-08-02T00:00:00+00:00")
        low = self._record("l", LifecycleState.NEEDS_MORE, 0.33, "2026-08-01T00:00:00+00:00")
        parked = self._record("p", LifecycleState.INCONCLUSIVE_PARKED, 1.0, "2026-08-01T00:00:00+00:00")
        confirmed = self._record("c", LifecycleState.CONFIRMED, 0.99, "2026-08-01T00:00:00+00:00")

        capped = manager.allocate_investigation_budget([low, confirmed, high, parked, mid], run_budget=2)
        uncapped = manager.allocate_investigation_budget([low, confirmed, high, parked, mid])

        assert [r.finding_id for r in capped] == ["h", "m"]
        assert [r.finding_id for r in uncapped] == ["h", "m", "l"]

    def test_tie_break_by_last_investigated(self):
        """同一 promise → last_investigated 昇順"""
        manager = CandidateLifecycleManager()
        older = self._record("a", LifecycleState.NEEDS_MORE, 0.5, "2026-08-01T00:00:00+00:00")
        newer = self._record("b", LifecycleState.NEEDS_MORE, 0.5, "2026-08-05T00:00:00+00:00")

        assert [r.finding_id for r in manager.allocate_investigation_budget([newer, older])] == ["a", "b"]


class TestHashAccountToken:
    """hash_account_token: 生アカウント識別子を保存しない"""

    def test_hash_properties(self):
        """12桁 hex・決定的・生トークンを含まない"""
        token = "alice@example.com"

        digest = CandidateLifecycleManager.hash_account_token(token)

        assert len(digest) == 12
        int(digest, 16)  # hex として妥当
        assert digest == CandidateLifecycleManager.hash_account_token(token)
        assert token not in digest


class TestNormalizeEndpoint:
    """normalize_endpoint: 安定した endpoint トークン化"""

    def test_normalization_rules(self):
        """query/fragment/userinfo 除去・末尾スラッシュ除去・ポート保持・
        scheme/host 小文字化・root "/" 保持"""
        normalize = CandidateLifecycleManager.normalize_endpoint
        assert normalize("https://target.example/api?q=1#frag") == "https://target.example/api"
        assert normalize("HTTP://Target.Example:8080/Path/?x=1") == "http://target.example:8080/Path"
        assert normalize("https://user:pass@target.example:8443/root/") == "https://target.example:8443/root"
        assert normalize("https://target.example/") == "https://target.example/"
        assert normalize("https://target.example") == "https://target.example/"

    def test_invalid_inputs_skipped(self):
        """空・scheme なし・host なし・不正ポート → ""（スキップ）"""
        normalize = CandidateLifecycleManager.normalize_endpoint
        assert normalize("") == ""
        assert normalize("target.example/api") == ""
        assert normalize("https://") == ""
        assert normalize("https://target.example:bad/") == ""


class TestEdgeCases:
    """境界分岐の網羅（Enum 変換・不正 status・空 payload・naive 時刻）"""

    def test_new_record_with_minimal_payload(self):
        """payload 欠落（{}）→ 全フィールド空で安全に生成（guarded）"""
        manager = CandidateLifecycleManager()

        record = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), {})

        assert record.finding_id == ""
        assert record.vuln_type == ""
        assert record.title == ""
        assert record.target_url_masked == ""
        assert record.evidence_summary == {"refs": ["evidence.request_url"]}
        assert record.state == LifecycleState.NEEDS_MORE
        assert record.budget_used == 1

    def test_new_record_status_zero_or_unparseable(self):
        """response_status が 0 / 非数値 → evidence_summary では None（guarded）"""
        manager = CandidateLifecycleManager()
        zero = manager.apply_verdict(
            None,
            make_verdict(VerdictState.NEEDS_MORE),
            {"id": "f-zero", "evidence": {"response_status": 0}},
        )
        unparseable = manager.apply_verdict(
            None,
            make_verdict(VerdictState.NEEDS_MORE),
            {"id": "f-bad", "evidence": {"response_status": "oops"}},
        )

        assert zero.evidence_summary["response_status"] is None
        assert unparseable.evidence_summary["response_status"] is None
        assert "request_url_masked" not in zero.evidence_summary  # 欠落キーは省略

    def test_new_record_enum_vuln_type(self):
        """vuln_type が Enum でも文字列に変換して記録"""
        manager = CandidateLifecycleManager()
        record = manager.apply_verdict(
            None,
            make_verdict(VerdictState.NEEDS_MORE),
            {"id": "f-enum", "vuln_type": VulnType.IDOR},
        )

        assert record.vuln_type == "idor"

    def test_derive_triggers_enum_vuln_type(self):
        """derive_triggers の vuln_type Enum 分岐"""
        manager = CandidateLifecycleManager()

        triggers = manager.derive_triggers({"vuln_type": VulnType.XSS})

        assert triggers == [("vuln_type", "xss")]

    def test_age_days_unparseable_first_seen_parks(self):
        """first_seen がパース不能 → age=inf → 即棚上げ（fail-closed）"""
        manager = CandidateLifecycleManager(max_visits=10)
        record = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), make_finding())
        record.first_seen = "not-a-date"

        result = manager.apply_verdict(
            record, make_verdict(VerdictState.NEEDS_MORE, promise_score=0.33), make_finding()
        )

        assert result.state == LifecycleState.INCONCLUSIVE_PARKED
        assert result.reason == "budget_exhausted"

    def test_age_days_naive_timestamps(self):
        """naive な first_seen / now → UTC 前提で年齢計算（予算内なら継続）"""
        clock = FakeClock(datetime(2026, 8, 6))  # naive
        manager = CandidateLifecycleManager(max_visits=10, now=clock)
        finding = make_finding()
        record = manager.apply_verdict(None, make_verdict(VerdictState.NEEDS_MORE), finding)
        record.first_seen = "2026-08-01T00:00:00"  # naive

        result = manager.apply_verdict(
            record, make_verdict(VerdictState.NEEDS_MORE), finding
        )

        assert result.state == LifecycleState.NEEDS_MORE  # 5日 < max_age_days
        assert result.budget_used == 2


class TestMasking:
    """record 生成時の 0439 マスキング（生秘密ゼロ）"""

    def test_new_record_contains_no_raw_secrets(self):
        """fake secret 入り finding → target_url_masked / evidence_summary に
        生値なし・[PII: トークンのみ"""
        manager = CandidateLifecycleManager()
        finding = make_finding(
            target_url=_SECRET_URL,
            request_url=_SECRET_URL,
        )

        record = manager.apply_verdict(
            None, make_verdict(VerdictState.NEEDS_MORE), finding
        )

        for secret in (SECRET_QUERY, SECRET_SK, SECRET_BEARER, SECRET_EMAIL):
            assert secret not in record.target_url_masked
            assert secret not in record.evidence_summary["request_url_masked"]
        assert "[PII:" in record.target_url_masked
        assert "[PII:" in record.evidence_summary["request_url_masked"]
