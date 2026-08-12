"""
Hybrid Verdict Self-Check Tests - SGK-2026-0443 (plan appendix F, f1-f12)

PRODUCT-INDEPENDENT fixtures: generic targets (https://target.example/),
generic titles. No product identifiers leak into fixtures.

The mechanical floor is the real evaluate_payout_grade (never bypassed);
AI and reproduction are injected mocks. T1's default NoopReproductionChecker
makes CONFIRMED unreachable except through an explicit matched mock.
"""
import pytest
from typing import Optional

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.validation.finding_validator import (
    AiJudgement,
    HybridVerdict,
    PoCJudge,
    ReproductionOutcome,
    VerdictState,
    validate_finding,
    validate_findings,
)

# ---------------------------------------------------------------------------
# Product-independent fixtures
# ---------------------------------------------------------------------------

_XSS_BODY = '<html><script>alert(1)</script></html>'


def make_finding(
    *,
    with_evidence: bool = True,
    with_impact: bool = True,
    additional_info: Optional[dict] = None,
) -> Finding:
    """floor-PASSING XSS finding（GET 証跡 + 発火印 <script>/alert( + impact）"""
    evidence = (
        Evidence(
            request_method="GET",
            request_url="https://target.example/search?q=probe",
            response_status=200,
            response_body=_XSS_BODY,
        )
        if with_evidence
        else Evidence()
    )
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title="Reflected payload in search response",
        description="A generic reflected-XSS style finding for hybrid verdict tests.",
        target_url="https://target.example/",
        evidence=evidence,
        reproduction_steps=(
            ["Send the probe request", "Observe the reflected payload"]
            if with_impact
            else []
        ),
        impact=(
            "Session hijack via reflected payload execution."
            if with_impact
            else ""
        ),
        additional_info=additional_info or {},
    )


def make_judgement(
    *,
    payout_grade: bool = True,
    is_real: bool = True,
    has_actual_impact: bool = True,
    counter_evidence: bool = False,
    needs_human: bool = False,
    evidence_refs=("evidence.response_body",),
    markers=("payload_reflected_and_executed",),
    reason_masked: str = "Reflected payload observed in the response.",
) -> AiJudgement:
    return AiJudgement(
        payout_grade=payout_grade,
        is_real=is_real,
        has_actual_impact=has_actual_impact,
        counter_evidence=counter_evidence,
        needs_human=needs_human,
        evidence_refs=evidence_refs,
        markers=markers,
        reason_masked=reason_masked,
    )


class FakeJudge:
    """Duck-typed ai_judge: judge(finding) -> configurable AiJudgement."""

    def __init__(self, judgement: AiJudgement):
        self._judgement = judgement
        self.calls = 0

    def judge(self, finding) -> AiJudgement:
        self.calls += 1
        return self._judgement


class FakeRepro:
    """Duck-typed reproduction_checker: check(finding) -> configurable outcome."""

    def __init__(self, outcome: ReproductionOutcome):
        self._outcome = outcome
        self.calls = 0

    def check(self, finding) -> ReproductionOutcome:
        self.calls += 1
        return self._outcome


class FakeLLMClient:
    """LLMClient ライク: generate(messages) -> {"choices": [...content...]}."""

    def __init__(self, content: str):
        self._content = content
        self.last_messages = None

    def generate(self, messages, **kwargs):
        self.last_messages = messages
        return {"choices": [{"message": {"content": self._content}}]}


def verdict(finding, judgement=None, repro=None) -> HybridVerdict:
    return validate_finding(
        finding,
        ai_judge=FakeJudge(judgement) if judgement is not None else None,
        reproduction_checker=repro,
    )


# ---------------------------------------------------------------------------
# f1-f12: state-transition table (plan appendix B) + contract details
# ---------------------------------------------------------------------------


class TestFloorFailNeverConfirmed:
    def test_f1_floor_fail_ai_prize_not_confirmed(self):
        """f1: フロア不足 + AI 賞金級発言 → confirmed にしない（needs_more・
        フロア reason コードパススルー）"""
        finding = make_finding(with_evidence=True, with_impact=False)
        result = verdict(
            finding,
            judgement=make_judgement(payout_grade=True),
            repro=FakeRepro(ReproductionOutcome("matched", "mock")),
        )

        assert result.state == VerdictState.NEEDS_MORE
        assert result.reason == "missing_impact"  # フロア reason コード
        assert result.state != VerdictState.CONFIRMED

    def test_f3_floor_fail_no_refute_not_refuted(self):
        """f3: 証明不足のみでは却下しない（refute シグナルなし）"""
        finding = make_finding(with_evidence=False, with_impact=False)
        result = verdict(
            finding,
            judgement=make_judgement(payout_grade=True),
        )

        assert result.state != VerdictState.REFUTED
        assert result.state == VerdictState.NEEDS_MORE


class TestAiInsufficientEvidence:
    def test_f2_floor_pass_ai_no_prize_inconclusive(self):
        """f2: フロア pass + AI 証拠不足（payout_grade=false・反証なし）→
        inconclusive（confirmed にしない）"""
        finding = make_finding()
        result = verdict(
            finding,
            judgement=make_judgement(
                payout_grade=False, is_real=False, has_actual_impact=False
            ),
            repro=FakeRepro(ReproductionOutcome("matched", "mock")),
        )

        assert result.state == VerdictState.INCONCLUSIVE
        assert result.reason == "ai_no_prize_grade"


class TestExplicitRefute:
    def test_f4_refute_signal_beats_floor_and_ai(self):
        """f4: refute シグナル（additional_info.falsified）はフロア pass +
        AI 賞金級でも最優先で却下"""
        finding = make_finding(additional_info={"falsified": True})
        result = verdict(
            finding,
            judgement=make_judgement(payout_grade=True),
            repro=FakeRepro(ReproductionOutcome("matched", "mock")),
        )

        assert result.state == VerdictState.REFUTED
        assert result.reason == "explicit_refute_signal"

    def test_f7_ai_counter_evidence_refuted(self):
        """f7: AI counter_evidence=true → 却下"""
        finding = make_finding()
        result = verdict(
            finding,
            judgement=make_judgement(payout_grade=True, counter_evidence=True),
            repro=FakeRepro(ReproductionOutcome("matched", "mock")),
        )

        assert result.state == VerdictState.REFUTED
        assert result.reason == "ai_counter_evidence"

    def test_f10_reproduction_mismatch_refuted(self):
        """f10: 再現 mismatched → 却下"""
        finding = make_finding()
        result = verdict(
            finding,
            judgement=make_judgement(payout_grade=True),
            repro=FakeRepro(ReproductionOutcome("mismatched", "mock mismatch")),
        )

        assert result.state == VerdictState.REFUTED
        assert result.reason == "reproduction_mismatch"


class TestThreeWayAnd:
    def test_f5_floor_ai_repro_matched_confirmed(self):
        """f5: 3条件AND（フロア pass + AI 賞金級 + 再現一致）→ confirmed"""
        finding = make_finding()
        result = verdict(
            finding,
            judgement=make_judgement(payout_grade=True),
            repro=FakeRepro(ReproductionOutcome("matched", "mock")),
        )

        assert result.state == VerdictState.CONFIRMED
        assert result.reason == "hybrid_confirmed"

    def test_f6_t1_stub_confirmed_unreachable(self):
        """f6: T1 デフォルト（NoopReproductionChecker）→ confirmed 到達不能"""
        finding = make_finding()
        result = verdict(
            finding,
            judgement=make_judgement(payout_grade=True),
            # reproduction_checker を渡さない → NoopReproductionChecker
        )

        assert result.state == VerdictState.NEEDS_MORE
        assert result.reason == "reproduction_pending"
        assert result.reproduction.status == "not_run"
        assert result.reproduction.reason == "reproduction_wiring_t3"
        assert result.state != VerdictState.CONFIRMED


class TestNeedsHumanAndPending:
    def test_f8_ai_needs_human(self):
        """f8: AI needs_human=true → needs_human"""
        finding = make_finding()
        result = verdict(
            finding,
            judgement=make_judgement(payout_grade=True, needs_human=True),
            repro=FakeRepro(ReproductionOutcome("matched", "mock")),
        )

        assert result.state == VerdictState.NEEDS_HUMAN
        assert result.reason == "ai_needs_human"

    def test_f11_ai_not_run_floor_pass(self):
        """f11: ai_judge=None（フロア pass）→ needs_more / ai_judgement_pending"""
        finding = make_finding()
        result = verdict(finding, judgement=None)

        assert result.state == VerdictState.NEEDS_MORE
        assert result.reason == "ai_judgement_pending"
        assert result.ai_judgement is None


class TestMasking:
    def test_f9_ai_reason_secret_masked_in_verdict(self):
        """f9: AI reason 内の secret は構築時にマスクされ、verdict 経路に
        生値が残らない（PoCJudge 実物 + FakeLLMClient）"""
        raw_token = "sk-1234567890abcdefghijklmnop"
        llm_json = (
            '{"payout_grade": true, "is_real": true, "has_actual_impact": true, '
            '"counter_evidence": false, "needs_human": false, '
            '"evidence_refs": ["evidence.response_body"], "markers": [], '
            '"reason": "The response contains the reflected token '
            + raw_token
            + ' which proves execution."}'
        )
        judge = PoCJudge(client=FakeLLMClient(llm_json))
        finding = make_finding()

        judgement = judge.judge(finding)
        result = verdict(
            finding,
            judgement=judgement,
            repro=FakeRepro(ReproductionOutcome("matched", "mock")),
        )

        assert raw_token not in judgement.reason_masked
        assert "[PII:" in judgement.reason_masked
        assert result.ai_judgement is not None
        assert raw_token not in result.ai_judgement.reason_masked
        assert raw_token not in repr(result)
        assert result.state == VerdictState.CONFIRMED


class TestPromiseScoreAndRefs:
    def test_f12_promise_scores(self):
        """f12: promise_score = 満たしたゲート数/3（参考のみ）"""
        # 0/3: フロア fail（AI 賞金級 + 再現一致でもフロアで止まる。
        # 遅延評価: フロア fail は再現ゲート実行前に退出するため再現は
        # 未実施扱い = 0 と数える（保守的・fail-closed））
        floor_fail = verdict(
            make_finding(with_evidence=True, with_impact=False),
            judgement=make_judgement(payout_grade=True),
            repro=FakeRepro(ReproductionOutcome("matched", "mock")),
        )
        assert floor_fail.promise_score == pytest.approx((0.0 + 1.0 + 0.0) / 3.0)

        # 2/3: フロア pass + AI 賞金級 + 再現 not_run
        repro_pending = verdict(
            make_finding(),
            judgement=make_judgement(payout_grade=True),
        )
        assert repro_pending.promise_score == pytest.approx(2.0 / 3.0)

        # 3/3: confirmed のみ
        confirmed = verdict(
            make_finding(),
            judgement=make_judgement(payout_grade=True),
            repro=FakeRepro(ReproductionOutcome("matched", "mock")),
        )
        assert confirmed.promise_score == pytest.approx(1.0)

    def test_f12_evidence_refs_ordered_union_dedup(self):
        """f12: evidence_refs はフロア refs + AI refs の順序保持ユニオン"""
        ai_refs = ("evidence.response_body", "ai.observation.specific")
        result = verdict(
            make_finding(),
            judgement=make_judgement(payout_grade=True, evidence_refs=ai_refs),
            repro=FakeRepro(ReproductionOutcome("matched", "mock")),
        )

        floor_refs = (
            "evidence.request_method",
            "evidence.request_url",
            "evidence.response_status",
            "evidence.response_body",
        )
        assert result.evidence_refs == (
            floor_refs[0],
            floor_refs[1],
            floor_refs[2],
            floor_refs[3],
            "ai.observation.specific",
        )
        assert len(result.evidence_refs) == len(set(result.evidence_refs))


class TestPoCJudgeJsonParsing:
    def test_f12_poc_judge_parses_valid_json(self):
        """f12: PoCJudge は正しい JSON を AiJudgement にパースする"""
        llm_json = (
            '{"payout_grade": true, "is_real": true, "has_actual_impact": true, '
            '"counter_evidence": false, "needs_human": false, '
            '"evidence_refs": ["evidence.response_body"], '
            '"reason": "観測された反射ペイロードにより確定", '
            '"markers": ["payload_reflected_and_executed"]}'
        )
        client = FakeLLMClient(llm_json)
        judge = PoCJudge(client=client)

        judgement = judge.judge(make_finding())

        assert isinstance(judgement, AiJudgement)
        assert judgement.payout_grade is True
        assert judgement.is_real is True
        assert judgement.has_actual_impact is True
        assert judgement.counter_evidence is False
        assert judgement.needs_human is False
        assert judgement.evidence_refs == ("evidence.response_body",)
        assert judgement.markers == ("payload_reflected_and_executed",)
        assert judgement.reason_masked == "観測された反射ペイロードにより確定"

    def test_f12_poc_judge_rejects_invalid_json(self):
        """f12: 不正 JSON → ValueError（判定を捏造しない・fail-closed）"""
        judge = PoCJudge(client=FakeLLMClient("this is not json"))

        with pytest.raises(ValueError):
            judge.judge(make_finding())

    def test_f12_poc_judge_rejects_missing_bool_field(self):
        """f12: 必須フィールド欠落 → ValueError（fail-closed）"""
        llm_json = (
            '{"payout_grade": true, "is_real": true, "has_actual_impact": true, '
            '"reason": "missing counter_evidence / needs_human", "markers": []}'
        )
        judge = PoCJudge(client=FakeLLMClient(llm_json))

        with pytest.raises(ValueError):
            judge.judge(make_finding())


class TestLazyEvaluationAndExceptionBoundary:
    """ora-1 指摘対応: 短絡規則より先に LLM/再送が走らない・例外境界"""

    def test_refute_signal_skips_ai_call(self):
        """refute シグナルは AI 呼び出しより先に判定（LLM 例外が却下を隠さない）"""

        class RaisingJudge:
            def judge(self, finding):
                raise AssertionError(
                    "ai_judge must not be called for refuted findings"
                )

        finding = make_finding(additional_info={"falsified": True})
        result = validate_finding(
            finding,
            ai_judge=RaisingJudge(),
            reproduction_checker=FakeRepro(
                ReproductionOutcome("matched", "mock")
            ),
        )

        assert result.state == VerdictState.REFUTED
        assert result.reason == "explicit_refute_signal"
        assert result.ai_judgement is None  # 遅延評価: 未実施

    def test_ai_exception_propagates_when_floor_pass(self):
        """フロア pass + AI 例外 → 伝播（fail-closed・判定を捏造しない）"""

        class RaisingJudge:
            def judge(self, finding):
                raise ValueError("LLM failure")

        with pytest.raises(ValueError, match="LLM failure"):
            validate_finding(make_finding(), ai_judge=RaisingJudge())

    def test_repro_exception_propagates(self):
        """再現チェック例外 → 伝播（fail-closed）"""

        class RaisingRepro:
            def check(self, finding):
                raise RuntimeError("resend failure")

        with pytest.raises(RuntimeError, match="resend failure"):
            validate_finding(
                make_finding(),
                ai_judge=FakeJudge(make_judgement(payout_grade=True)),
                reproduction_checker=RaisingRepro(),
            )

    def test_unexpected_repro_status_fail_closed(self):
        """予期しない再現ステータス → needs_more / reproduction_pending（fail closed）"""
        finding = make_finding()
        result = verdict(
            finding,
            judgement=make_judgement(payout_grade=True),
            # 意図的に Literal 外の status を渡し、evaluate() の fail-closed
            # フォールバックを検証する（型チェッカは ignore で明示）
            repro=FakeRepro(ReproductionOutcome("weird", "???")),  # type: ignore[arg-type]
        )

        assert result.state == VerdictState.NEEDS_MORE
        assert result.reason == "reproduction_pending"
        assert result.state != VerdictState.CONFIRMED


class TestPoCJudgeDefensiveParsing:
    """ora-1 指摘対応: 防御的パース境界のテスト追加"""

    def test_fenced_json_accepted(self):
        """コードフェンス包み JSON はパースする（捏造はしない）"""
        llm_json = (
            '```json\n{"payout_grade": true, "is_real": true, '
            '"has_actual_impact": true, "counter_evidence": false, '
            '"needs_human": false, "evidence_refs": ["evidence.response_body"], '
            '"reason": "反射ペイロード実測", "markers": []}\n```'
        )
        judgement = PoCJudge(client=FakeLLMClient(llm_json)).judge(make_finding())

        assert judgement.payout_grade is True
        assert judgement.reason_masked == "反射ペイロード実測"

    def test_empty_response_rejected(self):
        """空応答 → ValueError"""
        with pytest.raises(ValueError):
            PoCJudge(client=FakeLLMClient("")).judge(make_finding())

    def test_non_object_json_rejected(self):
        """JSON オブジェクト以外（配列等）→ ValueError"""
        with pytest.raises(ValueError):
            PoCJudge(client=FakeLLMClient("[1, 2, 3]")).judge(make_finding())

    def test_wrong_type_bool_rejected(self):
        """bool フィールドが文字列 → ValueError"""
        llm_json = (
            '{"payout_grade": "true", "is_real": true, "has_actual_impact": true, '
            '"counter_evidence": false, "needs_human": false, '
            '"evidence_refs": [], "reason": "r", "markers": []}'
        )
        with pytest.raises(ValueError):
            PoCJudge(client=FakeLLMClient(llm_json)).judge(make_finding())

    def test_empty_choices_rejected(self):
        """choices が空リスト → ValueError（IndexError でなく）"""

        class EmptyChoicesClient:
            def generate(self, messages, **kwargs):
                return {"choices": []}

        with pytest.raises(ValueError):
            PoCJudge(client=EmptyChoicesClient()).judge(make_finding())

    def test_non_string_content_rejected(self):
        """content が非文字列 → ValueError"""

        class NonStringClient:
            def generate(self, messages, **kwargs):
                return {"choices": [{"message": {"content": 123}}]}

        with pytest.raises(ValueError):
            PoCJudge(client=NonStringClient()).judge(make_finding())

    def test_secret_in_evidence_refs_and_markers_masked(self):
        """ora-1 [important]: evidence_refs / markers 要素の秘密もマスクされる"""
        raw_token = "sk-1234567890abcdefghijklmnop"
        llm_json = (
            '{"payout_grade": true, "is_real": true, "has_actual_impact": true, '
            '"counter_evidence": false, "needs_human": false, '
            '"evidence_refs": ["' + raw_token + '"], "reason": "ok", '
            '"markers": ["' + raw_token + '"]}'
        )
        judgement = PoCJudge(client=FakeLLMClient(llm_json)).judge(make_finding())

        assert raw_token not in judgement.evidence_refs[0]
        assert "[PII:" in judgement.evidence_refs[0]
        assert raw_token not in judgement.markers[0]
        assert "[PII:" in judgement.markers[0]


class TestBatchContract:
    def test_validate_findings_with_ai_and_repro(self):
        """validate_findings: 注入引数を渡し入力順の verdict リストを返す"""
        good = make_finding()
        bad = make_finding(with_evidence=False, with_impact=False)
        results = validate_findings(
            [good, bad],
            ai_judge=FakeJudge(make_judgement(payout_grade=True)),
            reproduction_checker=FakeRepro(
                ReproductionOutcome("matched", "mock")
            ),
        )

        assert len(results) == 2
        assert results[0].state == VerdictState.CONFIRMED
        assert results[1].state == VerdictState.NEEDS_MORE
