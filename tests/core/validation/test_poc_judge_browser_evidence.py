"""
SGK-2026-0455 C3(b) — poc_judge への実発火証拠（browser_execution）可視化テスト（T5）。

PRODUCT-INDEPENDENT fixtures: generic targets (https://target.example/).

Covers:
- ``PoCJudge._build_user_payload`` の出力 JSON に browser_execution の事実
  サブフィールド（executor/event/variant/dom_mutation_observed/
  dialog_observed/test_url）だけが含まれる。
- browser_execution が dict でない/無い finding → キーは None（証拠なしを
  捏造しない・fail-closed）。
- stub judge（FakeLLMClient）に渡して入力受領を検証（user content に実発火
  証拠が到達する）。
- 偽陽性回帰: ブラウザ証拠無し・反射なし候補は従来どおり賞金級にならない
  （判定ルール 200-233 無改変の回帰）。
"""
import json

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.validation.finding_validator import (
    AiJudgement,
    PoCJudge,
    VerdictState,
    validate_finding,
)

_BROWSER_TEST_URL = "https://target.example/#/results?q=probe"


def _dom_finding(
    *,
    dialog_observed: "bool | None" = None,
    dom_mutation_observed: "bool | None" = None,
    event: str = "dom_runtime_execution",
    variant: str = "dom",
) -> Finding:
    """DOM-variant XSS finding carrying browser_execution evidence."""
    browser_execution: dict = {
        "executor": "playwright",
        "event": event,
        "variant": variant,
        "parameter": "q",
        "payload": "<img src=x onerror=alert(1)>",
        "test_url": _BROWSER_TEST_URL,
    }
    if dialog_observed is not None:
        browser_execution["dialog_observed"] = dialog_observed
    if dom_mutation_observed is not None:
        browser_execution["dom_mutation_observed"] = dom_mutation_observed
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title="DOM XSS in search results",
        description="d",
        target_url="https://target.example/",
        evidence=Evidence(
            request_method="GET",
            request_url=_BROWSER_TEST_URL,
            response_status=200,
            response_body="",
        ),
        reproduction_steps=["Open the URL in a browser", "Observe the alert"],
        impact="DOM-based execution in the victim's browser.",
        additional_info={"browser_execution": browser_execution},
    )


class FakeLLMClient:
    """LLMClient ライク: generate(messages) -> {"choices": [...]}; 入力を記録."""

    def __init__(self, content: str):
        self._content = content
        self.last_messages = None

    def generate(self, messages, **kwargs):
        self.last_messages = messages
        return {"choices": [{"message": {"content": self._content}}]}


_LLM_JSON = (
    '{"payout_grade": true, "is_real": true, "has_actual_impact": true, '
    '"counter_evidence": false, "needs_human": false, '
    '"evidence_refs": ["additional_info.browser_execution"], '
    '"markers": ["browser_dialog_observed"], '
    '"reason": "Browser dialog observed during runtime execution"}'
)


class TestBuildUserPayloadBrowserEvidence:
    def test_browser_execution_factual_subfields_in_payload(self):
        """dialog 発火証拠が事実サブフィールドとして写像される."""
        payload = _dom_finding(dialog_observed=True).to_dict()
        data = json.loads(PoCJudge._build_user_payload(payload))
        be = data["browser_execution"]
        assert set(be.keys()) == {
            "executor",
            "event",
            "variant",
            "dom_mutation_observed",
            "dialog_observed",
            "test_url",
        }
        assert be["executor"] == "playwright"
        assert be["event"] == "dom_runtime_execution"
        assert be["variant"] == "dom"
        assert be["dialog_observed"] is True
        assert be["dom_mutation_observed"] is None
        assert be["test_url"] == _BROWSER_TEST_URL

    def test_dom_mutation_subfield_in_payload(self):
        """dom_mutation_observed 経由の証拠（dialog_observed 無し）も写像される."""
        payload = _dom_finding(
            dom_mutation_observed=True, event="dom_sink_reflection"
        ).to_dict()
        data = json.loads(PoCJudge._build_user_payload(payload))
        be = data["browser_execution"]
        assert be["dom_mutation_observed"] is True
        assert be["event"] == "dom_sink_reflection"
        assert be["dialog_observed"] is None

    def test_missing_browser_execution_is_none(self):
        """ブラウザ証拠が無い finding → キーは None（捏造しない・fail-closed）."""
        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.MEDIUM,
            title="Reflected payload in search response",
            description="d",
            target_url="https://target.example/",
            evidence=Evidence(
                request_method="GET",
                request_url="https://target.example/search?q=probe",
                response_status=200,
                response_body="<script>alert(1)</script>",
            ),
            reproduction_steps=["Send the probe request"],
            impact="Session hijack via reflected payload execution.",
            additional_info={},
        )
        data = json.loads(PoCJudge._build_user_payload(finding.to_dict()))
        assert data["browser_execution"] is None

    def test_non_dict_browser_execution_is_none(self):
        """browser_execution が dict でない → None（fail-closed）."""
        finding = _dom_finding()
        finding.additional_info = {"browser_execution": "garbage"}
        data = json.loads(PoCJudge._build_user_payload(finding.to_dict()))
        assert data["browser_execution"] is None


class TestStubJudgeReceivesBrowserEvidence:
    def test_judge_receives_browser_execution_facts(self):
        """stub judge に実発火証拠が到達する（入力受領検証）."""
        client = FakeLLMClient(_LLM_JSON)
        judge = PoCJudge(client=client)
        finding = _dom_finding(dialog_observed=True)

        judgement = judge.judge(finding)

        assert isinstance(judgement, AiJudgement)
        assert judgement.payout_grade is True
        assert judgement.markers == ("browser_dialog_observed",)
        # 入力受領: user content の JSON に browser_execution 事実が載っている
        assert client.last_messages is not None
        user_content = client.last_messages[0]["content"]
        data = json.loads(user_content)
        assert data["browser_execution"]["dialog_observed"] is True
        assert data["browser_execution"]["test_url"] == _BROWSER_TEST_URL
        assert data["browser_execution"]["event"] == "dom_runtime_execution"


class TestNoBrowserEvidenceNoPrizeGrade:
    def test_without_browser_evidence_no_reflection_not_prize_grade(self):
        """偽陽性回帰: ブラウザ証拠無し・反射なし候補は従来どおり賞金級に
        ならない（判定ルール 200-233 無改変・確認の敷居を下げない）."""
        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.MEDIUM,
            title="Plain candidate without evidence",
            description="d",
            target_url="https://target.example/",
            evidence=Evidence(
                request_method="GET",
                request_url="https://target.example/search?q=probe",
                response_status=200,
                response_body="OK",
            ),
            reproduction_steps=["Send the probe request"],
            impact="",
            additional_info={},
        )
        # judge への入力: ブラウザ証拠は無い（None・捏造なし）
        data = json.loads(PoCJudge._build_user_payload(finding.to_dict()))
        assert data["browser_execution"] is None
        # 判定: フロア不足（反射なし）→ AI 発言がなくても賞金級/確定にならない
        result = validate_finding(finding, ai_judge=None, reproduction_checker=None)
        assert result.state == VerdictState.NEEDS_MORE
        assert result.state != VerdictState.CONFIRMED
        assert result.state != VerdictState.INCONCLUSIVE
