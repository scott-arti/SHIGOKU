"""
open_redirect 本物確定（CONFIRMED / hybrid_confirmed）統合テスト — SGK-2026-0471

finding_validator.validate_finding に以下を与えると CONFIRMED に到達する
ことを検証する（確定バーの敷居は下げない・3 条件 AND は不変）:

- 機械フロア: 本物の open_redirect 証跡（real evaluate_payout_grade が
  marker=external_redirect / payout_grade=True を返す Finding 形状）
- AI 賞金級: payout_grade=true を返すスタブ ai_judge
- 再現: matched スタブ、および実 SealedReproductionChecker +
  FakeNetworkClient（3xx + Location 再出現）の両方

PRODUCT-INDEPENDENT fixtures のみ（target.example / evil.com）。
"""
import pytest

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.finding_validator import (
    AiJudgement,
    ReproductionOutcome,
    VerdictState,
    validate_finding,
)
from src.core.validation.sealed_reproduction_checker import (
    SealedReproductionChecker,
)

TARGET_SCOPE = ScopeDefinition(
    program_name="open-redirect-confirm-test",
    in_scope_domains=["target.example"],
)

EXPLOIT_URL = (
    "https://target.example/redirect?url=https%3A%2F%2F"
    "shigoku-verify-abc.evil.com%2F"
)
ATTACKER_HOST = "shigoku-verify-abc.evil.com"
ATTACKER_LOCATION = f"http://{ATTACKER_HOST}/"


class FakeResponse:
    def __init__(self, status: int = 200, body: str = "", headers: "dict | None" = None):
        self.status = status
        self.body = body
        self.headers = headers or {}


class FakeNetworkClient:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        return self.response


class FakeJudge:
    """payout_grade=true の AI 賞金級判定（duck-typed ai_judge）。"""

    def __init__(self, judgement: AiJudgement):
        self._judgement = judgement

    def judge(self, finding) -> AiJudgement:
        return self._judgement


class FakeRepro:
    def __init__(self, outcome: ReproductionOutcome):
        self._outcome = outcome

    def check(self, finding) -> ReproductionOutcome:
        return self._outcome


def make_open_redirect_finding() -> Finding:
    """OpenRedirectSpecialist (B) が生成する Finding 形状。"""
    return Finding(
        vuln_type=VulnType.OPEN_REDIRECT,
        severity=Severity.MEDIUM,
        title="Open Redirect in parameter 'url'",
        description="Attacker can redirect users to arbitrary external URLs.",
        target_url="https://target.example/",
        evidence=Evidence(
            request_method="GET",
            request_url=EXPLOIT_URL,
            response_status=302,
            response_headers={"Location": ATTACKER_LOCATION},
            response_body=f"Redirect location: {ATTACKER_LOCATION}",
        ),
        reproduction_steps=[
            f"GET {EXPLOIT_URL}",
            f"応答 302 / Location: {ATTACKER_LOCATION}",
            "ヘッドレスブラウザで上記URLを開き、攻撃者管理ホストへの遷移を確認",
        ],
        impact="認証済み利用者を攻撃者が管理する外部URLへ誘導可能。",
        additional_info={
            "parameter": "url",
            "payload": f"http://{ATTACKER_HOST}/",
            "payloads_used": [f"http://{ATTACKER_HOST}/"],
            "tested_params": ["url"],
            "redirect_to": ATTACKER_LOCATION,
            "injected_host": ATTACKER_HOST,
        },
    )


def _prize_judgement() -> AiJudgement:
    return AiJudgement(
        payout_grade=True,
        is_real=True,
        has_actual_impact=True,
        counter_evidence=False,
        needs_human=False,
        evidence_refs=("evidence.request_url",),
        markers=("external_redirect",),
        reason_masked="",
    )


class TestOpenRedirectHybridConfirmation:
    def test_real_floor_plus_ai_prize_plus_matched_repro_confirms(self) -> None:
        """3 条件 AND（real 機械フロア external_redirect + AI 賞金級 +
        再現 matched）→ CONFIRMED / hybrid_confirmed。"""
        verdict = validate_finding(
            make_open_redirect_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome("matched", "reproduction_marker_matched:external_redirect")
            ),
        )
        assert verdict.state == VerdictState.CONFIRMED
        assert verdict.reason == "hybrid_confirmed"
        # 機械フロアが実コード経由で open_redirect を通過している（A①）。
        assert verdict.mechanical_floor.payout_grade is True
        assert verdict.mechanical_floor.marker == "external_redirect"
        assert verdict.promise_score == 1.0

    def test_real_sealed_checker_matched_confirms(self) -> None:
        """実 SealedReproductionChecker（A②）+ FakeNetworkClient の 3xx /
        Location 再出現でも CONFIRMED に到達する（スタブ checker 不使用）。"""
        client = FakeNetworkClient(
            FakeResponse(302, body="", headers={"Location": ATTACKER_LOCATION})
        )
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        verdict = validate_finding(
            make_open_redirect_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=checker,
        )
        assert verdict.state == VerdictState.CONFIRMED
        assert verdict.reason == "hybrid_confirmed"
        assert verdict.reproduction.reason == "reproduction_marker_matched:external_redirect"

    def test_repro_mismatch_refutes(self) -> None:
        """再現 mismatched は従来どおり REFUTED（敷居を下げない）。"""
        verdict = validate_finding(
            make_open_redirect_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome("mismatched", "reproduction_marker_mismatch")
            ),
        )
        assert verdict.state == VerdictState.REFUTED
        assert verdict.reason == "reproduction_mismatch"

    def test_floor_gap_still_needs_more(self) -> None:
        """機械フロアが通らない証跡（impact 空）は AI 発言でも上書きされない。"""
        finding = make_open_redirect_finding()
        finding.impact = ""
        verdict = validate_finding(
            finding,
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome("matched", "reproduction_marker_matched:external_redirect")
            ),
        )
        assert verdict.state == VerdictState.NEEDS_MORE
        assert verdict.reason == "missing_impact"
