"""
cors 本物確定（CONFIRMED / hybrid_confirmed）統合テスト — SGK-2026-0475

finding_validator.validate_finding に以下を与えると CONFIRMED に到達する
ことを検証する（確定バーの敷居は下げない・3 条件 AND は不変）:

- 機械フロア: 本物の cors 証跡（real evaluate_payout_grade が
  marker=cors_credentialed_reflection / payout_grade=True を返す Finding 形状）
- AI 賞金級: payout_grade=true を返すスタブ ai_judge
- 再現: matched スタブ、および実 SealedReproductionChecker +
  FakeNetworkClient（Origin 再送で ACAO 反映 + ACAC true）の両方

さらに wildcard（acao="*"・public-data CORS）の Finding は機械フロアで
no_firing_marker となり CONFIRMED に到達しない（Juice Shop 型の正しい
非確定・fail-closed）ことを実証する。

PRODUCT-INDEPENDENT fixtures のみ（attacker.example / target.example）。
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
    program_name="cors-confirm-test",
    in_scope_domains=["target.example"],
)

API_URL = "https://target.example/api/account"
TEST_ORIGIN = "https://attacker.example"
CREDENTIALED_BODY = (
    '{"session_token":"dummy-session-3f2a9c8e1b7d","user_email":"alice@example.test",'
    '"account_role":"admin","account_id":"acct_100042"}'
)


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


def make_cors_finding(acao: str = TEST_ORIGIN, acac: str = "true") -> Finding:
    """SmartCORSHunter (B) が生成する Finding 形状。"""
    return Finding(
        vuln_type=VulnType.CORS_MISCONFIGURATION,
        severity=Severity.HIGH,
        title="CORS Misconfiguration: origin_reflection_with_credentials",
        description=(
            f"Origin '{TEST_ORIGIN}' was reflected in Access-Control-Allow-Origin header. "
            "Type: origin_reflection_with_credentials."
        ),
        target_url=API_URL,
        evidence=Evidence(
            request_method="GET",
            request_url=API_URL,
            request_headers={"Origin": TEST_ORIGIN},
            response_status=200,
            response_headers={
                "Access-Control-Allow-Origin": acao,
                "Access-Control-Allow-Credentials": acac,
            },
            response_body=CREDENTIALED_BODY if acao == TEST_ORIGIN else "",
        ),
        reproduction_steps=[
            f"1. Send GET {API_URL} with header: Origin: {TEST_ORIGIN}",
            f"2. Observe response header: Access-Control-Allow-Origin: {acao}",
            "3. If Access-Control-Allow-Credentials: true, cross-origin requests "
            "with cookies are possible.",
        ],
        impact=(
            "An attacker can read sensitive cross-origin responses (tokens, PII) "
            "if the victim visits a malicious page while authenticated."
        ),
        additional_info={
            "test_origin": TEST_ORIGIN,
            "acao": acao,
            "acac": acac,
            "misconfiguration": (
                "origin_reflection_with_credentials"
                if acao == TEST_ORIGIN
                else "wildcard_no_credentials"
            ),
            "credentialed_body_excerpt": (
                CREDENTIALED_BODY if acao == TEST_ORIGIN and acac == "true" else ""
            ),
            "poc_request": f"GET {API_URL} HTTP/1.1\nOrigin: {TEST_ORIGIN}\n",
            "poc_response": (
                "HTTP/1.1 200 OK\n"
                f"Access-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: {acac}\n"
            ),
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
        markers=("cors_credentialed_reflection",),
        reason_masked="",
    )


class TestCorsHybridConfirmation:
    def test_real_floor_plus_ai_prize_plus_matched_repro_confirms(self) -> None:
        """3 条件 AND（real 機械フロア cors_credentialed_reflection + AI 賞金級
        + 再現 matched）→ CONFIRMED / hybrid_confirmed。"""
        verdict = validate_finding(
            make_cors_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome(
                    "matched", "reproduction_marker_matched:cors_credentialed_reflection"
                )
            ),
        )
        assert verdict.state == VerdictState.CONFIRMED
        assert verdict.reason == "hybrid_confirmed"
        # 機械フロアが実コード経由で cors を通過している（A①）。
        assert verdict.mechanical_floor.payout_grade is True
        assert verdict.mechanical_floor.marker == "cors_credentialed_reflection"
        assert verdict.promise_score == 1.0

    def test_real_sealed_checker_matched_confirms(self) -> None:
        """実 SealedReproductionChecker（A②）+ FakeNetworkClient の Origin 再送
        （ACAO 反映 + ACAC true）でも CONFIRMED に到達する（スタブ checker
        不使用）。"""
        client = FakeNetworkClient(
            FakeResponse(
                200,
                body="",
                headers={
                    "Access-Control-Allow-Origin": TEST_ORIGIN,
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        )
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        verdict = validate_finding(
            make_cors_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=checker,
        )
        assert verdict.state == VerdictState.CONFIRMED
        assert verdict.reason == "hybrid_confirmed"
        assert (
            verdict.reproduction.reason
            == "reproduction_marker_matched:cors_credentialed_reflection"
        )

    def test_repro_mismatch_refutes(self) -> None:
        """再現 mismatched（ACAO 非反映等）は従来どおり REFUTED（敷居を下げない）。"""
        verdict = validate_finding(
            make_cors_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome("mismatched", "reproduction_marker_mismatch")
            ),
        )
        assert verdict.state == VerdictState.REFUTED
        assert verdict.reason == "reproduction_mismatch"

    def test_wildcard_public_data_cors_never_confirms(self) -> None:
        """(Juice Shop 型の正しい非確定) acao="*"（公開データのみ・低影響）は
        機械フロア no_firing_marker → CONFIRMED に到達しない。AI 発言でも
        上書きされない。"""
        verdict = validate_finding(
            make_cors_finding(acao="*", acac=""),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome(
                    "matched", "reproduction_marker_matched:cors_credentialed_reflection"
                )
            ),
        )
        assert verdict.state == VerdictState.NEEDS_MORE
        assert verdict.reason == "no_firing_marker"
        assert verdict.mechanical_floor.payout_grade is False
        assert verdict.mechanical_floor.marker is None
