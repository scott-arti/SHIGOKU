"""
JWT alg=none 本物確定（CONFIRMED / hybrid_confirmed）統合テスト — SGK-2026-0476

finding_validator.validate_finding に以下を与えると CONFIRMED に到達する
ことを検証する（確定バーの敷居は下げない・3 条件 AND は不変）:

- 機械フロア: 本物の JWT 偽造受理証跡（real evaluate_payout_grade が
  marker=jwt_forgery_accepted / payout_grade=True を返す Finding 形状）
- AI 賞金級: payout_grade=true を返すスタブ ai_judge
- 再現: matched スタブ、および実 SealedReproductionChecker +
  FakeNetworkClient（forged_token 再送で forged_identity 再出現）の両方

さらに署名検証済み（jwt_alg=RS256）の Finding は機械フロアで
no_firing_marker となり CONFIRMED に到達しない（署名検証サーバ型の正しい
非確定・fail-closed）ことを実証する。

PRODUCT-INDEPENDENT fixtures のみ（target.example / reserved example TLD の
fabricated identity）。
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
    program_name="jwt-confirm-test",
    in_scope_domains=["target.example"],
)

AUTH_URL = "https://target.example/api/identity"
FABRICATED_IDENTITY = "forge-3f2a9c8e@evil.example"
FORGED_BODY = f'{{"user":{{"id":1,"email":"{FABRICATED_IDENTITY}"}}}}'
FORGED_TOKEN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0."
    "eyJkYXRhIjp7ImlkIjoxLCJlbWFpbCI6ImZvcmdlLTNmMmE5YzhlQGV2aWwuZXhhbXBsZSJ9LCJpYXQiOjEyM30."
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


def make_jwt_forgery_finding(jwt_alg: str = "none") -> Finding:
    """AuthNinja (B) が生成する Finding 形状。jwt_alg="RS256" で署名検証済み
    （非確定）の変種も作れる。"""
    reflected = jwt_alg == "none"
    return Finding(
        vuln_type=VulnType.JWT_ALG_NONE,
        severity=Severity.HIGH,
        title="Authentication Bypass: JWT accepts 'none' algorithm (Signature Bypass)",
        description="JWT accepts 'none' algorithm (Signature Bypass)",
        target_url=AUTH_URL,
        evidence=Evidence(
            request_method="GET",
            request_url=AUTH_URL,
            response_status=200,
            response_body=FORGED_BODY if reflected else '{"user":{}}',
        ),
        reproduction_steps=[
            "1. GET the identity endpoint with no token (identity absent).",
            "2. Fabricate a local alg=none token with an attacker-chosen identity.",
            "3. GET the same endpoint with the forged token in Authorization/Cookie.",
            "4. Observe the fabricated identity reflected in the response.",
        ],
        impact=(
            "The server accepts unsigned (alg=none) JWT tokens without signature "
            "verification: an attacker can impersonate an arbitrary identity."
        ),
        additional_info={
            "jwt_alg": jwt_alg,
            "unauth_baseline_absent": reflected,
            "forged_identity": FABRICATED_IDENTITY,
            "forged_identity_reflected": reflected,
            "auth_endpoint": AUTH_URL,
            "forged_token": FORGED_TOKEN,
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
        markers=("jwt_forgery_accepted",),
        reason_masked="",
    )


class TestJwtHybridConfirmation:
    def test_real_floor_plus_ai_prize_plus_matched_repro_confirms(self) -> None:
        """3 条件 AND（real 機械フロア jwt_forgery_accepted + AI 賞金級
        + 再現 matched）→ CONFIRMED / hybrid_confirmed。"""
        verdict = validate_finding(
            make_jwt_forgery_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome(
                    "matched", "reproduction_marker_matched:jwt_forgery_accepted"
                )
            ),
        )
        assert verdict.state == VerdictState.CONFIRMED
        assert verdict.reason == "hybrid_confirmed"
        # 機械フロアが実コード経由で jwt を通過している（A①）。
        assert verdict.mechanical_floor.payout_grade is True
        assert verdict.mechanical_floor.marker == "jwt_forgery_accepted"
        assert verdict.promise_score == 1.0

    def test_real_sealed_checker_matched_confirms(self) -> None:
        """実 SealedReproductionChecker（A②）+ FakeNetworkClient の forged_token
        再送（forged_identity 再出現）でも CONFIRMED に到達する（スタブ checker
        不使用）。"""
        client = FakeNetworkClient(FakeResponse(200, body=FORGED_BODY))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        verdict = validate_finding(
            make_jwt_forgery_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=checker,
        )
        assert verdict.state == VerdictState.CONFIRMED
        assert verdict.reason == "hybrid_confirmed"
        assert (
            verdict.reproduction.reason
            == "reproduction_marker_matched:jwt_forgery_accepted"
        )
        # 再送は forged_token を Authorization/Cookie に付けた 1 回の GET
        assert len(client.calls) == 1
        headers = client.calls[0]["kwargs"]["headers"]
        assert headers["Authorization"] == f"Bearer {FORGED_TOKEN}"
        assert headers["Cookie"] == f"token={FORGED_TOKEN}"

    def test_repro_mismatch_refutes(self) -> None:
        """再現 mismatched（forged_identity 非再出現等）は従来どおり REFUTED
        （敷居を下げない）。"""
        verdict = validate_finding(
            make_jwt_forgery_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome("mismatched", "reproduction_marker_mismatch")
            ),
        )
        assert verdict.state == VerdictState.REFUTED
        assert verdict.reason == "reproduction_mismatch"

    def test_signed_token_variant_never_confirms(self) -> None:
        """(署名検証サーバ型の正しい非確定) jwt_alg=RS256（署名検証済み）は
        機械フロア no_firing_marker → CONFIRMED に到達しない。AI 発言でも
        上書きされない。"""
        verdict = validate_finding(
            make_jwt_forgery_finding(jwt_alg="RS256"),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome(
                    "matched", "reproduction_marker_matched:jwt_forgery_accepted"
                )
            ),
        )
        assert verdict.state == VerdictState.NEEDS_MORE
        assert verdict.reason == "no_firing_marker"
        assert verdict.mechanical_floor.payout_grade is False
        assert verdict.mechanical_floor.marker is None
