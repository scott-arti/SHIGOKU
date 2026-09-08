"""
SGK-2026-0474 — LFI 本物確定（CONFIRMED / hybrid_confirmed）統合テスト

finding_validator.validate_finding に以下を与えると CONFIRMED に到達する
ことを検証する（確定バーの敷居は下げない・3 条件 AND は不変）:

- 機械フロア: 本物の LFI 証跡（real evaluate_payout_grade が
  marker=file_content_leak / payout_grade=True を返す Finding 形状）
- AI 賞金級: payout_grade=true を返すスタブ ai_judge
- 再現: matched スタブ、および実 SealedReproductionChecker +
  FakeNetworkClient（excerpt 再出現）の両方

PRODUCT-INDEPENDENT fixtures のみ（target.example・一般ファイル名）。
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
    program_name="lfi-confirm-test",
    in_scope_domains=["target.example"],
)

LEAK_URL = "https://target.example/private/report.bak%2500.md"
CLEAN_URL = "https://target.example/private/report.bak"

# パス方式で取得した機密本文（JSON 風・複数行・_LFI_PATTERNS 非一致）。
LEAK_BODY = (
    "{\n"
    '  "quarterly_report": "2026-Q1",\n'
    '  "total_amount": 1250000,\n'
    '  "internal_note": "unaudited draft for board review",\n'
    '  "entries": [\n'
    '    {"region": "emea", "amount": 340000}\n'
    "  ]\n"
    "}\n"
)
# 差分成立時にエンジンが保存する安定抜粋（再送本文に再出現する断片）。
EXCERPT = '"internal_note": "unaudited draft for board review"'


class FakeResponse:
    def __init__(self, status: int = 200, body: str = ""):
        self.status = status
        self.body = body


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


def make_lfi_finding() -> Finding:
    """SmartLFIHunter（パス方式・差分成立）が生成する Finding 形状。"""
    return Finding(
        vuln_type=VulnType.LFI,
        severity=Severity.HIGH,
        title="LFI/Path Traversal via URL path (path-based file disclosure)",
        description="LFI detected.",
        target_url=CLEAN_URL,
        evidence=Evidence(
            request_method="GET",
            request_url=LEAK_URL,
            response_status=200,
            response_body=LEAK_BODY,
        ),
        reproduction_steps=[
            f"クリーン URL（{CLEAN_URL}）への GET は 403 で取得不可（バイパスなし）",
            f"バイパス URL（{LEAK_URL}）への GET は 200 で機密ファイル内容を取得",
            f"取得本文の抜粋を確認する: {EXCERPT}",
        ],
        impact="認証・認可を経ずに本来非公開のサーバ内ファイルを取得可能。機密情報漏えいの起点。",
        additional_info={
            "parameter": None,
            "tested_params": [],
            "payload": "/private/report.bak%2500.md",
            "file_marker_excerpt": EXCERPT,
            "target_file": "/private/report.bak",
            "poc_request": (
                f"GET /private/report.bak%2500.md HTTP/1.1\nHost: target.example"
            ),
            "poc_response": f"HTTP/1.1 200\n\n{LEAK_BODY}",
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
        markers=("file_content_leak",),
        reason_masked="",
    )


class TestLfiHybridConfirmation:
    def test_real_floor_plus_ai_prize_plus_matched_repro_confirms(self) -> None:
        """3 条件 AND（real 機械フロア file_content_leak + AI 賞金級 +
        再現 matched）→ CONFIRMED / hybrid_confirmed。"""
        verdict = validate_finding(
            make_lfi_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome(
                    "matched", "reproduction_marker_matched:file_content_leak"
                )
            ),
        )
        assert verdict.state == VerdictState.CONFIRMED
        assert verdict.reason == "hybrid_confirmed"
        # 機械フロアが実コード経由で LFI を通過している（excerpt 発火）。
        assert verdict.mechanical_floor.payout_grade is True
        assert verdict.mechanical_floor.marker == "file_content_leak"
        assert verdict.promise_score == 1.0

    def test_real_sealed_checker_excerpt_reappearance_confirms(self) -> None:
        """実 SealedReproductionChecker（A②）+ FakeNetworkClient の excerpt
        再出現でも CONFIRMED に到達する（スタブ checker 不使用）。"""
        client = FakeNetworkClient(FakeResponse(200, LEAK_BODY))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        verdict = validate_finding(
            make_lfi_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=checker,
        )
        assert verdict.state == VerdictState.CONFIRMED
        assert verdict.reason == "hybrid_confirmed"
        assert (
            verdict.reproduction.reason
            == "reproduction_marker_matched:file_content_leak"
        )
        # 封印再送はバイパス URL（evidence.request_url）に対して行われている。
        assert client.calls[0]["url"] == LEAK_URL

    def test_repro_mismatch_refutes(self) -> None:
        """再現 mismatched は従来どおり REFUTED（敷居を下げない）。"""
        verdict = validate_finding(
            make_lfi_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome("mismatched", "reproduction_marker_mismatch")
            ),
        )
        assert verdict.state == VerdictState.REFUTED
        assert verdict.reason == "reproduction_mismatch"

    def test_floor_gap_still_needs_more(self) -> None:
        """機械フロアが通らない証跡（impact 空）は AI 発言でも上書きされない。"""
        finding = make_lfi_finding()
        finding.impact = ""
        verdict = validate_finding(
            finding,
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome(
                    "matched", "reproduction_marker_matched:file_content_leak"
                )
            ),
        )
        assert verdict.state == VerdictState.NEEDS_MORE
        assert verdict.reason == "missing_impact"
