"""
SGK-2026-0481 — アップロード経由の保存型XSS（ブラウザ実行）の本物確定
（CONFIRMED / hybrid_confirmed）統合テスト。

finding_validator.validate_finding に以下を与えると CONFIRMED に到達することを
検証する（確定バーの敷居は下げない・3 条件 AND は不変）:

- 機械フロア: xss + additional_info.browser_execution.dialog_observed=True
  （real evaluate_payout_grade が marker=reflected_payload / payout_grade=True）
- AI 賞金級: payout_grade=true を返すスタブ ai_judge
- 再現: 実 SealedReproductionChecker が browser_execution.test_url を実ブラウザ
  再ロードし dialog 再観測（browser_validator はスタブ）→ matched

PRODUCT-INDEPENDENT fixtures のみ（target.example・汎用良性 XSS ペイロード）。
"""
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
    program_name="xss-upload-confirm-test",
    in_scope_domains=["target.example"],
)

TARGET_URL = "https://target.example/upload"
RETRIEVAL_URL = "https://target.example/uploads/probe_xss_a1b2c3d4e5f6.html"
NONCE = "sgka1b2c3d4e5f6"


class _FakeBrowserValidator:
    """PlaywrightValidator 互換スタブ（実ブラウザは起動しない）。"""

    is_available = True

    def __init__(self, fired: bool = True) -> None:
        self._fired = fired
        self.last_url = ""

    def validate_xss_sync(self, url, timeout=10.0, cookies=None):
        self.last_url = url
        return self._fired


class FakeJudge:
    def __init__(self, judgement: AiJudgement) -> None:
        self._judgement = judgement

    def judge(self, finding) -> AiJudgement:
        return self._judgement


class FakeRepro:
    def __init__(self, outcome: ReproductionOutcome) -> None:
        self._outcome = outcome

    def check(self, finding) -> ReproductionOutcome:
        return self._outcome


def make_xss_upload_finding() -> Finding:
    """FileUploadSpecialist の xss_via_upload 経路が生成する Finding 形状。"""
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.HIGH,
        title="Stored XSS via File Upload",
        description="Uploaded HTML is served and executed by the browser.",
        target_url=TARGET_URL,
        evidence=Evidence(
            request_method="GET",
            request_url=RETRIEVAL_URL,
            response_status=200,
            response_body=(
                "[Stored XSS via upload runtime execution]\n"
                f"test_url={RETRIEVAL_URL}\n"
                f"injected_nonce={NONCE}\n"
                f"observed_dialog_message={NONCE}\n"
                "nonce_match=True\n"
            ),
        ),
        reproduction_steps=[
            "Upload an HTML file",
            "Open the retrieval URL in a browser",
            "Observe the alert dialog",
        ],
        impact="Stored XSS: attacker script executes in the target origin.",
        additional_info={
            "browser_execution": {
                "dialog_observed": True,
                "executor": "playwright",
                "event": "stored_upload_browser_execution",
                "variant": "stored",
                "parameter": "uploaded",
                "payload": f"<html><body><img src=x onerror=alert('{NONCE}')></body></html>",
                "test_url": RETRIEVAL_URL,
                "nonce": NONCE,
                "observed_dialog_message": NONCE,
                "nonce_match": True,
            },
        },
    )


def _prize_judgement() -> AiJudgement:
    return AiJudgement(
        payout_grade=True,
        is_real=True,
        has_actual_impact=True,
        counter_evidence=False,
        needs_human=False,
        evidence_refs=("additional_info.browser_execution",),
        markers=("reflected_payload",),
        reason_masked="",
    )


class TestXssUploadHybridConfirmation:
    def test_real_floor_plus_ai_prize_plus_matched_repro_confirms(self) -> None:
        verdict = validate_finding(
            make_xss_upload_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome(
                    "matched", "reproduction_marker_matched:reflected_payload"
                )
            ),
        )
        assert verdict.state == VerdictState.CONFIRMED
        assert verdict.reason == "hybrid_confirmed"
        assert verdict.mechanical_floor.payout_grade is True
        assert verdict.mechanical_floor.marker == "reflected_payload"
        assert verdict.promise_score == 1.0

    def test_real_sealed_checker_browser_reload_confirms(self) -> None:
        """実 SealedReproductionChecker が test_url を実ブラウザ再ロードし
        dialog 再観測 → matched（browser_validator はスタブ）。"""
        validator = _FakeBrowserValidator(fired=True)
        checker = SealedReproductionChecker(
            browser_validator=validator,
            scope_definition=TARGET_SCOPE,
        )
        verdict = validate_finding(
            make_xss_upload_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=checker,
        )
        assert verdict.state == VerdictState.CONFIRMED
        assert verdict.reason == "hybrid_confirmed"
        assert verdict.reproduction.status == "matched"
        assert validator.last_url == RETRIEVAL_URL

    def test_sealed_checker_no_dialog_mismatches(self) -> None:
        checker = SealedReproductionChecker(
            browser_validator=_FakeBrowserValidator(fired=False),
            scope_definition=TARGET_SCOPE,
        )
        verdict = validate_finding(
            make_xss_upload_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=checker,
        )
        assert verdict.state == VerdictState.REFUTED
        assert verdict.reason == "reproduction_mismatch"

    def test_without_browser_execution_evidence_needs_more(self) -> None:
        """browser_execution を欠く xss 候補は発火マーカー無し → needs_more
        （AI 発言でも上書き不可・fail-closed）。"""
        finding = make_xss_upload_finding()
        finding.additional_info = {}
        verdict = validate_finding(
            finding,
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome("matched", "reproduction_marker_matched:x")
            ),
        )
        assert verdict.state == VerdictState.NEEDS_MORE
        assert verdict.reason == "no_firing_marker"
