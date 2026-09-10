"""
SGK-2026-0480 — unrestricted file upload（任意ファイル設置＋Web 取得）の本物確定
（CONFIRMED / hybrid_confirmed）統合テスト

finding_validator.validate_finding に以下を与えると CONFIRMED に到達する
ことを検証する（確定バーの敷居は下げない・3 条件 AND は不変）:

- 機械フロア: 本物の設置＋取得証跡（real evaluate_payout_grade が
  marker=uploaded_file_retrieved / payout_grade=True を返す Finding 形状）
- AI 賞金級: payout_grade=true を返すスタブ ai_judge
- 再現: 実 SealedReproductionChecker + FakeNetworkClient
  （file_upload_evidence.retrieval_url への純 GET 再読 → 一意マーカー再出現）

PRODUCT-INDEPENDENT fixtures のみ（target.example・汎用良性マーカー）。
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
    program_name="file-upload-confirm-test",
    in_scope_domains=["target.example"],
)

UPLOAD_URL = "https://target.example/upload"
RETRIEVAL_URL = "https://target.example/uploads/probe_a1b2c3d4e5f60718.txt"
MARKER = "SHIGOKU_PROBE_a1b2c3d4e5f60718"


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


def make_upload_finding() -> Finding:
    """FileUploadSpecialist（retrieved＋retrieval_marker 確定時・SGK-2026-0480）
    が生成する Finding 形状。impact/reproduction_steps/file_upload_evidence
    完備。"""
    return Finding(
        vuln_type=VulnType.FILE_UPLOAD,
        severity=Severity.HIGH,
        title="Unrestricted File Upload: Safe Canary Upload Probe",
        description="Uploaded a benign non-executable file and retrieved it via Web.",
        target_url=UPLOAD_URL,
        evidence=Evidence(
            request_method="POST",
            request_url=UPLOAD_URL,
            request_headers={"Cookie": "session=abc123"},
            response_status=200,
            response_body=(
                "Status: 200\n"
                f"Evidence: retrieved at {RETRIEVAL_URL}\n\n"
                f"Retrieval URL: {RETRIEVAL_URL}\n"
                "Retrieval Status: 200\n"
                f"Retrieval Marker: {MARKER}\n"
                f"Retrieval Body Excerpt: stored {MARKER}"
            ),
        ),
        reproduction_steps=[
            "Upload a benign file carrying a unique per-run marker.",
            "GET the retrieval URL from the upload response.",
            "Observe the same unique marker in the GET response body.",
        ],
        impact=(
            "認証境界内で任意の非実行ファイルをサーバへ設置し、"
            "Web から取得できる。悪性ファイル設置・保存型攻撃・"
            "情報設置の起点になり得る。"
        ),
        additional_info={
            "file_upload_evidence": {
                "upload_allowed": True,
                "retrieved": True,
                "retrieval_url": RETRIEVAL_URL,
                "retrieval_status": 200,
                "retrieval_marker": MARKER,
                "execution_observed": False,
                "safe_canary": True,
                "mime_type": "image/jpeg",
                "technique": "Safe Canary Upload Probe",
            },
            "payload": "probe_a1b2c3d4e5f60718.jpg",
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
        markers=("uploaded_file_retrieved",),
        reason_masked="",
    )


class TestFileUploadHybridConfirmation:
    def test_real_floor_plus_ai_prize_plus_matched_repro_confirms(self) -> None:
        """3 条件 AND（real 機械フロア uploaded_file_retrieved + AI 賞金級 +
        再現 matched）→ CONFIRMED / hybrid_confirmed。"""
        verdict = validate_finding(
            make_upload_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome(
                    "matched", "reproduction_marker_matched:uploaded_file_retrieved"
                )
            ),
        )
        assert verdict.state == VerdictState.CONFIRMED
        assert verdict.reason == "hybrid_confirmed"
        assert verdict.mechanical_floor.payout_grade is True
        assert verdict.mechanical_floor.marker == "uploaded_file_retrieved"
        assert verdict.promise_score == 1.0

    def test_real_sealed_checker_get_replay_confirms(self) -> None:
        """実 SealedReproductionChecker（A⑤）+ FakeNetworkClient の
        retrieval_url 純 GET 再読 → 一意マーカー再出現でも CONFIRMED に
        到達する（アップロード POST は再送されず、GET のみ）。"""
        client = FakeNetworkClient(FakeResponse(200, f"stored file: {MARKER}"))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        verdict = validate_finding(
            make_upload_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=checker,
        )
        assert verdict.state == VerdictState.CONFIRMED
        assert verdict.reason == "hybrid_confirmed"
        assert (
            verdict.reproduction.reason
            == "reproduction_marker_matched:uploaded_file_retrieved"
        )
        # 封印再送は retrieval_url への GET のみ（POST 再送・実行はしない）。
        assert len(client.calls) == 1
        assert client.calls[0]["method"] == "GET"
        assert client.calls[0]["url"] == RETRIEVAL_URL

    def test_repro_mismatch_refutes(self) -> None:
        """再現 mismatched（応答あり・マーカー非再出現）は従来どおり REFUTED
        （敷居を下げない）。"""
        verdict = validate_finding(
            make_upload_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome("mismatched", "reproduction_marker_mismatch")
            ),
        )
        assert verdict.state == VerdictState.REFUTED
        assert verdict.reason == "reproduction_mismatch"

    def test_floor_gap_still_needs_more(self) -> None:
        """機械フロアが通らない証跡（impact 空）は AI 発言でも
        上書きされない。"""
        finding = make_upload_finding()
        finding.impact = ""
        verdict = validate_finding(
            finding,
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome(
                    "matched", "reproduction_marker_matched:uploaded_file_retrieved"
                )
            ),
        )
        assert verdict.state == VerdictState.NEEDS_MORE
        assert verdict.reason == "missing_impact"
