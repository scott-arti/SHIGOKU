"""
SGK-2026-0478 — in-band OS コマンド実行の本物確定（CONFIRMED / hybrid_confirmed）
統合テスト

finding_validator.validate_finding に以下を与えると CONFIRMED に到達する
ことを検証する（確定バーの敷居は下げない・3 条件 AND は不変）:

- 機械フロア: 本物の in-band コマンド実行証跡（real evaluate_payout_grade が
  marker=command_execution / payout_grade=True を返す POST Finding 形状）
- AI 賞金級: payout_grade=true を返すスタブ ai_judge
- 再現: matched スタブ、および実 SealedReproductionChecker +
  FakeNetworkClient（command_replay の POST 再送 → uid= 再出現）の両方

PRODUCT-INDEPENDENT fixtures のみ（target.example・汎用コマンド id）。
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
    program_name="cmd-confirm-test",
    in_scope_domains=["target.example"],
)

CMD_URL = "https://target.example/exec/"
BODY_PARAMS = {"ip": "127.0.0.1;id", "Submit": "Submit"}
# _CMD_INDICATORS（uid= 等）を含む in-band 応答（id の出力）。
CMD_BODY = (
    "PING 127.0.0.1 (127.0.0.1): 56 data bytes\n"
    "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
    "--- 127.0.0.1 ping statistics ---"
)
NO_CMD_BODY = "<html><body>host appears to be down</body></html>"


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


def make_cmd_finding() -> Finding:
    """SmartCmdSSRFHunter（POST in-band 確定・SGK-2026-0478）が生成する
    Finding 形状。command_replay 記述子（読み取り専用コマンド id）付き。"""
    return Finding(
        vuln_type=VulnType.OS_COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        title="Command Injection/SSRF in parameter 'ip'",
        description="Command Injection/SSRF detected.",
        target_url=CMD_URL,
        evidence=Evidence(
            request_method="POST",
            request_url=CMD_URL,
            request_headers={"Cookie": "session=abc123"},
            response_status=200,
            response_body=CMD_BODY,
        ),
        reproduction_steps=[
            "対象フォームのパラメータ 'ip' を method=POST で送信する（認証セッションを使用）。",
            "パラメータ値に読み取り専用コマンドを注入する: 127.0.0.1;id",
            "応答本文に OS コマンド出力の指標（uid= 等）が返ることを確認する。",
        ],
        impact=(
            "注入パラメータ経由で任意 OS コマンドを実行可能。"
            "サーバ完全掌握(RCE)の起点。"
        ),
        additional_info={
            "parameter": "ip",
            "tested_params": ["ip"],
            "payload": "127.0.0.1;id",
            "command_replay": {
                "method": "POST",
                "url": CMD_URL,
                "body_params": dict(BODY_PARAMS),
                "readonly_command": "id",
                "content_type": "application/x-www-form-urlencoded",
            },
            "command_execution_evidence": {
                "output_observed": True,
                "payload": "127.0.0.1;id",
                "command_output": CMD_BODY,
                "response_status": 200,
            },
            "poc_request": (
                f"POST /exec/ HTTP/1.1\nHost: target.example\n\n"
                f"ip=127.0.0.1%3Bid&Submit=Submit"
            ),
            "poc_response": f"HTTP/1.1 200\n\n{CMD_BODY}",
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
        markers=("command_execution",),
        reason_masked="",
    )


class TestCmdExecutionHybridConfirmation:
    def test_real_floor_plus_ai_prize_plus_matched_repro_confirms(self) -> None:
        """3 条件 AND（real 機械フロア command_execution + AI 賞金級 +
        再現 matched）→ CONFIRMED / hybrid_confirmed。"""
        verdict = validate_finding(
            make_cmd_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome(
                    "matched", "reproduction_marker_matched:command_execution"
                )
            ),
        )
        assert verdict.state == VerdictState.CONFIRMED
        assert verdict.reason == "hybrid_confirmed"
        # 機械フロアが実コード経由で in-band コマンド実行を通過している。
        assert verdict.mechanical_floor.payout_grade is True
        assert verdict.mechanical_floor.marker == "command_execution"
        assert verdict.promise_score == 1.0

    def test_real_sealed_checker_post_replay_confirms(self) -> None:
        """実 SealedReproductionChecker（A②）+ FakeNetworkClient の
        command_replay POST 再送 → uid= 再出現でも CONFIRMED に到達する
        （スタブ checker 不使用・GET ではなく POST が再送される）。"""
        client = FakeNetworkClient(FakeResponse(200, CMD_BODY))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        verdict = validate_finding(
            make_cmd_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=checker,
        )
        assert verdict.state == VerdictState.CONFIRMED
        assert verdict.reason == "hybrid_confirmed"
        assert (
            verdict.reproduction.reason
            == "reproduction_marker_matched:command_execution"
        )
        # 封印再送は元 method=POST・元フォーム値（body_params）で行われる。
        assert client.calls[0]["method"] == "POST"
        assert client.calls[0]["url"] == CMD_URL
        assert client.calls[0]["kwargs"]["data"] == BODY_PARAMS

    def test_repro_mismatch_refutes(self) -> None:
        """再現 mismatched（応答あり・uid= 非再出現）は従来どおり REFUTED
        （敷居を下げない）。"""
        verdict = validate_finding(
            make_cmd_finding(),
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome("mismatched", "reproduction_marker_mismatch")
            ),
        )
        assert verdict.state == VerdictState.REFUTED
        assert verdict.reason == "reproduction_mismatch"

    def test_floor_gap_still_needs_more(self) -> None:
        """機械フロアが通らない証跡（impact 空）は AI 発言でも上書きされない。"""
        finding = make_cmd_finding()
        finding.impact = ""
        verdict = validate_finding(
            finding,
            ai_judge=FakeJudge(_prize_judgement()),
            reproduction_checker=FakeRepro(
                ReproductionOutcome(
                    "matched", "reproduction_marker_matched:command_execution"
                )
            ),
        )
        assert verdict.state == VerdictState.NEEDS_MORE
        assert verdict.reason == "missing_impact"
