"""
Finding Validator - 証拠品質ゲート + 共有ハイブリッド確定判定モジュール

レガシー API（インスタンス validate / validate_batch / ValidationResult /
REQUIRED_EVIDENCE_KEYS / RECOMMENDED_EVIDENCE_KEYS / get_validator）は
SGK-2026-0441 以前の動作を byte-identical に温存する（manager.py の
_finding_validator.validate 配線と funnel ゲート reason_code
finding_validator_rejected が依存するため）。

SGK-2026-0443 T1 で追加するハイブリッド確定判定（evaluate /
validate_finding / validate_findings / PoCJudge）は、どの swarm /
サブエージェントからも呼べる共有契約として整備した:

- 機械フロア evaluate_payout_grade（SGK-2026-0441・決定的・fail-closed・
  LLM なし）を必須ゲートとし、AI 判断（poc_judge role）と再現裏取り
  （T3 で実送信を配線予定・T1 は NoopReproductionChecker スタブ）を合成して
  rich verdict（VerdictState / reason / evidence_refs / promise_score）を返す。
- 本モジュールの hybrid `confirmed` は swarm 経路の助言的確定であり、
  canonical な署名付き確定ではない。VdpEvidenceValidator は無変更・独立
  （本モジュールから import しない）。reporting / gate は hybrid confirmed を
  canonical として扱ってはならない。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Literal, Optional, Protocol, Set

if TYPE_CHECKING:
    from src.core.agents.swarm.injection.payout_grade import PayoutGradeResult


@dataclass
class ValidationResult:
    """検証結果"""
    reject: bool
    reason: Optional[str] = None
    missing_keys: Optional[Set[str]] = None


@dataclass
class FindingValidator:
    """
    Findingの証拠品質を検証するクラス
    
    アクション优先の判定ゲート:
    - thoughtのみのfindingは不採用
    - request/responseの実データが必要
    - 再送で再現可能であること
    
    SGK-2026-0443: ハイブリッド確定判定 `evaluate()` を追加（レガシー
    validate / validate_batch は無変更）。
    """
    
    # 必須証拠キー
    REQUIRED_EVIDENCE_KEYS: Set[str] = field(
        default_factory=lambda: {
            "request_url",
            "response_status",
            "response_body_sample"
        }
    )
    
    # 推奨証拠キー（警告用）
    RECOMMENDED_EVIDENCE_KEYS: Set[str] = field(
        default_factory=lambda: {
            "request_headers",
            "response_headers",
            "request_payload",
            "response_time_ms",
            "evidence_timestamp"
        }
    )
    
    def validate(self, finding: Any) -> ValidationResult:
        """
        Findingの検証
        
        Args:
            finding: Findingオブジェクトまたは類似のdataclass
            
        Returns:
            ValidationResult: reject=Trueで不採用、reasonで理由を返す
        """
        # thought-onlyチェック
        if not hasattr(finding, 'actions') or not finding.actions:
            return ValidationResult(
                reject=True,
                reason="thought-only",
                missing_keys=None
            )
        
        # メタデータチェック
        if not hasattr(finding, 'metadata') or not finding.metadata:
            return ValidationResult(
                reject=True,
                reason="missing_metadata",
                missing_keys=self.REQUIRED_EVIDENCE_KEYS
            )
        
        # 必須キーの存在確認
        metadata_keys = set(finding.metadata.keys())
        missing_required = self.REQUIRED_EVIDENCE_KEYS - metadata_keys
        
        if missing_required:
            return ValidationResult(
                reject=True,
                reason="insufficient_evidence",
                missing_keys=missing_required
            )
        
        # 推奨キーの欠落確認（警告のみ、不採用にはしない）
        missing_recommended = self.RECOMMENDED_EVIDENCE_KEYS - metadata_keys
        if missing_recommended:
            # 警告ログは呼び出し側で出力
            pass
        
        return ValidationResult(reject=False)
    
    def validate_batch(self, findings: list) -> tuple:
        """
        複数findingのバッチ検証
        
        Args:
            findings: Findingオブジェクトのリスト
            
        Returns:
            (valid_findings, rejected_findings): 採用/不採用の分離結果
        """
        valid = []
        rejected = []
        
        for finding in findings:
            result = self.validate(finding)
            if result.reject:
                rejected.append((finding, result))
            else:
                valid.append(finding)
        
        return valid, rejected
    
    def evaluate(
        self,
        finding: Any,
        *,
        ai_judge: Optional[Any] = None,
        reproduction_checker: Optional[Any] = None,
    ) -> "HybridVerdict":
        """SGK-2026-0443: ハイブリッド確定判定（状態遷移表・優先順位順に評価）。

        - 機械フロア evaluate_payout_grade は決してバイパスしない（確認の
          敷居を下げない）。AI 発言は機械フロア不足を上書きできない。
        - ai_judge: ``judge(finding) -> AiJudgement`` を持つ任意オブジェクト
          （duck-typed。デフォルト None = AI 未実行）。
        - reproduction_checker: ``check(finding) -> ReproductionOutcome`` を
          持つ任意オブジェクト。デフォルト NoopReproductionChecker()
          （T1 では confirmed は到達不能）。
        - ai_judge.judge の例外は握りつぶさず伝播させる（fail-closed。
          T2 の配線側で catch する）。
        """
        from src.core.agents.swarm.injection.payout_grade import (
            evaluate_payout_grade,
            finding_payload,
            has_explicit_refute_signal,
        )

        floor = evaluate_payout_grade(finding_payload(finding))
        checker = (
            reproduction_checker
            if reproduction_checker is not None
            else NoopReproductionChecker()
        )
        # AI / 再現チェックは最初に消費する分岐の直前で実行する（ora-1）:
        # 短絡規則より先に LLM 呼び出し・再送が走ると、refuted / needs_more
        # 判定を LLM 例外が覆い隠してしまうため。早期退出 verdict では
        # 未実施のまま（ai=None / reproduction=not_run・
        # reason=reproduction_not_performed）として fail-closed に保つ。
        ai: Optional[AiJudgement] = None
        repro: Optional[ReproductionOutcome] = None

        def verdict(state: VerdictState, reason: str) -> "HybridVerdict":
            return HybridVerdict(
                state=state,
                reason=reason,
                mechanical_floor=floor,
                ai_judgement=ai,
                reproduction=(
                    repro
                    if repro is not None
                    else ReproductionOutcome(
                        "not_run", "reproduction_not_performed"
                    )
                ),
                evidence_refs=self._union_evidence_refs(floor, ai),
                promise_score=self._promise_score(floor, ai, repro),
            )

        # 1) 明確な反証シグナル（フロア・AI と無関係に最優先）
        if has_explicit_refute_signal(finding):
            return verdict(VerdictState.REFUTED, "explicit_refute_signal")
        # 2) AI 反証（証拠内の矛盾実測）
        if ai_judge is not None:
            ai = ai_judge.judge(finding)
        if ai is not None and ai.counter_evidence:
            return verdict(VerdictState.REFUTED, "ai_counter_evidence")
        # 3) 機械フロア不足（AI 発言は上書き不可・フロア reason をパススルー）
        if not floor.payout_grade:
            return verdict(VerdictState.NEEDS_MORE, floor.reason)
        # 4) AI 未実行
        if ai is None:
            return verdict(VerdictState.NEEDS_MORE, "ai_judgement_pending")
        # 5) AI が人間判定を要求
        if ai.needs_human:
            return verdict(VerdictState.NEEDS_HUMAN, "ai_needs_human")
        # 6) AI 賞金級でない（反証なし → 棚上げ・却下はしない）
        if not ai.payout_grade:
            return verdict(VerdictState.INCONCLUSIVE, "ai_no_prize_grade")
        # 7) 再現裏取り（最初に消費する分岐の直前で実行）
        if repro is None:
            repro = checker.check(finding)
        assert repro is not None  # rule 7 で必ず計算済み
        if repro.status == "not_run":
            return verdict(VerdictState.NEEDS_MORE, "reproduction_pending")
        # 8) 再現不一致 → 却下
        if repro.status == "mismatched":
            return verdict(VerdictState.REFUTED, "reproduction_mismatch")
        # 9) 再現一致 → 確定（3条件AND）
        if repro.status == "matched":
            return verdict(VerdictState.CONFIRMED, "hybrid_confirmed")
        # 予期しない再現ステータス: fail closed
        return verdict(VerdictState.NEEDS_MORE, "reproduction_pending")

    @staticmethod
    def _union_evidence_refs(floor: Any, ai: Optional["AiJudgement"]) -> tuple:
        """evidence_refs の順序保持ユニオン（フロア refs + AI refs・重複除去）。
        フィールド名のみを保持し、値を保持しない。"""
        refs: list = list(getattr(floor, "evidence_refs", None) or [])
        if ai is not None:
            refs.extend(list(getattr(ai, "evidence_refs", None) or ()))
        seen: Set[str] = set()
        ordered = []
        for ref in refs:
            if ref not in seen:
                seen.add(ref)
                ordered.append(ref)
        return tuple(ordered)

    @staticmethod
    def _promise_score(floor: Any, ai: Optional["AiJudgement"], repro: Any) -> float:
        """満たしたゲート数 / 3（参考のみ・確定をゲートしない）。"""
        return (
            int(bool(getattr(floor, "payout_grade", False)))
            + (0 if ai is None else int(bool(ai.payout_grade)))
            + int(getattr(repro, "status", None) == "matched")
        ) / 3.0


class VerdictState(Enum):
    CONFIRMED = "confirmed"        # 確定
    REFUTED = "refuted"            # 却下
    NEEDS_MORE = "needs_more"      # 継続
    INCONCLUSIVE = "inconclusive"  # 棚上げ
    NEEDS_HUMAN = "needs_human"    # 人間送り


@dataclass(frozen=True)
class AiJudgement:
    """poc_judge パース結果（reason は構築時に pii_masker でマスク済み）。"""
    payout_grade: bool        # 賞金級
    is_real: bool
    has_actual_impact: bool
    counter_evidence: bool    # 明確な反証（証拠内の矛盾実測）のみ true
    needs_human: bool
    evidence_refs: tuple[str, ...] = ()
    markers: tuple[str, ...] = ()
    reason_masked: str = ""


@dataclass(frozen=True)
class ReproductionOutcome:
    status: Literal["not_run", "matched", "mismatched"]
    reason: str


class ReproductionChecker(Protocol):
    def check(self, finding: Any) -> ReproductionOutcome: ...


class NoopReproductionChecker:
    """T1 stub; real resend wiring is T3. Never satisfies the reproduction
    gate (threshold must not be lowered)."""

    def check(self, finding: Any) -> ReproductionOutcome:
        return ReproductionOutcome("not_run", "reproduction_wiring_t3")


@dataclass(frozen=True)
class HybridVerdict:
    state: VerdictState
    reason: str                        # 安定コード（語彙表）
    mechanical_floor: "PayoutGradeResult"  # TYPE_CHECKING 型・0441 無改変で保持
    ai_judgement: Optional[AiJudgement]
    reproduction: ReproductionOutcome
    evidence_refs: tuple[str, ...]     # フィールド名のみ・値を保持しない
    promise_score: float               # 満たしたゲート数/3・参考のみ・確定をゲートしない


# グローバルインスタンス（シングルトン風）
_default_validator: Optional[FindingValidator] = None


def get_validator() -> FindingValidator:
    """デフォルトバリデータ取得"""
    global _default_validator
    if _default_validator is None:
        _default_validator = FindingValidator()
    return _default_validator


def validate_finding(
    finding: Any,
    *,
    ai_judge: Optional[Any] = None,
    reproduction_checker: Optional[Any] = None,
) -> HybridVerdict:
    """SGK-2026-0443: 共有ハイブリッド確定判定（単一 finding）。

    全 swarm 向け共通契約。旧契約（validator 引数・ValidationResult 返却）は
    生産呼び出し0のため新契約へ変更した。レガシー検証はインスタンス
    ``FindingValidator().validate()`` を利用すること。
    """
    validator = get_validator()
    return validator.evaluate(
        finding,
        ai_judge=ai_judge,
        reproduction_checker=reproduction_checker,
    )


def validate_findings(
    findings: list,
    *,
    ai_judge: Optional[Any] = None,
    reproduction_checker: Optional[Any] = None,
) -> list:
    """SGK-2026-0443: 共有ハイブリッド確定判定（バッチ・入力順を維持）。"""
    validator = get_validator()
    return [
        validator.evaluate(
            finding,
            ai_judge=ai_judge,
            reproduction_checker=reproduction_checker,
        )
        for finding in findings
    ]


class PoCJudge:
    """poc_judge role LLM アダプタ。製品非依存プロンプト:
    src/prompts/roles/poc_judge.md（LLMClient が role の system prompt を自動注入）。

    Masking: AI reason は構築時に pii_masker でマスクする（write 境界で
    redact。生値を verdict 経路に残さない）。
    """

    _BOOL_FIELDS = (
        "payout_grade",
        "is_real",
        "has_actual_impact",
        "counter_evidence",
        "needs_human",
    )

    def __init__(self, client: Optional[Any] = None):
        # client: LLMClient ライク（generate(messages) を持つ）。循環 import
        # 回避のため LLMClient は遅延 import（thought_loop.py:166 と同型）。
        if client is None:
            from src.core.models.llm import LLMClient
            client = LLMClient(role="poc_judge")
        self._client = client

    def judge(self, finding: Any) -> AiJudgement:
        """finding を判定し、マスク済み reason を持つ AiJudgement を返す。

        FAIL-CLOSED: LLM 応答が JSON として解釈できない・必須フィールドが
        欠落・型不正の場合は ValueError を送出する（判定を捏造しない）。
        """
        from src.core.agents.swarm.injection.payout_grade import finding_payload
        from src.core.security.pii_masker import get_pii_masker

        payload = finding_payload(finding)
        user_content = self._build_user_payload(payload)
        response = self._client.generate([{"role": "user", "content": user_content}])
        content = self._extract_content(response)
        data = self._parse_json_response(content)
        fields = self._extract_fields(data)

        # マスク境界（write 境界で redact・ora-1）。マスク失敗時は伝播させ、
        # マスクされていない値を verdict 経路に載せない。reason だけでなく
        # evidence_refs / markers の各要素もマスクする（秘密境界の教訓:
        # ネスト list も走査し、callsite バイパスを防ぐ）。
        masker = get_pii_masker()
        reason_masked = masker.mask(fields["reason"]).masked
        evidence_refs_masked = tuple(
            masker.mask(ref).masked for ref in fields["evidence_refs"]
        )
        markers_masked = tuple(
            masker.mask(marker).masked for marker in fields["markers"]
        )

        return AiJudgement(
            payout_grade=fields["payout_grade"],
            is_real=fields["is_real"],
            has_actual_impact=fields["has_actual_impact"],
            counter_evidence=fields["counter_evidence"],
            needs_human=fields["needs_human"],
            evidence_refs=evidence_refs_masked,
            markers=markers_masked,
            reason_masked=reason_masked,
        )

    @staticmethod
    def _build_user_payload(payload: dict) -> str:
        """判定用ユーザーメッセージ。生証拠（再現 req/res・発火印・impact・
        再現手順）だけを渡し、期待答え・製品名・「本物」ヒントは含めない
        （カーブフィッティング禁止・判断は judge 側に委ねる）。"""
        evidence = payload.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        info = payload.get("additional_info")
        if not isinstance(info, dict):
            info = {}
        browser_execution = info.get("browser_execution")
        user_data = {
            "vuln_type": payload.get("vuln_type"),
            "evidence": {
                "request_method": evidence.get("request_method"),
                "request_url": evidence.get("request_url"),
                "response_status": evidence.get("response_status"),
                "response_body": evidence.get("response_body"),
            },
            "poc_request": info.get("poc_request"),
            "poc_response": info.get("poc_response"),
            "impact": payload.get("impact"),
            "reproduction_steps": payload.get("reproduction_steps"),
            # SGK-2026-0455 C3(b): 実発火証拠（browser_execution）を judge に
            # 可視化。事実サブフィールドのみを写像し、期待答え・製品名・
            # 「本物」等のヒントは含めない（カーブフィッティング禁止）。
            # dict でなければ None（証拠なしを捏造しない・fail-closed）。
            "browser_execution": (
                {
                    "executor": browser_execution.get("executor"),
                    "event": browser_execution.get("event"),
                    "variant": browser_execution.get("variant"),
                    "dom_mutation_observed": browser_execution.get(
                        "dom_mutation_observed"
                    ),
                    "dialog_observed": browser_execution.get("dialog_observed"),
                    "test_url": browser_execution.get("test_url"),
                }
                if isinstance(browser_execution, dict)
                else None
            ),
        }
        return json.dumps(user_data, ensure_ascii=False, indent=2)

    @staticmethod
    def _extract_content(response: Any) -> str:
        """LLM 応答オブジェクト（dict / DictToObject / str）から本文を抽出。"""
        if isinstance(response, str):
            return response
        if not hasattr(response, "get"):
            raise ValueError("PoCJudge: unexpected LLM response shape (no .get)")
        content = (response.get("choices") or [{}])[0].get("message", {}).get("content", "")
        if not isinstance(content, str):
            raise ValueError("PoCJudge: LLM response content is not a string")
        return content

    @staticmethod
    def _parse_json_response(content: str) -> dict:
        """JSON のみ出力契約のパース。パース不能は ValueError（fail-closed）。"""
        text = (content or "").strip()
        if not text:
            raise ValueError("PoCJudge: empty LLM response, expected a JSON object")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # 実運用でモデルが JSON をコードフェンスで包むことがあるため、
            # フェンス内のみ再試行する（捏造はしない）。
            fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
            if fenced is None:
                raise ValueError("PoCJudge: LLM response is not valid JSON")
            try:
                data = json.loads(fenced.group(1).strip())
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"PoCJudge: LLM response is not valid JSON: {exc}"
                ) from exc
        if not isinstance(data, dict):
            raise ValueError("PoCJudge: LLM response JSON is not an object")
        return data

    @classmethod
    def _extract_fields(cls, data: dict) -> dict:
        """必須フィールドの型検証（欠落・型不正は ValueError・fail-closed）。"""
        fields = {}
        for key in cls._BOOL_FIELDS:
            value = data.get(key)
            if not isinstance(value, bool):
                raise ValueError(
                    f"PoCJudge: malformed judgement — '{key}' must be a boolean"
                )
            fields[key] = value
        reason = data.get("reason")
        if not isinstance(reason, str):
            raise ValueError("PoCJudge: malformed judgement — 'reason' must be a string")
        fields["reason"] = reason
        for key in ("evidence_refs", "markers"):
            value = data.get(key)
            if not isinstance(value, list) or not all(
                isinstance(item, str) for item in value
            ):
                raise ValueError(
                    f"PoCJudge: malformed judgement — '{key}' must be a list of strings"
                )
            fields[key] = value
        return fields
