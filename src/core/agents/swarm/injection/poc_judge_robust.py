"""SGK-2026-0461 Option B — poc_judge 実運用頑健化ラッパー（バー無改変）。

凍結バー（poc_judge.md / finding_validator.py）の判定・閾値は一切変えず、
LLM 応答の取り扱いだけを頑健化する:
- per-call タイムアウト強制（11分ループ防止）
- JSON 救済パース（コードフェンス / 前後散文 / 先頭JSONオブジェクト抽出）
- パース失敗時のみのバウンド付きリトライ（正当な却下は決して再試行しない）
fail-closed: 全試行失敗は ValueError（既存契約どおり wiring が ai_judge=None
へ写像 → needs_more。決して confirmed を偽装しない）。
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

# per-call タイムアウト上限（LLM generate 1 回の硬上限）。注入された judge は
# この値以下に clamp されるため、11分ループのような長期ブロックを防ぐ。
DEFAULT_TIMEOUT_SECONDS: float = 90.0


def _balanced_object_end(text: str, start: int) -> int:
    """先頭 '{' から対になる '}' の位置まで走査する（文字列・エスケープを
    最小限に尊重する単純な char スキャン）。閉じられない文字列や未完了の
    オブジェクトは保守的に -1（救済しない）。"""
    depth = 0
    in_string = False
    escaped = False
    i = start
    n = len(text)
    while i < n:
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def _strip_fences(text: str) -> str:
    """コードフェンス区切り（```json / ```）だけを除去し、本文を残す。

    前後の散文・補足を保存したままフェンスを外すことで、JSON オブジェクト
    の位置を壊さずに後続の先頭 '{' 探索へ渡す。"""
    return re.sub(r"```(?:json)?\s*", "", text)


def _salvage_json_object(text: Any) -> Optional[str]:
    """LLM 本文から ``json.loads`` で必ずパース可能な JSON オブジェクト文字列を
    返す（捏造なし）。見つからなければ None。

    アルゴリズム（純粋・no fabrication）:
    1. strip して全体を json.loads → dict ならその json.dumps を返す。
    2. コードフェンス（```json ... ``` / ``` ... ```）を除去。
    3. 先頭 '{' を探し、ブレース深さカウンタで対になる '}' を走査
       （文字列・エスケープを最小限に尊重。未閉じクォートは保守的に失敗）。
    4. 抽出した区間を json.loads → dict なら抽出文字列を返す。
    例外は全て None（best-effort・fail-closed は凍結 PoCJudge 側が担う）。
    """
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped:
        return None
    try:
        data = json.loads(stripped)
    except Exception:  # noqa: BLE001 — salvage is best-effort
        data = None
    if isinstance(data, dict):
        try:
            return json.dumps(data, ensure_ascii=False)
        except Exception:  # noqa: BLE001 — non-serializable dict -> raw text
            return stripped
    candidate = _strip_fences(stripped)
    start = candidate.find("{")
    if start == -1:
        return None
    end = _balanced_object_end(candidate, start)
    if end == -1:
        return None
    extracted = candidate[start : end + 1]
    try:
        data = json.loads(extracted)
    except Exception:  # noqa: BLE001 — salvage is best-effort
        return None
    if isinstance(data, dict):
        return extracted
    return None


class _BoundedLLMClient:
    """inner LLMClient を per-call タイムアウト + JSON 救済で包む薄いラッパー。

    - ``generate`` の timeout を ``DEFAULT_TIMEOUT_SECONDS`` に clamp。
    - 応答が str なら救済結果（見つからなければ原文のまま）。
    - 応答が dict なら PoCJudge._extract_content と同じ取り出し方で content を
      救済し、異なる文字列が得られた場合のみ plain dict で包み直す。
    - ここでは絶対に raise しない（best-effort。凍結 PoCJudge が自前の
      パースと fail-closed を適用する）。
    """

    def __init__(self, inner: Any, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        self._inner = inner
        self._timeout_seconds = float(timeout_seconds)

    def generate(self, messages: list, **kwargs: Any) -> Any:
        kwargs = dict(kwargs)
        kwargs["timeout"] = min(
            float(kwargs.get("timeout") or self._timeout_seconds),
            self._timeout_seconds,
        )
        response = self._inner.generate(messages, **kwargs)
        try:
            if isinstance(response, str):
                salvaged = _salvage_json_object(response)
                return salvaged if salvaged is not None else response
            if not hasattr(response, "get"):
                return response
            content = (response.get("choices") or [{}])[0].get("message", {}).get("content", "")
            if isinstance(content, str):
                salvaged = _salvage_json_object(content)
                if salvaged is not None and salvaged != content:
                    return {"choices": [{"message": {"content": salvaged}}]}
            return response
        except Exception:  # noqa: BLE001 — best-effort, never raise here
            return response


class RobustPoCJudge:
    """PoCJudge 互換の頑健化ラッパー（判定・閾値は一切変更しない）。

    - inner 未注入時は ``PoCJudge(client=_BoundedLLMClient(LLMClient(
      role="poc_judge")))`` を遅延構築する。
    - ``judge`` は ``max_attempts`` 回まで再試行するが、リトライ対象は
      ValueError（LLM 応答のパース不能）のみ。正当な却下（payout_grade
      =false の AiJudgement）は raise しないため決して再試行しない。
    - 全試行失敗は ValueError で終端（既存契約どおり wiring が ai_judge=None
      へ写像 → needs_more。confirmed を偽装しない）。
    """

    def __init__(
        self,
        inner: Optional[Any] = None,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_attempts: int = 2,
    ) -> None:
        if inner is None:
            # 循環回避のため遅延 import（validation <=> injection の import ループ）
            from src.core.models.llm import LLMClient
            from src.core.validation.finding_validator import PoCJudge

            inner = PoCJudge(
                client=_BoundedLLMClient(
                    LLMClient(role="poc_judge"),
                    timeout_seconds=timeout_seconds,
                )
            )
        self._inner = inner
        self._max_attempts = max(1, int(max_attempts))

    def judge(self, finding: Any) -> Any:
        last_exc: Optional[Exception] = None
        for _ in range(self._max_attempts):
            try:
                return self._inner.judge(finding)
            except ValueError as exc:
                last_exc = exc
                logger.warning(
                    "PoCJudge: judgement parse failed for finding %s; "
                    "robust salvage + bounded retry",
                    getattr(finding, "id", "?"),
                )
        raise ValueError(
            f"PoCJudge: judgement failed after {self._max_attempts} attempts "
            "(robust parse + retry exhausted)"
        ) from last_exc
