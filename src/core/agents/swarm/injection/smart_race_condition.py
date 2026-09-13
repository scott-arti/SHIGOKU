"""
Smart Race Condition Hunter - TOCTOU レース 検出スペシャリスト (SGK-2026-0489)

check-then-act の間に窓がある処理へ**並列バースト**を撃つと、逐次では検証/ロックで
弾かれるはずのアクションが窓の中で実行される（TOCTOU）。本エンジンは一意マーカーを
使った**決定論的差分**で確定する：
  - 逐次コントロール（trigger→observe） → マーカー非反映（検証/ロックで弾かれる）
  - 並列バースト（trigger と observe を並列で複数ラウンド） → observe 応答にマーカー反映
両者の差分（並列でのみマーカーが出る）が「TOCTOU 窓で実行された」証拠になる。マーカーは
我々が選ぶ乱数トークンで、反映に出れば我々の注入アクションが窓で走った決定的証拠（偶然混入・
捏造不可）。シナリオ（trigger/observe/reset のテンプレ）は task 由来で、製品固有の URL/
ペイロードはハードコードしない。
"""
import asyncio
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

_MARKER_PREFIX = "SHIGOKU_RACE_"
_MARKER_PLACEHOLDER = "{marker}"
_RACE_SNIPPET_CAP = 1500
_RACE_FULL_CAP = 12000
_MAX_CONCURRENCY = 12
_MAX_ROUNDS = 40
_DEFAULT_CONCURRENCY = 8
_DEFAULT_ROUNDS = 25


def _subst_marker(params: Dict[str, Any], marker: str) -> Dict[str, Any]:
    """params の文字列値に含まれる ``{marker}`` を marker に置換したコピーを返す。"""
    out: Dict[str, Any] = {}
    for k, v in (params or {}).items():
        out[k] = v.replace(_MARKER_PLACEHOLDER, marker) if isinstance(v, str) else v
    return out


def _aligned_snippets(control_full: str, race_full: str, marker: str) -> Tuple[str, str]:
    """control と race のスニペットを**同一オフセット窓**で切り出して返す。

    race 本文でマーカーが出る位置を基準に、control も同じ窓を切る。両者は同一
    テンプレートなので、反映領域（例 ``<div id="system-message">``）が双方に含まれ、
    「同じ場所で control=既定値/race=マーカー」という差分が審査側で検証可能になる
    （先頭固定切り詰めだと別領域を見せてしまい差分が成立しない＝poc_judge の指摘）。
    """
    control_full = control_full or ""
    race_full = race_full or ""
    idx = race_full.find(marker)
    if idx < 0:
        return control_full[:_RACE_SNIPPET_CAP], race_full[:_RACE_SNIPPET_CAP]
    start = max(0, idx - _RACE_SNIPPET_CAP // 2)
    end = start + _RACE_SNIPPET_CAP
    return control_full[start:end], race_full[start:end]


class SmartRaceConditionHunter(Specialist):
    name = "SmartRaceConditionHunter"
    description = "Race condition (TOCTOU) detector (sequential-vs-concurrent differential)"
    timeout_seconds = 180
    is_aggressive = False

    def __init__(self, config: Dict = None):
        super().__init__()
        self.config = config or {}

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        result = await self._probe_race(task)
        if result is None:
            return []
        return [self._build_finding(task.target, result)]

    def _scenario(self, task: Task) -> Optional[Dict[str, Any]]:
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        trigger = params.get("race_trigger")
        observe = params.get("race_observe")
        if not (isinstance(trigger, dict) and isinstance(observe, dict)):
            return None
        if not (str(trigger.get("url") or "").strip() and str(observe.get("url") or "").strip()):
            return None
        concurrency = int(params.get("race_concurrency") or _DEFAULT_CONCURRENCY)
        rounds = int(params.get("race_rounds") or _DEFAULT_ROUNDS)
        return {
            "trigger": trigger,
            "observe": observe,
            "reset": params.get("race_reset") if isinstance(params.get("race_reset"), dict) else None,
            "concurrency": max(1, min(_MAX_CONCURRENCY, concurrency)),
            "rounds": max(1, min(_MAX_ROUNDS, rounds)),
            "auth_headers": self._auth_headers(task),
        }

    def _auth_headers(self, task: Task) -> Dict[str, str]:
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        _auth = params.get("_auth", {}) if isinstance(params.get("_auth"), dict) else {}
        headers = dict(_auth.get("auth_headers", {}) or {})
        cookies = str(_auth.get("cookies", "") or params.get("cookies", "") or "")
        if cookies and "Cookie" not in headers:
            headers["Cookie"] = cookies
        return headers

    async def _probe_race(self, task: Task) -> Optional[Dict[str, Any]]:
        sc = self._scenario(task)
        if sc is None:
            return None
        trigger, observe, reset = sc["trigger"], sc["observe"], sc["reset"]
        headers = sc["auth_headers"]
        marker = _MARKER_PREFIX + uuid.uuid4().hex[:12]

        # 逐次コントロール: reset → trigger(marker) → observe。検証/ロックで弾かれ
        # マーカーは observe 応答に出ないはず（出たら TOCTOU 差分にならない＝棄却）。
        try:
            if reset:
                await self._send(reset, marker, headers)
            await self._send(trigger, marker, headers)
            ctrl_status, ctrl_body = await self._send(observe, marker, headers)
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] control sequence failed: %s", self.name, exc)
            return None
        if marker in ctrl_body:
            # 逐次でも通る＝ロック/検証が無い（TOCTOU でなく単なる注入）→ 本エンジンでは非確定
            return None

        # 並列バースト: reset の後、trigger と observe を並列で複数ラウンド撃ち、
        # observe 応答にマーカーが出れば TOCTOU 窓で実行された証拠。
        try:
            if reset:
                await self._send(reset, marker, headers)
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] pre-burst reset failed: %s", self.name, exc)
        race_hit: Optional[Tuple[int, str]] = None
        for _ in range(sc["rounds"]):
            kinds: List[str] = []
            coros = []
            for _ in range(sc["concurrency"]):
                kinds.append("trigger")
                coros.append(self._send(trigger, marker, headers))
                kinds.append("observe")
                coros.append(self._send(observe, marker, headers))
            results = await asyncio.gather(*coros, return_exceptions=True)
            for kind, res in zip(kinds, results):
                if kind != "observe" or isinstance(res, Exception):
                    continue
                status, body = res
                if marker in body:
                    race_hit = (status, body)
                    break
            if race_hit is not None:
                break
        if race_hit is None:
            return None

        race_status, race_body = race_hit
        return {
            "observe_url": str(observe.get("url")),
            "observe_method": str(observe.get("method") or "GET").upper(),
            "trigger_url": str(trigger.get("url")),
            "trigger_method": str(trigger.get("method") or "GET").upper(),
            "marker": marker,
            "race_status": race_status,
            "race_served_body_full": race_body[:_RACE_FULL_CAP],
            "control_status": ctrl_status,
            "control_served_body_full": ctrl_body[:_RACE_FULL_CAP],
            "concurrency": sc["concurrency"],
            "rounds": sc["rounds"],
            "trigger": trigger,
            "observe": observe,
            "reset": reset,
            "auth_headers": headers,
        }

    async def _send(
        self, spec: Dict[str, Any], marker: str, headers: Dict[str, str]
    ) -> Tuple[int, str]:
        """1 リクエスト送信（``self._client`` 注入 seam or AsyncNetworkClient）。

        spec: {method, url, params}（params の ``{marker}`` は marker に置換）。
        """
        method = str(spec.get("method") or "GET").upper()
        url = str(spec.get("url"))
        params = _subst_marker(spec.get("params") or {}, marker)
        h = dict(headers or {})

        async def _do(client):
            return await client.request(method, url, params=params, headers=h, use_proxy=True)

        injected = getattr(self, "_client", None)
        if injected is not None:
            resp = await _do(injected)
        else:
            from src.core.infra.network_client import AsyncNetworkClient
            async with AsyncNetworkClient() as client:
                resp = await _do(client)
        status = int(getattr(resp, "status", 0) or 0)
        rbody = getattr(resp, "body", None)
        if rbody is None:
            rbody = getattr(resp, "text", "") or ""
        if isinstance(rbody, bytes):
            rbody = rbody.decode("utf-8", errors="replace")
        return status, str(rbody)

    def _build_finding(self, target_url: str, proof: Dict[str, Any]) -> Finding:
        marker = proof["marker"]
        obs_url = proof["observe_url"]
        obs_method = proof["observe_method"]
        trg_url = proof["trigger_url"]
        trg_method = proof["trigger_method"]
        race_status = proof["race_status"]
        ctrl_status = proof["control_status"]
        # control と race を同一オフセット窓で切り出し、反映領域を双方に含める
        # （差分が審査側で検証可能になる＝poc_judge の指摘への対応）。
        ctrl_body, race_body = _aligned_snippets(
            proof["control_served_body_full"], proof["race_served_body_full"], marker
        )
        concurrency = proof["concurrency"]

        trg_params = _subst_marker((proof["trigger"] or {}).get("params") or {}, marker)
        obs_params = (proof["observe"] or {}).get("params") or {}
        # 差分の両ステップを poc に載せる（逐次＝非反映／並列＝反映の対比が必須）。
        poc_request = (
            "# Step 1 — sequential control (validation/lock blocks it)\r\n"
            f"{trg_method} {trg_url} params={trg_params}\r\n"
            f"{obs_method} {obs_url} params={obs_params}\r\n"
            "\r\n"
            f"# Step 2 — concurrent race burst ({concurrency} parallel trigger+observe, TOCTOU window)\r\n"
            f"repeat concurrently: {trg_method} {trg_url} params={trg_params}\r\n"
            f"                     {obs_method} {obs_url} params={obs_params}"
        )
        poc_response = (
            f"# Step 1 response — marker '{marker}' is ABSENT (blocked, HTTP {ctrl_status})\r\n"
            f"{ctrl_body}\r\n"
            "\r\n"
            f"# Step 2 response — marker '{marker}' is PRESENT (executed in TOCTOU window, HTTP {race_status})\r\n"
            f"{race_body}"
        )
        impact = (
            f"check-then-act の窓に並列バースト（{concurrency} 並列）を撃つと、逐次では検証/ロックで"
            f"弾かれる注入アクションが窓の中で実行される。逐次コントロールでは一意マーカー '{marker}' が"
            f"応答に出ない（HTTP {ctrl_status}）が、並列バーストでは同マーカーが応答に反映される"
            f"（HTTP {race_status}）。この差分から TOCTOU レース条件が確定。検証バイパス・多重処理・"
            "本来1回のはずの特権アクションの複数成立（レース経由の注入/権限昇格）に直結する実害。"
        )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.RACE_CONDITION,
            severity=Severity.HIGH,
            title="Race Condition (TOCTOU) via concurrent burst",
            description=(
                "Race condition confirmed by sequential-vs-concurrent differential: a unique "
                f"marker '{marker}' is absent under sequential requests (HTTP {ctrl_status}) but "
                f"reflected under a concurrent burst (HTTP {race_status}), proving execution in the "
                "check-then-act (TOCTOU) window."
            ),
            source_agent=self.name,
            confidence=0.95,
            impact=impact,
            reproduction_steps=[
                "逐次で trigger→observe を送り、一意マーカーが応答に出ない（検証/ロックで弾かれる）"
                f"ことを確認する（HTTP {ctrl_status}）。",
                f"trigger と observe を {concurrency} 並列で複数ラウンド撃つと、同じマーカーが observe "
                f"応答に反映される（HTTP {race_status}）ことを確認する（差分＝TOCTOU 窓で実行）。",
            ],
            tags=["race_condition", "high", "race_condition_toctou"],
            evidence=Evidence(
                request_method=obs_method,
                request_url=obs_url,
                request_headers={**proof.get("auth_headers", {})},
                request_body="",
                response_status=race_status,
                response_headers={},
                response_body=race_body,
            ),
            additional_info={
                "race_evidence": {
                    "request_url": obs_url,
                    "marker": marker,
                    "race_status": race_status,
                    "race_served_body": race_body,
                    "control_status": ctrl_status,
                    "control_served_body": ctrl_body,
                    "concurrency": concurrency,
                    "rounds": proof["rounds"],
                },
                "race_replay": {
                    "observe": {"method": obs_method, "url": obs_url,
                                "params": obs_params},
                    "trigger": {"method": trg_method, "url": trg_url,
                                "params": (proof["trigger"] or {}).get("params") or {}},
                    "reset": proof["reset"],
                    "concurrency": concurrency,
                    "rounds": proof["rounds"],
                },
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )
