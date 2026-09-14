"""
Smart Prototype Pollution Hunter - プロトタイプ汚染 検出スペシャリスト (SGK-2026-0497)

Node.js で攻撃者制御の入力を再帰マージ（lodash.merge 等）すると、`__proto__` 経由で
`Object.prototype` を汚染でき、以降に生成される**無関係なオブジェクト**にも注入プロパティが
継承される（権限昇格・DoS・RCE ガジェットの起点）。

確定は**in-band 差分＋一意マーカー**で行う：
  - control（汚染前）: setup で作った新オブジェクトを observe → 一意マーカーは出ない
  - pollute: `__proto__.<prop>` に一意マーカーを入れてマージ sink へ送る
  - observe（汚染後）: **別の**新オブジェクトを observe → そのマーカーが応答に出る
「その prop を一度も設定していない新オブジェクトにマーカーが現れる」ことが Object.prototype 汚染の
決定的証拠（マーカーは乱数で偶然混入・捏造不可）。シナリオ（sink/setup/observe テンプレ）は task 由来。
"""
import json
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

_PP_SNIPPET_CAP = 1200


def _subst(obj: Any, marker: str, uniq: str) -> Any:
    """テンプレの {marker}/{uniq} を再帰置換したコピーを返す。"""
    if isinstance(obj, str):
        return obj.replace("{marker}", marker).replace("{uniq}", uniq)
    if isinstance(obj, dict):
        return {k: _subst(v, marker, uniq) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_subst(v, marker, uniq) for v in obj]
    return obj


def _snippet(text: str, anchor: str) -> str:
    text = text or ""
    idx = text.find(anchor) if anchor else -1
    if idx < 0:
        return text[:_PP_SNIPPET_CAP]
    start = max(0, idx - _PP_SNIPPET_CAP // 2)
    return text[start:start + _PP_SNIPPET_CAP]


class SmartPrototypePollutionHunter(Specialist):
    name = "SmartPrototypePollutionHunter"
    description = "Prototype pollution detector (server-side, in-band differential)"
    timeout_seconds = 150
    is_aggressive = False

    def __init__(self, config: Dict = None):
        super().__init__()
        self.config = config or {}

    def _params(self, task: Task) -> Dict[str, Any]:
        return task.params if isinstance(getattr(task, "params", None), dict) else {}

    def _auth_headers(self, task: Task) -> Dict[str, str]:
        params = self._params(task)
        _auth = params.get("_auth", {}) if isinstance(params.get("_auth"), dict) else {}
        headers = dict(_auth.get("auth_headers", {}) or {})
        cookies = str(_auth.get("cookies", "") or params.get("cookies", "") or "")
        if cookies and "Cookie" not in headers:
            headers["Cookie"] = cookies
        return headers

    def _scenario(self, task: Task) -> Optional[Dict[str, Any]]:
        params = self._params(task)
        sink = params.get("pp_sink")
        observe = params.get("pp_observe")
        if not (isinstance(sink, dict) and isinstance(observe, dict)):
            return None
        if not (str(sink.get("url") or "").strip() and str(observe.get("url") or "").strip()):
            return None
        setup = params.get("pp_setup")
        setup = list(setup) if isinstance(setup, (list, tuple)) else []
        return {
            "sink": sink,
            "setup": setup,
            "observe": observe,
            "property": str(params.get("pp_property") or "polluted"),
        }

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        result = await self._probe(task)
        if result is None:
            return []
        return [self._build_finding(task.target, result)]

    async def _probe(self, task: Task) -> Optional[Dict[str, Any]]:
        sc = self._scenario(task)
        if sc is None:
            return None
        headers = self._auth_headers(task)
        marker = "shigoku_pp_" + uuid.uuid4().hex[:12]

        # control（汚染前）: 新オブジェクトを作って observe → マーカーは出ないはず。
        uniq_c = "ppc" + uuid.uuid4().hex[:8]
        try:
            for step in sc["setup"]:
                await self._send_step(step, marker, uniq_c, headers)
            _cs, control_body = await self._send_step(sc["observe"], marker, uniq_c, headers)
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] control failed: %s", self.name, exc)
            return None
        if marker in control_body:
            # 汚染前から出る＝差分にならない（単なる反響）→ 棄却
            return None

        # pollute: __proto__.<prop> に marker を入れてマージ sink へ。
        try:
            _ps, _pb = await self._send_step(sc["sink"], marker, "ppsink", headers)
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] pollute send failed: %s", self.name, exc)
            return None

        # observe（汚染後）: 別の新オブジェクトを作って observe → marker が出れば汚染。
        uniq_o = "ppo" + uuid.uuid4().hex[:8]
        try:
            for step in sc["setup"]:
                await self._send_step(step, marker, uniq_o, headers)
            obs_status, polluted_body = await self._send_step(sc["observe"], marker, uniq_o, headers)
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] observe failed: %s", self.name, exc)
            return None
        if marker not in polluted_body:
            return None

        return {
            "sink_url": str(sc["sink"].get("url")),
            "observe_url": str(sc["observe"].get("url")),
            "property": sc["property"],
            "marker": marker,
            "observe_status": obs_status,
            "polluted_served_body": _snippet(polluted_body, marker),
            "control_served_body": control_body[:_PP_SNIPPET_CAP],
            "sink": sc["sink"],
            "setup": sc["setup"],
            "observe": sc["observe"],
            "auth_headers": headers,
        }

    async def _send_step(
        self, step: Dict[str, Any], marker: str, uniq: str, headers: Dict[str, str]
    ) -> Tuple[int, str]:
        method = str(step.get("method") or "POST").upper()
        url = str(step.get("url"))
        mode = str(step.get("mode") or "form").lower()
        body = _subst(step.get("body") or {}, marker, uniq)
        h = dict(headers or {})
        if mode == "json":
            h["Content-Type"] = "application/json"
            data: Any = json.dumps(body)
        else:
            data = body  # form dict

        async def _do(client):
            return await client.request(method, url, data=data, headers=h, use_proxy=True)

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
        sink_url = proof["sink_url"]
        observe_url = proof["observe_url"]
        prop = proof["property"]
        marker = proof["marker"]
        obs_status = proof["observe_status"]
        polluted_body = proof["polluted_served_body"]
        control_body = proof["control_served_body"]
        sink_body = _subst((proof["sink"] or {}).get("body") or {}, marker, "ppsink")

        poc_request = (
            f"# Step 1 — control: create a fresh object then observe (no pollution yet)\r\n"
            f"GET/POST {observe_url}  -> marker '{marker}' ABSENT\r\n"
            "\r\n"
            f"# Step 2 — pollute: merge sink with __proto__.{prop} = marker\r\n"
            f"POST {sink_url} HTTP/1.1\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            f"{json.dumps(sink_body)}\r\n"
            "\r\n"
            f"# Step 3 — observe: create ANOTHER fresh object (never sets '{prop}') then observe\r\n"
            f"POST {observe_url} HTTP/1.1"
        )
        poc_response = (
            f"# Step 1 response — fresh object's '{prop}' is empty (marker absent)\r\n"
            f"{control_body}\r\n"
            "\r\n"
            f"# Step 3 response — a DIFFERENT fresh object now shows '{prop}' = '{marker}' "
            f"(HTTP {obs_status})\r\n"
            f"{polluted_body}\r\n"
            "\r\n"
            f"CORRELATION: the random marker '{marker}' was injected ONLY via __proto__.{prop} in the "
            "merge sink; it now appears on a newly-created object that never set that property => "
            "Object.prototype was polluted (prototype pollution)."
        )
        impact = (
            f"マージ sink（{sink_url}）へ `__proto__.{prop}` に一意マーカー '{marker}' を入れて送ると、"
            f"以降に作られた**その prop を一度も設定していない新オブジェクト**の応答（{observe_url}）に"
            f"マーカーが現れる（HTTP {obs_status}）。汚染前は出ない。これは Object.prototype が汚染された"
            "決定的証拠。汚染するプロパティ次第で権限昇格（例 admin フラグ）・認証バイパス・DoS・"
            "ガジェット次第で RCE に直結する実害。"
        )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.PROTOTYPE_POLLUTION,
            severity=Severity.HIGH,
            title=f"Prototype Pollution via __proto__.{prop} (server-side merge)",
            description=(
                "Prototype pollution confirmed by differential: a unique marker injected via "
                f"__proto__.{prop} into a merge sink appears on a freshly-created object that never "
                f"set that property (HTTP {obs_status}), while a pre-pollution control does not."
            ),
            source_agent=self.name,
            confidence=0.95,
            impact=impact,
            reproduction_steps=[
                f"汚染前に新オブジェクトを作って {observe_url} を観測し、'{prop}' が空（マーカー無し）で"
                "あることを確認する。",
                f"マージ sink {sink_url} に `__proto__.{prop}` = 一意マーカーを送る（汚染）。",
                f"別の新オブジェクトを作って {observe_url} を観測すると、そのマーカーが '{prop}' に現れる"
                "（汚染前は出ない）ことを確認する（差分＝Object.prototype 汚染）。",
            ],
            tags=["prototype_pollution", "high", "prototype_pollution_confirmed"],
            evidence=Evidence(
                request_method="POST",
                request_url=observe_url,
                request_headers={**proof.get("auth_headers", {})},
                request_body=json.dumps(sink_body),
                response_status=obs_status,
                response_headers={},
                response_body=polluted_body,
            ),
            additional_info={
                "prototype_pollution_evidence": {
                    "sink_url": sink_url,
                    "observe_url": observe_url,
                    "pollute_property": prop,
                    "marker": marker,
                    "observe_status": obs_status,
                    "polluted_served_body": polluted_body,
                    "control_served_body": control_body,
                },
                "prototype_pollution_replay": {
                    "sink": proof["sink"],
                    "setup": proof["setup"],
                    "observe": proof["observe"],
                    "property": prop,
                },
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )
