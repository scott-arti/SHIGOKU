"""
Smart Host Header Hunter - Host ヘッダ注入（認証/認可バイパス）検出スペシャリスト (SGK-2026-0491)

アプリが受信リクエストの Host（や X-Forwarded-Host 等）を認可・ルーティング・リンク生成に
そのまま信頼すると、攻撃者が Host を差し替えることで本来アクセスできない制限コンテンツに
到達できる（Host ヘッダ注入）。

確定は**決定論的差分**で行う：
  - control（非バイパスのホスト） → 制限コンテンツの署名が応答に出ない（拒否/リダイレクト）
  - injection（候補バイパス値） → 制限コンテンツの署名が応答に出る（バイパス成功）
署名（restricted_signature）は制限コンテンツにのみ現れる文字列で task 由来（製品固有値は
エンジンにハードコードしない）。注入ヘッダが Host 以外の場合は Host を control 値に固定して
注入ヘッダだけを変数化し、バイパスの原因を当該ヘッダに厳密に帰属させる（誤検知防止）。
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

_HHI_HEADERS: Tuple[str, ...] = (
    "Host", "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "Forwarded",
)
_HHI_BYPASS_VALUES: Tuple[str, ...] = ("localhost", "127.0.0.1")
_HHI_DEFAULT_CONTROL_HOST = "shigoku-control.example"
_HHI_SNIPPET_CAP = 1500


def _snip(text: str) -> str:
    return (text or "")[:_HHI_SNIPPET_CAP]


def _snip_centered(text: str, anchor: str) -> str:
    """anchor（制限署名）を中心にスニペットを切り出す。反映が本文後方にあっても
    証拠が落ちないようにする（先頭固定切り詰めだと署名が欠落する＝poc_judge の指摘）。"""
    text = text or ""
    idx = text.find(anchor)
    if idx < 0:
        return text[:_HHI_SNIPPET_CAP]
    start = max(0, idx - _HHI_SNIPPET_CAP // 2)
    return text[start:start + _HHI_SNIPPET_CAP]


class SmartHostHeaderHunter(Specialist):
    name = "SmartHostHeaderHunter"
    description = "Host header injection (auth/authz bypass) detector (differential confirmation)"
    timeout_seconds = 120
    is_aggressive = False

    def __init__(self, config: Dict = None):
        super().__init__()
        self.config = config or {}

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        result = await self._probe(task)
        if result is None:
            return []
        return [self._build_finding(task.target, result)]

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

    def _observe_url(self, task: Task) -> str:
        params = self._params(task)
        obs = params.get("hhi_observe")
        if isinstance(obs, dict) and str(obs.get("url") or "").strip():
            return str(obs["url"])
        return str(task.target)

    def _bypass_values(self, task: Task) -> List[str]:
        params = self._params(task)
        vals: List[str] = []
        provided = params.get("hhi_bypass_values")
        if isinstance(provided, (list, tuple)):
            vals.extend(str(v) for v in provided)
        for v in _HHI_BYPASS_VALUES:
            if v not in vals:
                vals.append(v)
        return vals

    def _headers_to_try(self, task: Task) -> Tuple[str, ...]:
        params = self._params(task)
        provided = params.get("hhi_headers")
        if isinstance(provided, (list, tuple)) and provided:
            return tuple(str(h) for h in provided)
        return _HHI_HEADERS

    async def _probe(self, task: Task) -> Optional[Dict[str, Any]]:
        params = self._params(task)
        signature = str(params.get("hhi_restricted_signature") or "").strip()
        if not signature:
            return None
        url = self._observe_url(task)
        control_host = str(params.get("hhi_control_host") or _HHI_DEFAULT_CONTROL_HOST).strip()
        base = self._auth_headers(task)

        # control: 非バイパスのホストで送る。制限署名が出ないベースライン。
        control_headers = {**base, "Host": control_host}
        try:
            _cs, control_body = await self._send(url, control_headers)
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] control send failed: %s", self.name, exc)
            return None
        if signature in control_body:
            # 非バイパスでも署名が出る＝アクセス制御されていない（差分にならない）→ 棄却
            return None

        for header in self._headers_to_try(task):
            for value in self._bypass_values(task):
                # 注入ヘッダを isolate: Host 以外を注入するときは Host を control 値に固定。
                inj_headers = dict(base)
                if header.lower() == "host":
                    inj_headers["Host"] = value
                else:
                    inj_headers["Host"] = control_host
                    inj_headers[header] = value
                try:
                    inj_status, inj_body = await self._send(url, inj_headers)
                except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
                    logger.debug("[%s] inj send failed (%s=%s): %s", self.name, header, value, exc)
                    continue
                if 200 <= inj_status < 300 and signature in inj_body:
                    return {
                        "request_url": url,
                        "injected_header": header,
                        "injected_host_value": value,
                        "control_host": control_host,
                        "restricted_signature": signature,
                        "injected_status": inj_status,
                        # 署名中心で切り出す（署名が本文後方でも証拠を保持）。
                        "injected_served_body": _snip_centered(inj_body, signature),
                        "control_served_body": _snip(control_body),
                        "auth_headers": base,
                    }
        return None

    async def _send(self, url: str, headers: Dict[str, str]) -> Tuple[int, str]:
        """GET 送信（``self._client`` 注入 seam or AsyncNetworkClient）。
        allow_redirects=False で即時応答（302 リダイレクトを追わない）を評価する。"""
        async def _do(client):
            return await client.request(
                "GET", url, headers=dict(headers or {}),
                allow_redirects=False, use_proxy=True,
            )

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
        url = proof["request_url"]
        header = proof["injected_header"]
        value = proof["injected_host_value"]
        control_host = proof["control_host"]
        signature = proof["restricted_signature"]
        inj_status = proof["injected_status"]
        inj_body = proof["injected_served_body"]
        ctrl_body = proof["control_served_body"]

        poc_request = (
            f"# Step 1 — control (non-bypass host: {control_host})\r\n"
            f"GET {url} HTTP/1.1\r\n"
            f"Host: {control_host}\r\n"
            "\r\n"
            f"# Step 2 — injection ({header}: {value})\r\n"
            f"GET {url} HTTP/1.1\r\n"
            + (f"Host: {value}\r\n" if header.lower() == "host"
               else f"Host: {control_host}\r\n{header}: {value}\r\n")
        )
        poc_response = (
            f"# Step 1 response — restricted signature '{signature}' ABSENT (access denied)\r\n"
            f"{ctrl_body}\r\n"
            "\r\n"
            f"# Step 2 response — restricted signature '{signature}' PRESENT (HTTP {inj_status}, bypass)\r\n"
            f"{inj_body}"
        )
        impact = (
            f"リクエストの '{header}' ヘッダを '{value}' に差し替えると、本来アクセス制御された制限"
            f"コンテンツ（署名 '{signature}'）が認証なしで応答に現れる（HTTP {inj_status}）。非バイパスの"
            f"ホスト（{control_host}）では現れない。この差分から、アプリが Host 系ヘッダを認可判定に"
            "信頼している Host ヘッダ注入が確定。認証/認可バイパス・パスワードリセットポイズニング・"
            "キャッシュ汚染等の実害に直結する。"
        )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.HOST_HEADER_INJECTION,
            severity=Severity.HIGH,
            title=f"Host Header Injection (auth bypass) via '{header}'",
            description=(
                "Host header injection confirmed by differential: injecting "
                f"'{header}: {value}' exposes restricted content (signature '{signature}', "
                f"HTTP {inj_status}) that a non-bypass Host ('{control_host}') does not."
            ),
            source_agent=self.name,
            confidence=0.95,
            impact=impact,
            reproduction_steps=[
                f"非バイパスのホスト（Host: {control_host}）で {url} を要求し、制限署名 "
                f"'{signature}' が応答に出ない（拒否）ことを確認する。",
                f"'{header}: {value}' を注入して {url} を要求すると、制限署名が応答に現れる"
                f"（HTTP {inj_status}）ことを確認する（差分＝Host ヘッダ注入によるバイパス）。",
            ],
            tags=["host_header_injection", "high", "host_header_auth_bypass"],
            evidence=Evidence(
                request_method="GET",
                request_url=url,
                request_headers={**proof.get("auth_headers", {}),
                                 **({"Host": value} if header.lower() == "host"
                                    else {"Host": control_host, header: value})},
                request_body="",
                response_status=inj_status,
                response_headers={},
                response_body=inj_body,
            ),
            additional_info={
                "host_header_evidence": {
                    "request_url": url,
                    "injected_header": header,
                    "injected_host_value": value,
                    "control_host": control_host,
                    "restricted_signature": signature,
                    "injected_status": inj_status,
                    "injected_served_body": inj_body,
                    "control_served_body": ctrl_body,
                },
                "host_header_replay": {
                    "url": url,
                    "header": header,
                    "value": value,
                    "signature": signature,
                },
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )
