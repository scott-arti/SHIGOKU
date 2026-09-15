"""
Smart Blind SSRF Hunter - OOB(帯域外)ブラインド SSRF 検出スペシャリスト (SGK-2026-0495)

アプリがリクエスト中の URL をサーバ側で取得（fetch）するが、その結果を in-band に返さない
（ブラインド SSRF）。唯一の手がかりは「サーバが我々の指定 URL を外向きに取得するか」。

確定は OOB で行う（SGK-2026-0494 の基盤を横展開）：`OOBProvider` が一意コールバック URL＋token を
発行 → URL パラメータ（`url`/`uri`/`target`/`webhook` 等）にその callback を入れて標的へ送る →
標的サーバがその URL を fetch → **我々の受信器に一意 token が届く** → ブラインド SSRF 確定。
token は乱数で、受信器に届けば「サーバが我々の URL を取得した」決定的証拠（偶然混入・捏造不可）。

確定バーの汎用 OOB マーカー `oob_interaction_received` を共有（vuln_type=ssrf）。封印再現も
`_check_oob_replay`（query/form/json モード）を流用＝新エンジンは Finding を作るだけ。HTTP OOB が
対象（DNS-only は DNS 受信器で別途）。製品固有ハードコードなし。
"""
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

_OOB_PLACEHOLDER = "{OOB}"
_SSRF_PARAMS: Tuple[str, ...] = (
    "url", "uri", "target", "dest", "destination", "callback", "webhook",
    "image_url", "imageUrl", "image", "link", "u", "host", "redirect",
    "next", "feed", "endpoint", "path", "src", "load",
)
_SSRF_MODES: Tuple[str, ...] = ("form", "query", "json")
_BLIND_SSRF_POLL_TIMEOUT = 10.0


class SmartBlindSSRFHunter(Specialist):
    name = "SmartBlindSSRFHunter"
    description = "Blind (OOB) SSRF detector via server-side fetch callback"
    timeout_seconds = 180
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

    def _oob_provider(self):
        provider = getattr(self, "_oob", None)
        if provider is not None:
            return provider
        from src.core.detection.oob_provider import LocalOOBProvider
        self._oob = LocalOOBProvider()
        return self._oob

    def _candidate_params(self, task: Task) -> List[str]:
        params = self._params(task)
        provided = params.get("ssrf_params") or params.get("ssrf_param")
        fields: List[str] = []
        if isinstance(provided, str) and provided.strip():
            fields.append(provided.strip())
        elif isinstance(provided, (list, tuple)):
            fields.extend(str(p) for p in provided)
        for p in _SSRF_PARAMS:
            if p not in fields:
                fields.append(p)
        return fields

    def _modes(self, task: Task) -> Tuple[str, ...]:
        params = self._params(task)
        provided = params.get("ssrf_modes")
        if isinstance(provided, (list, tuple)) and provided:
            return tuple(str(m) for m in provided if str(m) in _SSRF_MODES)
        return _SSRF_MODES

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        provider = self._oob_provider()
        started = False
        try:
            await provider.start()
            started = True
        except Exception as exc:  # noqa: BLE001 — receiver boundary, fail closed
            logger.warning("[%s] OOB provider start failed: %s", self.name, exc)
            return []
        try:
            result = await self._probe(task, provider)
        finally:
            if started:
                try:
                    await provider.stop()
                except Exception:  # noqa: BLE001 — best-effort cleanup
                    pass
        if result is None:
            return []
        return [self._build_finding(task.target, result)]

    async def _probe(self, task: Task, provider) -> Optional[Dict[str, Any]]:
        url = task.target
        headers = self._auth_headers(task)
        for mode in self._modes(task):
            method = "GET" if mode == "query" else "POST"
            for param in self._candidate_params(task):
                callback_url, token = provider.new_callback()
                try:
                    status = await self._send(mode, method, url, param, callback_url, headers)
                except Exception as exc:  # noqa: BLE001 — network boundary
                    logger.debug("[%s] send failed (%s/%s): %s", self.name, mode, param, exc)
                    continue
                interaction = await provider.poll(token, timeout=_BLIND_SSRF_POLL_TIMEOUT)
                if interaction and token in str(interaction.get("path", "")):
                    return {
                        "request_url": url, "mode": mode, "method": method, "param": param,
                        "callback_url": callback_url, "token": token,
                        "request_status": status, "interaction": interaction,
                        "auth_headers": headers,
                    }
        return None

    async def _send(self, mode, method, url, param, value, headers) -> int:
        h = dict(headers or {})

        async def _do(client):
            if mode == "query":
                return await client.request("GET", url, params={param: value},
                                            headers=h, use_proxy=True)
            if mode == "json":
                h2 = dict(h); h2["Content-Type"] = "application/json"
                return await client.request("POST", url, data=json.dumps({param: value}),
                                            headers=h2, use_proxy=True)
            return await client.request("POST", url, data={param: value},
                                        headers=h, use_proxy=True)

        injected = getattr(self, "_client", None)
        if injected is not None:
            resp = await _do(injected)
        else:
            from src.core.infra.network_client import AsyncNetworkClient
            async with AsyncNetworkClient() as client:
                resp = await _do(client)
        return int(getattr(resp, "status", 0) or 0)

    def _build_finding(self, target_url: str, proof: Dict[str, Any]) -> Finding:
        url = proof["request_url"]
        mode = proof["mode"]
        method = proof["method"]
        param = proof["param"]
        callback_url = proof["callback_url"]
        token = proof["token"]
        status = proof["request_status"]
        interaction = proof["interaction"]
        remote_ip = str(interaction.get("remote_ip", ""))
        channel = str(interaction.get("channel") or "http").lower()
        cb_method = str(interaction.get("method") or "GET")
        cb_path = str(interaction.get("path") or "")
        cb_headers = interaction.get("headers") if isinstance(interaction.get("headers"), dict) else {}
        cb_host = str(cb_headers.get("Host") or cb_headers.get("host") or "")
        cb_ua = str(cb_headers.get("User-Agent") or cb_headers.get("user-agent") or "")

        where = {"query": f"?{param}=", "json": f'JSON field "{param}"', "form": f"form field {param}"}.get(mode, param)
        poc_request = (
            f"{method} {url} HTTP/1.1\r\n"
            + (f"Content-Type: application/json\r\n\r\n{{\"{param}\": \"{callback_url}\"}}"
               if mode == "json"
               else (f"\r\n(query) {param}={callback_url}" if mode == "query"
                     else f"Content-Type: application/x-www-form-urlencoded\r\n\r\n{param}={callback_url}"))
            + f"\r\n# ^ Blind SSRF: our OOB callback URL is placed in {where}."
        )
        if channel == "dns":
            # DNS OOB: 受信器は権威 DNS として動作し、標的リゾルバが送ってきた DNS クエリ
            # （token を含む FQDN）を記録する。HTTP 形式で書かない（判定は「一貫した生の
            # 受信アーティファクト」を求める・[[poc-judge-raw-evidence]]）。
            oob_block = (
                "===== RAW OUT-OF-BAND DNS QUERY OBSERVED AT OUR DNS RECEIVER =====\r\n"
                "Our receiver is the authoritative DNS server for the callback domain; the "
                "target's own resolver sent this DNS query (recorded verbatim):\r\n"
                f"DNS query: QNAME={cb_path} (type A) from resolver/source {remote_ip}\r\n"
                "\r\n"
                f"CORRELATION: the random token '{token}' is the leftmost label of the queried "
                "FQDN above AND was placed by us ONLY inside the callback URL we supplied as the "
                "fetch target. No in-band channel could deliver this token to our DNS server; the "
                "only cause is the target resolving our URL's hostname before the server-side fetch. "
                "=> blind (out-of-band, DNS) SSRF confirmed."
            )
        else:
            oob_block = (
                "===== RAW OUT-OF-BAND REQUEST OBSERVED AT OUR OOB RECEIVER =====\r\n"
                "The target server itself made this inbound request to our server:\r\n"
                f"{cb_method} {cb_path} HTTP/1.1\r\n"
                + (f"Host: {cb_host}\r\n" if cb_host else "")
                + (f"User-Agent: {cb_ua}\r\n" if cb_ua else "")
                + f"(source IP: {remote_ip})\r\n"
                "\r\n"
                f"CORRELATION: the random token '{token}' appears in the path above AND was placed by us "
                "ONLY inside the callback URL we supplied as the fetch target. No in-band channel could "
                "deliver this token to our server; the only cause is the target performing a server-side "
                "fetch of our URL => blind (out-of-band) SSRF confirmed."
            )
        poc_response = (
            f"HTTP/1.1 {status}\r\n"
            "\r\n"
            "(in-band response does not reveal the fetch result: blind)\r\n"
            "\r\n"
            + oob_block
        )
        if channel == "dns":
            impact = (
                f"標的サーバがリクエスト中の URL（{where}）の**ホスト名を名前解決**した。in-band では"
                f"取得結果を返さない（HTTP {status}・ブラインド）が、我々が権威 DNS として動作する受信器に、"
                f"一意 token '{token}' を含む FQDN の DNS クエリが標的側リゾルバ（{remote_ip}）から届いた。"
                "token は我々が指定した URL のホスト名にしか存在しないため、サーバが我々の URL を解決した"
                "決定的証拠。真ブラインド（標的が外向き HTTP を出せない環境でも DNS 解決だけで確定でき、"
                "内部サービス到達・クラウドメタデータ取得・内部ポートスキャン等に直結する実害）。"
            )
            title = "Blind (OOB, DNS) SSRF via server-side hostname resolution"
            description = (
                "Blind SSRF confirmed out-of-band via DNS: a callback URL supplied in the request "
                f"({where}) caused the target to resolve its hostname, and the DNS query for token "
                f"'{token}' reached our authoritative DNS receiver from the target ({remote_ip}). No "
                f"in-band reflection (HTTP {status})."
            )
        else:
            impact = (
                f"標的サーバがリクエスト中の URL（{where}）を**サーバ側で取得**した。in-band では取得結果を"
                f"返さない（HTTP {status}・ブラインド）が、我々の受信器に一意 token '{token}' のコールバックが"
                f"標的（{remote_ip}）から届いた。token は我々が指定した URL にしか存在しないため、サーバが"
                "我々の URL を fetch した決定的証拠。ブラインド SSRF は内部サービス到達・クラウドメタデータ"
                "取得・内部ポートスキャン等に直結する実害。"
            )
            title = "Blind (OOB) SSRF via server-side fetch callback"
            description = (
                "Blind SSRF confirmed out-of-band: a callback URL supplied in the request "
                f"({where}) caused the target to fetch it, delivering the unique token '{token}' to "
                f"our receiver from the target ({remote_ip}). No in-band reflection (HTTP {status})."
            )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.SSRF,
            severity=Severity.HIGH,
            title=title,
            description=description,
            source_agent=self.name,
            confidence=0.95,
            impact=impact,
            reproduction_steps=[
                "OOB 受信器で一意コールバック URL＋token を発行する。",
                f"その callback URL を {where} に入れて {url} に送る（{method}）。",
                "受信器に token 付きのコールバックが標的サーバから届くことを確認する（＝ブラインド SSRF）。",
            ],
            tags=["ssrf", "blind", "oob", "high", "oob_interaction_received"],
            evidence=Evidence(
                request_method=method,
                request_url=url,
                request_headers={**proof.get("auth_headers", {})},
                request_body=f"{param}={callback_url}",
                response_status=status,
                response_headers={},
                response_body="",  # blind
            ),
            additional_info={
                "oob_evidence": {
                    "vuln_class": "ssrf",
                    "channel": channel,
                    "token": token,
                    "callback_url": callback_url,
                    # token を含む「送出値」= payout_grade の "token in payload" 検証に用いる。
                    "payload": f"{param}={callback_url}",
                    "interaction_received": True,
                    "interaction": interaction,
                    "request_status": status,
                },
                "oob_replay": {
                    "method": method,
                    "url": url,
                    "mode": mode,
                    "param": param,
                    "content_type": "application/json" if mode == "json" else None,
                    "payload_template": _OOB_PLACEHOLDER,
                },
                "unique_oob_callback_received": True,
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )
