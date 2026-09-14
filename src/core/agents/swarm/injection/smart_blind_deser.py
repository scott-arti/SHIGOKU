"""
Smart OOB Deserialization Hunter - 帯域外(OOB)デシリアライズ 検出スペシャリスト (SGK-2026-0496)

安全でないデシリアライズ（Python pickle 等）は、逆シリアライズ時に攻撃者ガジェットを実行する
（RCE 級）。応答に何も返らなくても、ガジェットに**外向き HTTP コールバック**を仕込めば OOB で
確定できる（SGK-2026-0494 の基盤を横展開）。

流れ：`OOBProvider` が一意コールバック URL＋token を発行 → デシリアライズ時に受信器へ HTTP GET
するペイロード（`oob_payload_builders.build_oob_payload`）を生成 → エンコード（hex 等）して sink へ
送信 → 標的がデシリアライズ → **我々の受信器に一意 token 到達** → OOB デシリアライズ確定。
token は乱数で、受信器に届けば「攻撃者ペイロードが逆シリアライズ・実行された」決定的証拠。

確定バーの汎用 OOB マーカー `oob_interaction_received` を共有（vuln_type=deserialization）。封印再現も
`_check_oob_replay` の builder パスで fresh callback から作り直して再送。製品固有ハードコードなし。
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.detection.oob_payload_builders import build_oob_payload, encode_payload

logger = logging.getLogger(__name__)

_DESER_PARAMS: Tuple[str, ...] = (
    "data_obj", "data", "obj", "payload", "pickle", "object", "o", "state", "session",
)
_DESER_POLL_TIMEOUT = 10.0


class SmartOOBDeserHunter(Specialist):
    name = "SmartOOBDeserHunter"
    description = "Blind (OOB) insecure-deserialization detector via callback gadget"
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
        provided = params.get("deser_params") or params.get("deser_param")
        fields: List[str] = []
        if isinstance(provided, str) and provided.strip():
            fields.append(provided.strip())
        elif isinstance(provided, (list, tuple)):
            fields.extend(str(p) for p in provided)
        for p in _DESER_PARAMS:
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
        params = self._params(task)
        url = task.target
        headers = self._auth_headers(task)
        kind = str(params.get("deser_kind") or "python_pickle")
        encoding = str(params.get("deser_encoding") or "hex")
        mode = str(params.get("deser_mode") or "form").lower()
        for param in self._candidate_params(task):
            callback_url, token = provider.new_callback()
            try:
                raw = build_oob_payload(kind, callback_url)
            except ValueError as exc:
                logger.warning("[%s] builder failed: %s", self.name, exc)
                return None
            encoded = encode_payload(raw, encoding)
            try:
                status = await self._send(mode, url, param, encoded, headers)
            except Exception as exc:  # noqa: BLE001 — network boundary
                logger.debug("[%s] send failed (%s): %s", self.name, param, exc)
                continue
            interaction = await provider.poll(token, timeout=_DESER_POLL_TIMEOUT)
            if interaction and token in str(interaction.get("path", "")):
                return {
                    "request_url": url, "mode": mode, "param": param, "kind": kind,
                    "encoding": encoding, "callback_url": callback_url, "token": token,
                    "request_status": status, "interaction": interaction,
                    "auth_headers": headers,
                }
        return None

    async def _send(self, mode, url, param, encoded, headers) -> int:
        h = dict(headers or {})

        async def _do(client):
            if mode == "raw":
                return await client.request("POST", url, data=encoded, headers=h, use_proxy=True)
            return await client.request("POST", url, data={param: encoded}, headers=h, use_proxy=True)

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
        param = proof["param"]
        kind = proof["kind"]
        encoding = proof["encoding"]
        callback_url = proof["callback_url"]
        token = proof["token"]
        status = proof["request_status"]
        interaction = proof["interaction"]
        remote_ip = str(interaction.get("remote_ip", ""))
        cb_method = str(interaction.get("method") or "GET")
        cb_path = str(interaction.get("path") or "")
        cb_headers = interaction.get("headers") if isinstance(interaction.get("headers"), dict) else {}
        cb_host = str(cb_headers.get("Host") or cb_headers.get("host") or "")

        where = f"form field {param}" if mode == "form" else "request body"
        poc_request = (
            f"POST {url} HTTP/1.1\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
            f"{param}=<{kind} gadget, {encoding}-encoded; __reduce__ -> os.system(HTTP callback to our receiver)>\r\n"
            f"# ^ Blind deserialization: the gadget calls back our OOB receiver on unpickle ({where})."
        )
        poc_response = (
            f"HTTP/1.1 {status}\r\n"
            "\r\n"
            "(in-band response does not reveal gadget execution: blind)\r\n"
            "\r\n"
            "===== RAW OUT-OF-BAND REQUEST OBSERVED AT OUR OOB RECEIVER =====\r\n"
            "The target itself made this inbound request to our server during deserialization:\r\n"
            f"{cb_method} {cb_path} HTTP/1.1\r\n"
            + (f"Host: {cb_host}\r\n" if cb_host else "")
            + f"(source IP: {remote_ip})\r\n"
            "\r\n"
            f"CORRELATION: the random token '{token}' appears in the path above AND was placed by us "
            f"ONLY inside the {kind} gadget we sent. No in-band channel could deliver this token to our "
            "server; the only cause is the target deserializing our attacker-controlled object and "
            "executing the gadget => blind (out-of-band) insecure deserialization (RCE-class) confirmed."
        )
        impact = (
            f"標的が攻撃者制御の {kind} オブジェクトを逆シリアライズし、ガジェット（`__reduce__`→"
            "`os.system`）を実行した。in-band では何も返さない（ブラインド）が、逆シリアライズ時に"
            f"我々の受信器へ一意 token '{token}' のコールバックが標的（{remote_ip}）から届いた。token は"
            "我々が送ったガジェットにしか存在しないため、任意コード実行に至る安全でないデシリアライズの"
            "決定的証拠（RCE 級・良性コールバックで非破壊確認）。"
        )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.DESERIALIZATION,
            severity=Severity.CRITICAL,
            title="Blind (OOB) Insecure Deserialization via callback gadget",
            description=(
                f"Insecure deserialization confirmed out-of-band: a {kind} gadget delivered the unique "
                f"token '{token}' to our receiver from the target ({remote_ip}) during unpickle. No "
                f"in-band reflection (HTTP {status}). RCE-class."
            ),
            source_agent=self.name,
            confidence=0.97,
            impact=impact,
            reproduction_steps=[
                "OOB 受信器で一意コールバック URL＋token を発行する。",
                f"逆シリアライズ時に受信器へ HTTP GET する {kind} ガジェットを生成し {where} に入れて "
                f"{url} に送る。",
                "受信器に token 付きのコールバックが標的から届くことを確認する（＝OOB デシリアライズ）。",
            ],
            tags=["deserialization", "blind", "oob", "critical", "oob_interaction_received"],
            evidence=Evidence(
                request_method="POST",
                request_url=url,
                request_headers={**proof.get("auth_headers", {})},
                request_body=f"{param}=<{kind} gadget {encoding}>",
                response_status=status,
                response_headers={},
                response_body="",  # blind
            ),
            additional_info={
                "oob_evidence": {
                    "vuln_class": "deserialization",
                    "channel": "http",
                    "token": token,
                    "callback_url": callback_url,
                    # token を含む「送出内容」= payout_grade の "token in payload" 検証に用いる
                    # （ガジェット内の callback URL に token が平文で存在する）。
                    "payload": f"{kind} gadget -> os.system callback {callback_url}",
                    "interaction_received": True,
                    "interaction": interaction,
                    "request_status": status,
                },
                "oob_replay": {
                    "method": "POST",
                    "url": url,
                    "mode": mode,
                    "param": param,
                    "content_type": None,
                    # builder パス: fresh callback からガジェットを作り直して再送する。
                    "builder": kind,
                    "encoding": encoding,
                    "payload_template": _OOB_BUILDER_TEMPLATE,
                },
                "unique_oob_callback_received": True,
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )


# 封印再現の記述子検証（payload_template 非空要件）を満たすためのマーカ文字列。
# 実際の再送ペイロードは builder（deser_kind）＋fresh callback から生成される（{OOB} 置換ではない）。
_OOB_BUILDER_TEMPLATE = "{OOB}"
