"""
LocalDNSOOBListener - ローカル DNS OOB (Out-of-Band) 受信サーバー（依存ゼロ）

真ブラインド（標的が外向き HTTP を出せないが DNS 解決はする／DNS でしか漏れない）を
拾うための最小 DNS サーバー。dnspython 等に依存せず、標準ライブラリだけで受信 DNS クエリの
QNAME を解析し、token を含むサブドメインの問い合わせを記録する。

用途:
- SSRF/XXE/ブラインド RCE 等で `<token>.<domain>` を解決させ、その DNS クエリを OOB 証拠にする。
- HTTP 受信器（LocalOOBListener）と同じ抽象（OOBProvider）で差し替え可能。

到達性:
- 本番/インターネット標的では、権威 DNS を自ドメインに委譲し :53 で受ける（自前 interactsh 相当）。
- ローカルでは標的コンテナを ``docker --dns <受信器IP>`` で起動し、名前解決を受信器へ向ける。
- :53 は特権ポート（root 必要）。テスト/ローカル検証では任意ポートを指定できる。

応答:
- 良性の最小応答（A レコード=0.0.0.0）を返し、リゾルバのリトライ地獄を避ける（非破壊）。
"""

import logging
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DNSInteraction:
    """検知された DNS 問い合わせ。"""
    token: str
    remote_ip: str
    qname: str          # 問い合わせられた FQDN（token を含む）
    qtype: int
    timestamp: float


def _parse_qname(data: bytes, offset: int) -> str:
    """DNS メッセージの QNAME をドット区切り名に復元（圧縮ポインタは問い合わせ QNAME では
    通常出ないが、出たら打ち切る）。"""
    labels: List[str] = []
    pos = offset
    guard = 0
    while pos < len(data) and guard < 128:
        guard += 1
        length = data[pos]
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:  # 圧縮ポインタ（QNAME では想定外）→ 打ち切り
            break
        pos += 1
        if pos + length > len(data):
            break
        labels.append(data[pos:pos + length].decode("latin-1", errors="replace"))
        pos += length
    return ".".join(labels)


class LocalDNSOOBListener:
    """依存ゼロのローカル DNS OOB 受信器（UDP）。"""

    def __init__(self, host: str = "0.0.0.0", port: int = 53,
                 base_domain: str = "oob.test"):
        self.host = host
        self.port = port
        self.base_domain = base_domain.strip(".")
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        # token -> List[DNSInteraction]
        self._interactions: Dict[str, List[DNSInteraction]] = {}
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._sock is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(0.5)
        self._sock = sock
        self._running.set()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        logger.info("👂 LocalDNSOOBListener started at %s:%d (domain=%s)",
                    self.host, self.port, self.base_domain)

    def stop(self) -> None:
        self._running.clear()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        logger.info("LocalDNSOOBListener stopped")

    def _serve(self) -> None:
        while self._running.is_set() and self._sock is not None:
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(data, addr)
            except Exception as exc:  # noqa: BLE001 — 受信境界、失敗しても継続
                logger.debug("DNS handle error: %s", exc)

    def _handle(self, data: bytes, addr) -> None:
        if len(data) < 12:
            return
        (txid, flags, qdcount, ancount, nscount, arcount) = struct.unpack(
            ">HHHHHH", data[:12])
        if qdcount < 1:
            return
        qname = _parse_qname(data, 12)
        # QNAME 直後の QTYPE/QCLASS を読む（応答生成用）。
        name_end = 12
        while name_end < len(data) and data[name_end] != 0:
            ln = data[name_end]
            if (ln & 0xC0) == 0xC0:
                name_end += 1
                break
            name_end += 1 + ln
        qtype = 1
        qend = name_end + 1
        if qend + 4 <= len(data):
            qtype = struct.unpack(">H", data[qend:qend + 2])[0]

        remote_ip = addr[0] if addr else ""
        # token を base_domain 直前のラベル群から推定（先頭ラベルを token として保持）。
        token = qname.split(".")[0] if qname else ""
        interaction = DNSInteraction(
            token=token, remote_ip=remote_ip, qname=qname,
            qtype=qtype, timestamp=time.time(),
        )
        with self._lock:
            self._interactions.setdefault(token, []).append(interaction)
            # base_domain を含む問い合わせは、部分一致でも引けるよう別キーに複製しない
            # （get_interactions_by_substring で走査する）。
        logger.info("🔔 DNS OOB query: qname=%s from %s (token=%s)",
                    qname, remote_ip, token)
        self._respond(data, txid, qname, name_end, addr)

    def _respond(self, req: bytes, txid: int, qname: str,
                 name_end: int, addr) -> None:
        """良性の最小 A 応答（0.0.0.0）を返す。失敗しても記録は済んでいる。"""
        if self._sock is None:
            return
        try:
            # Header: 同一 txid, QR=1 AA=1, qd=1 an=1
            flags = 0x8400
            header = struct.pack(">HHHHHH", txid, flags, 1, 1, 0, 0)
            question = req[12:name_end + 5]  # QNAME(+0) + QTYPE + QCLASS
            # Answer: ポインタ 0xC00C, TYPE A(1), CLASS IN(1), TTL 0, RDLEN 4, RDATA 0.0.0.0
            answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4) + b"\x00\x00\x00\x00"
            self._sock.sendto(header + question + answer, addr)
        except Exception as exc:  # noqa: BLE001 — 応答はベストエフォート
            logger.debug("DNS respond error: %s", exc)

    def generate_hostname(self) -> tuple:
        """検証用 (hostname, token) を発行。hostname = ``<token>.<base_domain>``。"""
        token = secrets.token_hex(4)
        return f"{token}.{self.base_domain}", token

    def get_interactions(self, token: str) -> List[DNSInteraction]:
        with self._lock:
            direct = list(self._interactions.get(token, []))
            if direct:
                return direct
            # token が先頭ラベルでない場合に備え、qname 部分一致でも走査。
            out: List[DNSInteraction] = []
            for lst in self._interactions.values():
                for it in lst:
                    if token and token in it.qname:
                        out.append(it)
            return out

    def wait_for_interaction(self, token: str, timeout: float = 10.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.get_interactions(token):
                return True
            time.sleep(0.1)
        return False
