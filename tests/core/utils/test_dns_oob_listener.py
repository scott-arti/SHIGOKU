"""SGK-2026-0500: LocalDNSOOBListener（依存ゼロの DNS OOB 受信器）の検証。
QNAME 解析・token 記録・良性応答・ホスト名発行を、実 UDP ソケットで確認（外部依存なし）。"""

import socket
import struct
import time

from src.core.utils.dns_oob_listener import LocalDNSOOBListener, _parse_qname


def _build_query(qname: str, txid: int = 0x1234) -> bytes:
    parts = qname.split(".")
    q = b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return header + q + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN


def test_parse_qname_reconstructs_dotted_name():
    data = _build_query("abcd.oob.test")
    assert _parse_qname(data, 12) == "abcd.oob.test"


def _start(port):
    lis = LocalDNSOOBListener(host="127.0.0.1", port=port, base_domain="oob.test")
    lis.start()
    return lis


def test_records_query_with_token_and_returns_benign_answer():
    port = 15361
    lis = _start(port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(_build_query("deadbeef.oob.test"), ("127.0.0.1", port))
        resp, _ = s.recvfrom(4096)
        # 良性 A 応答（ヘッダの ANCOUNT>=1）。
        ancount = struct.unpack(">H", resp[6:8])[0]
        assert ancount >= 1
        assert lis.wait_for_interaction("deadbeef", timeout=3.0)
        ix = lis.get_interactions("deadbeef")
        assert ix and ix[0].qname == "deadbeef.oob.test"
        assert ix[0].qtype == 1
    finally:
        lis.stop()


def test_generate_hostname_embeds_token_and_domain():
    lis = LocalDNSOOBListener(host="127.0.0.1", port=15362, base_domain="oob.test")
    hostname, token = lis.generate_hostname()
    assert hostname == f"{token}.oob.test"
    assert len(token) >= 8


def test_get_interactions_substring_fallback():
    port = 15363
    lis = _start(port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        # token が先頭ラベルでない問い合わせでも部分一致で引ける。
        s.sendto(_build_query("x.cafed00d.oob.test"), ("127.0.0.1", port))
        time.sleep(0.5)
        ix = lis.get_interactions("cafed00d")
        assert any("cafed00d" in i.qname for i in ix)
    finally:
        lis.stop()


def test_short_packet_is_ignored():
    port = 15364
    lis = _start(port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"tooshort", ("127.0.0.1", port))
        time.sleep(0.3)
        # 記録が増えない（<12 バイトは無視・クラッシュしない）。
        assert lis.get_interactions("tooshort") == []
    finally:
        lis.stop()
