"""SGK-2026-0500: LocalDNSOOBProvider（DNS OOB プロバイダ）の検証。OOBProvider プロトコル充足・
new_callback（URL/ホスト名）・poll が受信 DNS クエリ FQDN を path に写像することを実 UDP で確認。"""

import asyncio
import socket
import struct

from src.core.detection.oob_provider import LocalDNSOOBProvider, OOBProvider


def _build_query(qname: str) -> bytes:
    parts = qname.split(".")
    q = b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"
    return struct.pack(">HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)


def test_satisfies_oob_provider_protocol():
    prov = LocalDNSOOBProvider(host="127.0.0.1", port=15371)
    assert isinstance(prov, OOBProvider)
    assert prov.channel == "dns"


def test_new_callback_url_and_hostname_only():
    prov = LocalDNSOOBProvider(host="127.0.0.1", port=15372, base_domain="oob.test")
    url, token = prov.new_callback()
    assert url == f"http://{token}.oob.test/"
    prov_h = LocalDNSOOBProvider(host="127.0.0.1", port=15373, base_domain="oob.test",
                                 hostname_only=True)
    host, token2 = prov_h.new_callback()
    assert host == f"{token2}.oob.test"


def test_poll_maps_query_fqdn_to_path():
    async def _run():
        prov = LocalDNSOOBProvider(host="127.0.0.1", port=15374, base_domain="oob.test")
        await prov.start()
        try:
            url, token = prov.new_callback()
            hostname = url[len("http://"):].rstrip("/")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(_build_query(hostname), ("127.0.0.1", 15374))
            inter = await prov.poll(token, timeout=3.0)
            return inter, token
        finally:
            await prov.stop()

    inter, token = asyncio.run(_run())
    assert inter is not None
    assert inter["channel"] == "dns"
    assert inter["method"] == "DNS"
    # 確定バーは token in interaction.path で発火するため path に FQDN が写像される。
    assert token in inter["path"]


def test_poll_returns_none_without_query():
    async def _run():
        prov = LocalDNSOOBProvider(host="127.0.0.1", port=15375, base_domain="oob.test")
        await prov.start()
        try:
            _url, token = prov.new_callback()
            return await prov.poll(token, timeout=1.0)
        finally:
            await prov.stop()

    assert asyncio.run(_run()) is None
