"""
OOB (Out-of-Band) provider abstraction — SGK-2026-0494.

ブラインド脆弱性（in-band に何も返らない）の確認は「我々が生成した一意トークンが、我々の
管理下の受信器に、標的からのコールバックとして届いたか」で行う。受信器は差し替え可能にする：
  - ``LocalOOBProvider``  : 自前ローカル HTTP 受信（`LocalOOBListener`・依存ゼロ・ローカルラボ用）
  - （将来）自前ホスト interactsh プロバイダ（DNS＋HTTP・公開・実インターネット標的用）

エンジン／確定バーはこの抽象化としか話さない（宛先＝コールバック URL とトークンを配るだけ）。
受信器を差し替えても**宛先が変わるだけ**でエンジンは無改修（[[detection-capability-wiring-map]]）。

置き換え元: 旧 `oob_correlator.py`（poll/start_server が Placeholder のまま本番未使用）は
SGK-2026-0494 で削除し、本モジュールの実装に統一。
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Protocol, Tuple, runtime_checkable

from src.core.utils.oob_listener import LocalOOBListener

logger = logging.getLogger(__name__)


@runtime_checkable
class OOBProvider(Protocol):
    """OOB 受信器の共通インターフェース（プロバイダ非依存）。"""

    channel: str  # "http" / "dns" / "http+dns" 等

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def new_callback(self) -> Tuple[str, str]:
        """(callback_url, token) を返す。token は一意でペイロードに埋める。"""
        ...

    async def poll(self, token: str, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
        """token 宛のコールバック到達を待ち、来たら interaction record を返す（無ければ None）。"""
        ...


class LocalOOBProvider:
    """自前ローカル HTTP 受信（`LocalOOBListener` ラッパ）。依存ゼロ・決定論的。

    ローカルラボ用途では標的（多くは docker コンテナ）が受信器に到達できる必要がある。
    ``callback_base`` を与えると、ペイロードに埋める URL のホストを到達可能アドレス
    （例 docker gateway ``http://172.17.0.1:13337`` や公開アドレス）に差し替える。
    """

    channel = "http"

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 13337,
        callback_base: Optional[str] = None,
    ) -> None:
        self._listener = LocalOOBListener(host=host, port=port)
        self._callback_base = callback_base.rstrip("/") if callback_base else None

    async def start(self) -> None:
        await self._listener.start()

    async def stop(self) -> None:
        await self._listener.stop()

    def new_callback(self) -> Tuple[str, str]:
        url, token = self._listener.generate_payload()  # (url, token)
        if self._callback_base:
            url = f"{self._callback_base}/callback/{token}"
        return url, token

    async def poll(self, token: str, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
        received = await self._listener.wait_for_interaction(token, timeout=timeout)
        if not received:
            return None
        interactions = self._listener.get_interactions(token)
        if not interactions:
            return None

        def _as_dict(it: Any) -> Dict[str, Any]:
            return {
                "token": token,
                "channel": self.channel,
                "remote_ip": getattr(it, "remote_ip", ""),
                "method": getattr(it, "method", ""),
                "path": getattr(it, "path", ""),
                "query_string": getattr(it, "query_string", ""),
                "timestamp": getattr(it, "timestamp", 0.0),
                "headers": dict(getattr(it, "raw_headers", {}) or {}),
            }

        first = _as_dict(interactions[0])
        # 追加: 同一 token に届いた全インタラクション（例: Java ScriptEngineManager は
        # META-INF/services 取得→返した名前のクラス取得と複数回叩く）。生の受信ログとして
        # PoC に載せられるよう additive に付与する（既存 consumer は特定キーのみ参照）。
        first["interactions"] = [_as_dict(it) for it in interactions]
        return first

    async def __aenter__(self) -> "LocalOOBProvider":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()


class LocalDNSOOBProvider:
    """自前ローカル DNS 受信（`LocalDNSOOBListener` ラッパ）。真ブラインド（DNS-only）用。

    ``new_callback`` はデフォルトで URL ``http://<token>.<domain>/`` を返す（既存の blind
    XXE/SSRF エンジンは callback URL からペイロードを組むため無改修で使える。標的が
    ``<token>.<domain>`` を**名前解決するだけ**で DNS クエリが受信器に届き OOB 証拠になる。
    HTTP に到達できない真ブラインドでも DNS 解決だけで確定できるのが要点）。``hostname_only``
    を渡すと URL でなくホスト名そのものを返す（ホスト名を値に取る sink 用）。

    poll は受信した DNS クエリの **FQDN を ``path`` に写像**して返す（確定バーの汎用マーカー
    ``oob_interaction_received`` は ``token in interaction.path`` で発火するため payout_grade は
    無改修）。受信器の到達性: 本番は権威 DNS を自ドメインに委譲し :53 で受ける。ローカルは
    標的コンテナを ``docker --dns <受信器IP>`` で起動して名前解決を受信器へ向ける。
    """

    channel = "dns"

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 53,
        base_domain: str = "oob.test",
        hostname_only: bool = False,
    ) -> None:
        from src.core.utils.dns_oob_listener import LocalDNSOOBListener
        self._listener = LocalDNSOOBListener(
            host=host, port=port, base_domain=base_domain)
        self._hostname_only = hostname_only

    async def start(self) -> None:
        self._listener.start()

    async def stop(self) -> None:
        self._listener.stop()

    def new_callback(self) -> Tuple[str, str]:
        hostname, token = self._listener.generate_hostname()
        if self._hostname_only:
            return hostname, token
        return f"http://{hostname}/", token

    async def poll(self, token: str, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
        import asyncio

        loop = asyncio.get_event_loop()
        received = await loop.run_in_executor(
            None, self._listener.wait_for_interaction, token, timeout)
        if not received:
            return None
        interactions = self._listener.get_interactions(token)
        if not interactions:
            return None

        def _as_dict(it: Any) -> Dict[str, Any]:
            return {
                "token": token,
                "channel": self.channel,
                "remote_ip": getattr(it, "remote_ip", ""),
                "method": "DNS",
                # 確定バーは token in path で発火するため、問い合わせ FQDN を path に写像。
                "path": getattr(it, "qname", ""),
                "query_string": "",
                "qtype": getattr(it, "qtype", 0),
                "timestamp": getattr(it, "timestamp", 0.0),
                "headers": {},
            }

        first = _as_dict(interactions[0])
        first["interactions"] = [_as_dict(it) for it in interactions]
        return first

    async def __aenter__(self) -> "LocalDNSOOBProvider":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.stop()
