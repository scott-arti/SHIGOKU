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
