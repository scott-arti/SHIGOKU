"""
LocalOOBListener - ローカル OOB (Out-of-Band) 検知サーバー

外部サービス (Interactsh等) に依存せず、ローカルで HTTP リスナーを起動し、
SSRF や Blind RCE からのコールバックを検知する。

主な機能:
- aiohttp.web による軽量 HTTP サーバー
- トークンベースのインタラクション検知
- 非同期待機機能
"""

import asyncio
import logging
import time
import secrets
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Any

from aiohttp import web

logger = logging.getLogger(__name__)


@dataclass
class OOBInteraction:
    """検知されたインタラクション"""
    token: str
    remote_ip: str
    method: str
    path: str
    query_string: str
    timestamp: float
    raw_headers: Dict[str, str]


class LocalOOBListener:
    """ローカル OOB リスナー"""

    def __init__(self, host: str = "0.0.0.0", port: int = 13337):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}" if host != "0.0.0.0" else f"http://127.0.0.1:{port}"
        
        self._app = web.Application()
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        
        # トークンごとのイベント通知用
        # token -> asyncio.Event
        self._waiters: Dict[str, asyncio.Event] = {}
        
        # 検知済みインタラクションの履歴
        # token -> List[OOBInteraction]
        self._interactions: Dict[str, List[OOBInteraction]] = {}
        
        # ルーティング設定
        self._app.router.add_route('*', '/callback/{token}', self._handle_callback)
        self._app.router.add_route('*', '/{token}', self._handle_callback)  # ルート直下も拾う

    async def start(self):
        """サーバーを起動"""
        if self._runner:
            return  # 既に起動中

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.host, self.port)
        await self._site.start()
        
        logger.info(f"👂 LocalOOBListener started at {self.host}:{self.port}")

    async def stop(self):
        """サーバーを停止"""
        if self._site:
            await self._site.stop()
        if self._runner:
            await self._runner.cleanup()
        
        self._site = None
        self._runner = None
        logger.info("LocalOOBListener stopped")

    async def _handle_callback(self, request: web.Request) -> web.Response:
        """コールバックハンドラ"""
        token = request.match_info.get('token', 'unknown')
        
        interaction = OOBInteraction(
            token=token,
            remote_ip=request.remote or "unknown",
            method=request.method,
            path=request.path,
            query_string=request.query_string,
            timestamp=time.time(),
            raw_headers=dict(request.headers)
        )
        
        # 履歴に保存
        if token not in self._interactions:
            self._interactions[token] = []
        self._interactions[token].append(interaction)
        
        logger.info(f"🔔 OOB Interaction detected! Token: {token}, IP: {interaction.remote_ip}")
        
        # Phase 4: FlagWatcher Hook
        from src.core.engine.flag_watcher import FlagWatcher
        # ヘッダーやパスも対象に含める
        content_to_check = f"Path: {interaction.path}, Token: {token}, Headers: {interaction.raw_headers}"
        FlagWatcher.get_instance().check(content_to_check, source=f"OOB:{token}")
        
        # 待機中のイベントを発火
        if token in self._waiters:
            self._waiters[token].set()
            
        return web.Response(text="OK")

    def generate_payload(self) -> tuple[str, str]:
        """
        検証用ペイロードを生成
        
        Returns:
            (url, token) のタプル
        """
        token = secrets.token_hex(4)
        url = f"{self.base_url}/callback/{token}"
        return url, token

    async def wait_for_interaction(self, token: str, timeout: float = 10.0) -> bool:
        """
        指定されたトークンのインタラクションを待つ
        
        Args:
            token: 監視対象トークン
            timeout: タイムアウト（秒）
            
        Returns:
            検知できた場合 True
        """
        # 既に検知済みの場合
        if token in self._interactions and self._interactions[token]:
            return True
            
        # イベントを作成して待機
        event = asyncio.Event()
        self._waiters[token] = event
        
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False
        finally:
            if token in self._waiters:
                del self._waiters[token]

    def get_interactions(self, token: str) -> List[OOBInteraction]:
        """指定トークンのインタラクション履歴を取得"""
        return self._interactions.get(token, [])

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()


# シングルトン管理用（必要であれば）
_global_listener: Optional[LocalOOBListener] = None

def get_oob_listener() -> LocalOOBListener:
    global _global_listener
    if not _global_listener:
        _global_listener = LocalOOBListener()
    return _global_listener
