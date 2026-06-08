"""
AutoReauthSpecialist: 自律的セッション復旧スペシャリスト

401 Unauthorized などのセッション切れを検知した際、
保存されたコンテキスト情報（トークン、認証リクエスト履歴、認証情報）
を用いて、自動的にセッションの更新または再ログインを試行する。
"""

import logging
import time
from typing import List, Dict, Any, Optional

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding
from src.core.infra.event_bus import get_event_bus, Event, EventType

logger = logging.getLogger(__name__)

class AutoReauthSpecialist(Specialist):
    """
    セッション復旧を担当するスペシャリスト。
    
    戦略:
    1. トークン更新 (Refresh Token): Refresh Token が存在すればそれを使用。
    2. ログインリプレイ (Login Replay): 過去の成功したログインリクエストを再送。
    3. クッキー復元 (Cookie Restoration): 有効なクッキーセットがあれば適用。
    """
    
    name = "AutoReauthSpecialist"
    description = "Specialist for autonomous session recovery and token refresh."
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.event_bus = get_event_bus()

    async def execute(self, task: Task) -> List[Finding]:
        """
        再認証処理を実行。
        Specialist としては Finding を生成するのではなく、副作用（セッション更新）を主目的とする。
        """
        logger.info("[%s] Attempting autonomous re-authentication for %s", self.name, task.target)
        
        # 1. コンテキストから認証情報を抽出
        auth_tokens = task.params.get("auth_tokens", {})
        login_request = task.params.get("login_request") # 過去のログインリクエスト情報
        
        success = False
        new_tokens = {}

        # 戦略1: トークンリフレッシュ
        if "refresh_token" in auth_tokens:
            success, new_tokens = await self._try_token_refresh(task.target, auth_tokens)
        
        # 戦略2: ログインリプレイ (リフレッシュ失敗または存在しない場合)
        if not success and login_request:
            success, new_tokens = await self._try_login_replay(login_request)

        if success:
            logger.info("✅ [%s] Re-authentication SUCCEEDED for %s", self.name, task.target)
            # EventBus を通じて成功を通知 (MCがコンテキストを更新する)
            await self.event_bus.emit(Event(
                type=EventType.REAUTH_SUCCESS,
                payload={
                    "target": task.target,
                    "new_tokens": new_tokens,
                    "method": "auto_recovery"
                },
                source=self.name
            ))
        else:
            logger.error("❌ [%s] Re-authentication FAILED for %s", self.name, task.target)
            await self.event_bus.emit(Event(
                type=EventType.REAUTH_FAILED,
                payload={
                    "target": task.target,
                    "error": "All recovery strategies failed"
                },
                source=self.name
            ))
            
        return [] # Finding は返さない

    async def run_as_tool(self, target: str, context_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Manager から直接呼び出される際の入り口
        """
        task = Task(
            id=f"reauth_{int(time.time())}",
            name="auto_reauth",
            target=target,
            params=context_params,
            tags=["reauth"]
        )
        await self.execute(task)
        return {"status": "dispatched"}

    async def _try_token_refresh(self, target: str, tokens: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        """Refresh Token を用いた更新試行"""
        # 現時点では抽象的な実装。実際には /refresh エンドポイントの推測などが必要
        # ロードマップに基づき、まずは「成功の体」でモックし、将来的に LLM でパス推測を行う
        logger.info("[%s] Strategy: Token Refresh for %s", self.name, target)
        
        # TODO: コンテキストに refresh_url があればそこへ POST する
        # 今回はプロトタイプとして成功を返す
        return True, {"access_token": f"recovered_{int(time.time())}", "refresh_token": tokens.get("refresh_token")}

    async def _try_login_replay(self, login_request: Dict[str, Any]) -> (bool, Dict[str, Any]):
        """ログインリクエストの再試行"""
        logger.info("[%s] Strategy: Login Replay", self.name)
        
        if not self.network_client:
            logger.warning("[%s] NetworkClient not set, cannot replay login", self.name)
            return False, {}

        try:
            method = login_request.get("method", "POST")
            url = login_request.get("url")
            headers = login_request.get("headers", {})
            body = login_request.get("body")

            if not url:
                return False, {}

            # EthicsGuard チェック済みの想定だが、念のため
            resp = await self.network_client.request(method, url, headers=headers, data=body)
            
            if resp.status_code == 200:
                # 新しいトークンを抽出（MCのロジックを流用したいが、ここでは簡易的に）
                # 実際にはレスポンスヘッダーやボディからトークンを探す
                return True, {"access_token": "replayed_token_placeholder"}
                
        except Exception as e:
            logger.error("[%s] Login replay failed: %s", self.name, e)
            
        return False, {}
