
import logging
import re
from typing import Dict, Any, Optional, Callable, Awaitable

logger = logging.getLogger(__name__)

class RequestGuard:
    """
    ネットワーク層のガードレール。
    破壊的メソッド（POST/PUT/DELETE/PATCH）に対し、
    エンドポイント(method+URLパス)単位で人間の承認を要求する。
    一度承認されたエンドポイントはセッション中キャッシュされ、
    同一エンドポイントへの再承認は不要。
    """

    AGGRESSIVE_METHODS = ("POST", "PUT", "DELETE", "PATCH")

    def __init__(
        self, 
        mode: str = "bugbounty",
        hitl_callback: Optional[Callable[[Dict[str, Any]], Awaitable[bool]]] = None
    ):
        self.mode = mode
        self.hitl_callback = hitl_callback
        # キー: "POST:/api/users/{id}" -> bool (True: 許可, False: 拒否)
        self._approved_endpoints: Dict[str, bool] = {}

    def _normalize_path(self, url: str) -> str:
        """
        URLを正規化（数値ID、UUIDをワイルドカード化）
        例: /api/users/123 -> /api/users/{id}
            /api/items/550e8400-e29b-41d4-a716-446655440000 -> /api/items/{uuid}
        """
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        path = parsed.path
        
        # UUID 形式の置換
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        path = re.sub(uuid_pattern, '{uuid}', path, flags=re.IGNORECASE)
        
        # 数値 ID の置換 (3桁以上の数値を対象にするか、セグメント全体が数値の場合)
        # ここでは /123/ のようなセグメントを置換
        path = re.sub(r'/(?:\d+)(?=/|$)', '/{id}', path)
        
        return path

    def _make_key(self, method: str, url: str) -> str:
        return f"{method.upper()}:{self._normalize_path(url)}"

    async def check(self, method: str, url: str, source_agent: str = "") -> bool:
        """
        リクエスト実行前に呼ばれる。
        
        Returns:
            True: 実行許可
            False: ユーザー拒否 -> リクエストをスキップ
        """
        method_upper = method.upper()
        
        # GETは常に許可
        if method_upper not in self.AGGRESSIVE_METHODS:
            return True
        
        # CTFモードは全承認
        if self.mode == "ctf":
            return True
            
        key = self._make_key(method_upper, url)
        
        # キャッシュ確認
        if key in self._approved_endpoints:
            return self._approved_endpoints[key]
            
        # HITL承認が必要
        if self.hitl_callback:
            logger.info(f"[RequestGuard] Requesting approval for {method_upper} {url} from {source_agent}")
            
            task_info = {
                "type": "destructive_request",
                "method": method_upper,
                "url": url,
                "normalized_path": self._normalize_path(url),
                "agent": source_agent,
                "prompt": f"エージェント '{source_agent}' が破壊的な可能性のあるリクエストを行おうとしています:\n"
                          f"[{method_upper}] {url}\n"
                          f"このエンドポイント（および同様のパス）への通信を許可しますか？"
            }
            
            approved = await self.hitl_callback(task_info)
            self._approved_endpoints[key] = approved
            
            if approved:
                logger.info(f"[RequestGuard] User APPROVED {key}")
            else:
                logger.warning(f"[RequestGuard] User DENIED {key}")
                
            return approved
            
        # コールバックがない場合は、安全のため bugbounty モードでは拒否、それ以外は許可（暫定）
        if self.mode == "bugbounty":
            logger.error(f"[RequestGuard] No HITL callback set. Blocking aggressive request: {method_upper} {url}")
            return False
            
        return True

    def is_approved(self, method: str, url: str) -> bool:
        """キャッシュを確認（非同期ではない）"""
        key = self._make_key(method, url)
        return self._approved_endpoints.get(key, False)

# シングルトン管理用
_instance: Optional[RequestGuard] = None

def get_request_guard(mode: str = "bugbounty", hitl_callback=None) -> RequestGuard:
    global _instance
    if _instance is None:
        _instance = RequestGuard(mode=mode, hitl_callback=hitl_callback)
    else:
        normalized_mode = (mode or _instance.mode or "bugbounty").lower()
        if _instance.mode != normalized_mode:
            _instance.mode = normalized_mode
            _instance._approved_endpoints.clear()

        if hitl_callback is not None:
            _instance.hitl_callback = hitl_callback
    return _instance

def reset_request_guard():
    global _instance
    _instance = None
