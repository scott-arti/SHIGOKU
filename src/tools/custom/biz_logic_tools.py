from typing import Dict, Any, List, Optional
import asyncio
import logging
from src.tools.base import BaseTool
from src.tools import ToolRegistry
from src.core.infra.network_client import AsyncNetworkClient

logger = logging.getLogger(__name__)

class BizLogicToolBase(BaseTool):
    """Business Logic 関連ツールの基本クラス"""
    
    async def _get_client(self, cookies: Optional[Dict[str, str]] = None) -> AsyncNetworkClient:
        """ネットワーククライアントを取得"""
        client = AsyncNetworkClient(cookies=cookies)
        await client.start()
        return client

@ToolRegistry.register
class IDORValidatorTool(BizLogicToolBase):
    """
    Insecure Direct Object Reference (IDOR) の脆弱性を検証するツール。
    
    オブジェクト識別子（IDなど）を別の有効な値に変更し、他人のデータにアクセス可能かを確認します。
    """
    name = "idor_validator"
    description = "Validate IDOR (Insecure Direct Object Reference) by modifying resource IDs."

    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "検証対象のURL (例: https://example.com/api/user/123)"},
                        "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"], "default": "GET"},
                        "idor_param": {"type": "string", "description": "IDORを検証するパラメータ名"},
                        "test_value": {"type": "string", "description": "テストに使用する別のID値"},
                        "cookies": {"type": "object", "description": "認証用Cookie"}
                    },
                    "required": ["url", "test_value"]
                }
            }
        }

    async def run(self, url: str, test_value: str, method: str = "GET", idor_param: str = "", cookies: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        client = await self._get_client(cookies)
        
        test_url = url
        if idor_param and idor_param in url:
            import re
            test_url = re.sub(rf"/{re.escape(idor_param)}", f"/{test_value}", url)

        try:
            res = await client.request(method, test_url)
            
            is_vulnerable = False
            confidence = "low"
            
            if res.status == 200:
                body_lower = res.body.lower()
                if not any(x in body_lower for x in ["error", "denied", "forbidden", "unauthorized"]):
                    is_vulnerable = True
                    confidence = "medium"
                    
            return {
                "url": test_url,
                "status": res.status,
                "is_vulnerable": is_vulnerable,
                "confidence": confidence,
                "evidence": res.body[:500]
            }
        finally:
            await client.close()

@ToolRegistry.register
class HiddenParamHunterTool(BizLogicToolBase):
    """
    隠しパラメータを探索するツール。
    """
    name = "hidden_param_hunter"
    description = "Hunt for hidden or sensitive parameters (e.g., debug=true, admin=1)."

    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "対象URL"},
                        "method": {"type": "string", "default": "GET"},
                        "cookies": {"type": "object"},
                        "max_params": {"type": "integer", "default": 20}
                    },
                    "required": ["url"]
                }
            }
        }

    async def run(self, url: str, method: str = "GET", cookies: Optional[Dict[str, str]] = None, max_params: int = 20) -> Dict[str, Any]:
        common_hidden_params = [
            "debug", "admin", "test", "dev", "internal", "config", "role", "privilege",
            "access", "bypass", "api_key", "secret", "user_id", "is_admin"
        ]
        
        client = await self._get_client(cookies)
        results = []
        
        try:
            original = await client.request(method, url)
            
            for param in common_hidden_params[:max_params]:
                for val in ["1", "true"]:
                    test_params = {param: val}
                    res = await client.request(method, url, params=test_params)
                    
                    if res.status != original.status or abs(len(res.body) - len(original.body)) > 100:
                        results.append({
                            "param": param,
                            "value": val,
                            "status": res.status,
                            "size_diff": len(res.body) - len(original.body),
                            "note": "Response changed"
                        })
            
            return {
                "found_anomalies": results,
                "count": len(results)
            }
        finally:
            await client.close()

@ToolRegistry.register
class AdminBypasserTool(BizLogicToolBase):
    """
    管理者アクセス制御のバイパスを試行するツール。
    """
    name = "admin_bypasser"
    description = "Attempt to bypass administrative access controls using typical techniques."

    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "対象の管理者エンドポイント"},
                        "cookies": {"type": "object"}
                    },
                    "required": ["url"]
                }
            }
        }

    async def run(self, url: str, cookies: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        bypass_headers = [
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1"}
        ]
        
        client = await self._get_client(cookies)
        results = []
        
        try:
            for headers in bypass_headers:
                res = await client.request("GET", url, headers=headers)
                if res.status == 200:
                    results.append({
                        "header": list(headers.keys())[0],
                        "status": res.status,
                        "is_bypassed": True
                    })
            
            return {
                "results": results,
                "success": any(r["is_bypassed"] for r in results)
            }
        finally:
            await client.close()

@ToolRegistry.register
class BizLogicRaceConditionTool(BizLogicToolBase):
    """
    レースコンディション（競合状態）の脆弱性を検証するツール。
    """
    name = "biz_logic_race_tester"
    description = "Test for race conditions by sending concurrent requests (Async version)."

    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "default": "POST"},
                        "data": {"type": "object"},
                        "concurrency": {"type": "integer", "default": 20},
                        "cookies": {"type": "object"}
                    },
                    "required": ["url"]
                }
            }
        }

    async def run(self, url: str, method: str = "POST", data: Optional[Dict[str, Any]] = None, concurrency: int = 20, cookies: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        client = await self._get_client(cookies)
        
        try:
            tasks = [client.request(method, url, json=data) for _ in range(concurrency)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            status_counts = {}
            for res in responses:
                if isinstance(res, Exception):
                    status_counts["error"] = status_counts.get("error", 0) + 1
                    continue
                status_counts[res.status] = status_counts.get(res.status, 0) + 1
            
            return {
                "total": concurrency,
                "status_counts": status_counts
            }
        finally:
            await client.close()
ST", data: Optional[Dict[str, Any]] = None, concurrency: int = 20, cookies: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        client = await self._get_client(cookies)
        
        try:
            # 同時実行
            tasks = [client.request(method, url, json=data) for _ in range(concurrency)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            status_counts = {}
            for res in responses:
                if isinstance(res, Exception):
                    status_counts["error"] = status_counts.get("error", 0) + 1
                    continue
                status_counts[res.status] = status_counts.get(res.status, 0) + 1
            
            return {
                "total": concurrency,
                "status_counts": status_counts,
                "note": "Check if successful actions exceeded limits (e.g., more than 1 purchase)."
            }
        finally:
            await client.close()
