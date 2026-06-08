"""
GraphQLNavigator: GraphQL API偵察・攻撃エージェント

GraphQLエンドポイントに対する自動偵察と脆弱性チェックを行う。
"""

import re
import logging
from typing import Dict, Any, List, Set, Optional
from dataclasses import dataclass
from src.core.infra.network_client import AsyncNetworkClient, NetworkClientError
from src.core.agents.base import BaseAgent, AgentConfig

logger = logging.getLogger(__name__)


@dataclass
class GraphQLSchema:
    """復元されたスキーマ情報"""
    types: List[str]
    queries: List[str]
    mutations: List[str]
    raw_introspection: Optional[Dict] = None


@dataclass
class GraphQLFinding:
    """GraphQL関連の発見"""
    type: str  # introspection_enabled, field_suggestion, batch_allowed, etc.
    severity: str  # info, low, medium, high
    detail: str


class GraphQLNavigator(BaseAgent):
    """
    GraphQL偵察エージェント
    
    機能:
    - Introspection Queryによるスキーマ取得
    - Introspection無効時のField Suggestion攻撃
    - Batch Query (Array) の可否チェック
    - DoS/Complexity攻撃の可能性評価
    """
    
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            types {
                name
                kind
                fields {
                    name
                    type { name kind }
                }
            }
            queryType { name }
            mutationType { name }
        }
    }
    """
    
    # Field Suggestion用のよくあるフィールド名
    COMMON_FIELDS = [
        "user", "users", "me", "admin", "login", "register",
        "email", "password", "token", "id", "name", "role",
        "order", "orders", "payment", "transaction", "config",
        "file", "upload", "download", "secret", "key", "flag"
    ]

    def __init__(self, config: AgentConfig, workspace_root: Optional[str] = None):
        super().__init__(config, workspace_root)
        self.timeout = 15
        self._client = None

    async def close(self):
        """リソース解放"""
        if self._client:
            await self._client.close()
            self._client = None

    def _get_client(self) -> AsyncNetworkClient:
        if not self._client:
            self._client = AsyncNetworkClient()
        return self._client

    async def process(self, input_message: str) -> str:
        """BaseAgent 互換の対話プロトコル（未実装）"""
        return "GraphQLNavigator is a specialized agent and does not support chat messages yet."

    async def explore(self, endpoint: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        GraphQLエンドポイントを探索
        
        Args:
            endpoint: GraphQL APIエンドポイントURL
            headers: 認証ヘッダー等
            
        Returns:
            探索結果
        """
        findings: List[GraphQLFinding] = []
        schema: Optional[GraphQLSchema] = None
        headers = headers or {}
        headers.setdefault("Content-Type", "application/json")
        
        # 1. Introspection試行
        logger.info("Attempting GraphQL Introspection on %s", endpoint)
        introspection_result = await self._try_introspection(endpoint, headers)
        
        if introspection_result:
            findings.append(GraphQLFinding(
                type="introspection_enabled",
                severity="medium",
                detail="Introspection is enabled. Full schema can be extracted."
            ))
            schema = self._parse_introspection(introspection_result)
        else:
            findings.append(GraphQLFinding(
                type="introspection_disabled",
                severity="info",
                detail="Introspection is disabled. Attempting field suggestion."
            ))
            # 2. Field Suggestion攻撃
            suggested_fields = await self._try_field_suggestion(endpoint, headers)
            if suggested_fields:
                findings.append(GraphQLFinding(
                    type="field_suggestion_leak",
                    severity="low",
                    detail=f"Field suggestions leaked: {', '.join(suggested_fields[:10])}"
                ))
        
        # 3. Batch Query チェック
        batch_allowed = await self._check_batch_query(endpoint, headers)
        if batch_allowed:
            findings.append(GraphQLFinding(
                type="batch_query_allowed",
                severity="low",
                detail="Batch queries (array) are allowed. Potential for abuse."
            ))
        
        return {
            "endpoint": endpoint,
            "findings": [self._finding_to_dict(f) for f in findings],
            "schema": self._schema_to_dict(schema) if schema else None,
            "finding_count": len(findings)
        }

    async def _try_introspection(self, endpoint: str, headers: Dict[str, str]) -> Optional[Dict]:
        """Introspectionクエリ実行"""
        try:
            payload = {"query": self.INTROSPECTION_QUERY}
            client = self._get_client()
            resp = await client.request("POST", endpoint, json=payload, headers=headers, timeout=self.timeout, follow_redirects=True, use_proxy_rotation=True)
            
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    return data["data"]["__schema"]
        except (NetworkClientError, TimeoutError) as e:
            logger.debug("Introspection failed (Network/Timeout): %s", e)
        except Exception as e:
            logger.debug("Unexpected error during introspection: %s", e)
        return None

    def _parse_introspection(self, schema_data: Dict) -> GraphQLSchema:
        """Introspection結果をパース"""
        types = []
        queries = []
        mutations = []
        
        for t in schema_data.get("types", []):
            name = t.get("name", "")
            if not name.startswith("__"):  # 内部型を除外
                types.append(name)
                
        query_type_name = schema_data.get("queryType", {}).get("name", "Query")
        mutation_type_obj = schema_data.get("mutationType")
        mutation_type_name = mutation_type_obj.get("name", "Mutation") if mutation_type_obj else None
        
        for t in schema_data.get("types", []):
            if t.get("name") == query_type_name:
                queries = [f.get("name") for f in t.get("fields", []) if f.get("name")]
            elif t.get("name") == mutation_type_name:
                mutations = [f.get("name") for f in t.get("fields", []) if f.get("name")]
        
        return GraphQLSchema(
            types=types,
            queries=queries,
            mutations=mutations,
            raw_introspection=schema_data
        )

    async def _try_field_suggestion(self, endpoint: str, headers: Dict[str, str]) -> List[str]:
        """Field Suggestion攻撃（エラーメッセージからフィールド名を推測）"""
        suggested = []
        
        for field in self.COMMON_FIELDS:
            try:
                # 意図的に存在しないフィールドを投げてエラーメッセージを見る
                query = f"{{ {field}_nonexistent }}"
                payload = {"query": query}
                client = self._get_client()
                resp = await client.request("POST", endpoint, json=payload, headers=headers, timeout=self.timeout, follow_redirects=True, use_proxy_rotation=True)
                
                if resp.status_code == 200:
                    data = resp.json()
                    errors = data.get("errors", [])
                    for error in errors:
                        msg = error.get("message", "")
                        # "Did you mean ..." パターンを探す
                        match = re.search(r'Did you mean ["\']?(\w+)["\']?', msg, re.IGNORECASE)
                        if match:
                            suggested.append(match.group(1))
                        # または単に存在するフィールドを示唆するパターン
                        match2 = re.search(r'Cannot query field.*on type.*Did you mean (.+)\?', msg)
                        if match2:
                            candidates = re.findall(r'["\'](\w+)["\']', match2.group(1))
                            suggested.extend(candidates)
            except Exception:
                pass
        
        return list(set(suggested))

    async def _check_batch_query(self, endpoint: str, headers: Dict[str, str]) -> bool:
        """Batch Query（複数クエリ配列）の可否チェック"""
        try:
            # 配列で2つのクエリを送信
            payload = {"query": self.INTROSPECTION_QUERY}
            client = self._get_client()
            resp = await client.request("POST", endpoint, json=payload, headers=headers, timeout=self.timeout, follow_redirects=True, use_proxy_rotation=True)
            
            if resp.status_code == 200:
                data = resp.json()
                # 配列で返ってきたらBatch対応
                if isinstance(data, list) and len(data) == 2:
                    return True
        except (NetworkClientError, TimeoutError):
            pass
        except Exception as e:
            logger.debug("Unexpected error during batch query check: %s", e)
        return False

    def _finding_to_dict(self, f: GraphQLFinding) -> Dict[str, Any]:
        return {
            "type": f.type,
            "severity": f.severity,
            "detail": f.detail
        }

    def _schema_to_dict(self, s: GraphQLSchema) -> Dict[str, Any]:
        return {
            "types": s.types[:20],  # 上位20個
            "queries": s.queries,
            "mutations": s.mutations
        }

    async def execute(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """MasterConductor互換の実行メソッド"""
        endpoint = params.get("endpoint", target)
        headers = params.get("headers")
        
        if not endpoint.startswith("http"):
            return {
                "success": False,
                "error": "Valid GraphQL endpoint URL required"
            }
        
        result = await self.explore(endpoint, headers)
        result["success"] = True
        return result
