"""
GraphQL Analyzer - GraphQL Introspection

スキーマ抽出・攻撃ベクトル検出
"""

import json
import logging
import asyncio
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from urllib.parse import urlencode

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

logger = logging.getLogger(__name__)


# Introspectionクエリ
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}
"""


@dataclass
class GraphQLField:
    """GraphQLフィールド"""
    name: str
    type_name: str = ""
    args: List[Dict] = field(default_factory=list)
    description: str = ""


@dataclass
class GraphQLType:
    """GraphQL型"""
    name: str
    kind: str = ""
    fields: List[GraphQLField] = field(default_factory=list)
    description: str = ""


@dataclass
class GraphQLSchema:
    """GraphQLスキーマ"""
    query_type: str = ""
    mutation_type: str = ""
    subscription_type: str = ""
    types: List[GraphQLType] = field(default_factory=list)
    

@dataclass
class GraphQLAnalysisResult:
    """分析結果"""
    introspection_enabled: bool = False
    graphiql_enabled: bool = False
    field_suggestions_enabled: bool = False
    is_large_schema: bool = False
    schema: Optional[GraphQLSchema] = None
    queries: List[str] = field(default_factory=list)
    mutations: List[str] = field(default_factory=list)
    sensitive_fields: List[str] = field(default_factory=list)
    suggested_fields: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)


class GraphQLAnalyzer:
    """
    GraphQL Introspection分析
    
    機能:
    - Introspection有効性検出
    - スキーマ抽出
    - 機密フィールド検出
    - 攻撃ベクトル提案
    """
    
    # 機密フィールドパターン
    SENSITIVE_PATTERNS = [
        "password", "secret", "token", "key", "auth",
        "credential", "private", "ssn", "credit",
        "admin", "role", "permission", "internal",
    ]
    
    # 危険なMutationパターン
    DANGEROUS_MUTATIONS = [
        "delete", "remove", "drop", "destroy",
        "update", "modify", "change", "set",
        "create", "add", "insert", "register",
        "admin", "grant", "revoke",
    ]
    
    def __init__(self, auth_headers: Optional[Dict] = None, config: Optional[Dict] = None):
        self.auth_headers = auth_headers or {}
        self.config = config or {}
        self.results: List[GraphQLAnalysisResult] = []
        self._client: Optional[httpx.Client] = None
        self.TIMEOUT = self.config.get("timeout", 15)
        self.TIMEOUT_LARGE = self.config.get("timeout_large_schema", 45)
        self.LARGE_SCHEMA_THRESHOLD = self.config.get("large_schema_threshold", 500)
    
    def analyze(self, endpoint: str) -> GraphQLAnalysisResult:
        """
        GraphQLエンドポイントを分析（複数手法）
        
        Args:
            endpoint: GraphQL APIエンドポイント
        """
        result = GraphQLAnalysisResult()

        # 1. GraphiQL UI検出（軽量）
        result.graphiql_enabled = self._try_graphiql_ui(endpoint)
        if result.graphiql_enabled:
            logger.info("GraphiQL UI detected on %s", endpoint)

        # 2. Introspection試行（複数手法）
        schema_data = self._try_introspection(endpoint, use_get=False)
        if not schema_data:
            schema_data = self._try_introspection(endpoint, use_get=True)
        if not schema_data:
            schema_data = self._try_introspection_bypass(endpoint)

        if schema_data:
            result.introspection_enabled = True
            result.schema = self._parse_schema(schema_data)
            result.queries = self._extract_operations(result.schema, "Query")
            result.mutations = self._extract_operations(result.schema, "Mutation")
            result.sensitive_fields = self._find_sensitive_fields(result.schema)
            result.attack_vectors = self._suggest_attack_vectors(result)

            # 大規模スキーマ検出
            schema_size = self._estimate_schema_size(schema_data)
            result.is_large_schema = schema_size > self.LARGE_SCHEMA_THRESHOLD
            logger.info(
                "GraphQL schema parsed: %d types, %d fields",
                len(schema_data.get("types", [])),
                schema_size,
            )

        # 3. Field Suggestions検出
        suggestions = self._try_field_suggestions(endpoint)
        if suggestions:
            result.field_suggestions_enabled = True
            result.suggested_fields = suggestions
            logger.info("Field suggestions enabled on %s: %s", endpoint, suggestions[:3])

        self.results.append(result)
        return result

    async def analyze_async(self, endpoint: str) -> GraphQLAnalysisResult:
        """非同期分析エントリポイント"""
        return await asyncio.to_thread(self.analyze, endpoint)

    def analyze_sync(self, endpoint: str) -> GraphQLAnalysisResult:
        """同期版（リソース自動解放）"""
        try:
            return self.analyze(endpoint)
        finally:
            self.close()
    
    def _get_client(self) -> httpx.Client:
        """Client生成（再利用・タイムアウト設定）"""
        if self._client is None:
            self._client = httpx.Client(
                timeout=self.TIMEOUT,
                follow_redirects=False,
                headers=self.auth_headers,
            )
        return self._client

    def close(self):
        """リソース解放"""
        if self._client:
            self._client.close()
            self._client = None

    def _try_introspection(self, endpoint: str, use_get: bool = False) -> Optional[Dict]:
        """POST/GET Introspection試行"""
        if not HAS_HTTPX:
            logger.warning("httpx not available for GraphQL introspection")
            return None

        client = self._get_client()

        try:
            if use_get:
                query_param = urlencode({"query": INTROSPECTION_QUERY})
                url = f"{endpoint}?{query_param}"
                response = client.get(url)
            else:
                headers = {**self.auth_headers, "Content-Type": "application/json"}
                payload = {"query": INTROSPECTION_QUERY}
                response = client.post(endpoint, json=payload, headers=headers)

        except httpx.TimeoutException:
            logger.warning("GraphQL introspection timeout on %s (get=%s)", endpoint, use_get)
            return None
        except httpx.ConnectError as e:
            logger.warning("GraphQL connection error on %s: %s", endpoint, e)
            return None
        except httpx.HTTPStatusError as e:
            logger.debug("GraphQL HTTP error on %s: %s", endpoint, e.response.status_code)
            return None
        except Exception as exc:
            logger.debug("GraphQL introspection error on %s: %s", endpoint, exc)
            return None

        if not response.is_success:
            return None

        try:
            data = response.json()
        except json.JSONDecodeError:
            return None

        schema = data.get("data", {}).get("__schema")
        if schema:
            logger.info("GraphQL introspection success on %s (get=%s)", endpoint, use_get)
            return schema

        errors = data.get("errors", [])
        if errors:
            logger.debug("GraphQL introspection disabled on %s: %s", endpoint, errors[:1])
        return None

    def _try_introspection_bypass(self, endpoint: str) -> Optional[Dict]:
        """Content-Typeバイパス試行"""
        if not HAS_HTTPX:
            return None

        client = self._get_client()
        headers = {
            **self.auth_headers,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        payload = urlencode({"query": INTROSPECTION_QUERY})

        try:
            response = client.post(endpoint, content=payload, headers=headers)
        except Exception:
            return None

        if not response.is_success:
            return None

        try:
            data = response.json()
        except Exception:
            return None

        return data.get("data", {}).get("__schema")

    def _try_graphiql_ui(self, endpoint: str) -> bool:
        """GraphiQL Explorer UI検出"""
        if not HAS_HTTPX:
            return False

        client = self._get_client()

        try:
            response = client.get(
                endpoint,
                headers={
                    **self.auth_headers,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                }
            )

            if not response.is_success:
                return False

            content_type = response.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type:
                return False

            indicators = ["GraphiQL", "graphiql", "graphql-playground", "apollo-server", "altair"]
            text = response.text[:5000]
            return any(ind in text for ind in indicators)

        except Exception as exc:
            logger.debug("GraphiQL detection error on %s: %s", endpoint, exc)
            return False

    def _try_field_suggestions(self, endpoint: str) -> Optional[List[str]]:
        """Field Suggestions有効性検出"""
        if not HAS_HTTPX:
            return None

        client = self._get_client()
        test_query = "{ thisFieldDoesNotExist12345 }"
        payload = {"query": test_query}

        try:
            response = client.post(
                endpoint,
                json=payload,
                headers={**self.auth_headers, "Content-Type": "application/json"},
            )
        except Exception:
            return None

        if not response.is_success:
            return None

        try:
            data = response.json()
        except Exception:
            return None

        errors = data.get("errors", [])
        suggestions = []

        for error in errors:
            message = error.get("message", "")
            if "did you mean" in message.lower():
                import re
                matches = re.findall(r'"([^"]+)"', message)
                suggestions.extend(matches)

        return suggestions[:10] if suggestions else None

    def _estimate_schema_size(self, schema_data: Dict) -> int:
        """スキーマサイズ推定（timeout調整用）"""
        types = schema_data.get("types", [])
        return sum(len(t.get("fields", [])) for t in types)
    
    def _parse_schema(self, schema_data: Dict) -> GraphQLSchema:
        """スキーマパース"""
        schema = GraphQLSchema()
        
        schema.query_type = schema_data.get("queryType", {}).get("name", "")
        schema.mutation_type = schema_data.get("mutationType", {}).get("name", "")
        schema.subscription_type = schema_data.get("subscriptionType", {}).get("name", "")
        
        for type_data in schema_data.get("types", []):
            if type_data["name"].startswith("__"):
                continue  # 内部型スキップ
            
            gql_type = GraphQLType(
                name=type_data["name"],
                kind=type_data.get("kind", ""),
                description=type_data.get("description", ""),
            )
            
            for field_data in type_data.get("fields", []) or []:
                gql_field = GraphQLField(
                    name=field_data["name"],
                    description=field_data.get("description", ""),
                    args=[a["name"] for a in field_data.get("args", [])],
                )
                gql_type.fields.append(gql_field)
            
            schema.types.append(gql_type)
        
        return schema
    
    def _extract_operations(self, schema: GraphQLSchema, type_name: str) -> List[str]:
        """Query/Mutationオペレーション抽出"""
        for t in schema.types:
            if t.name == type_name:
                return [f.name for f in t.fields]
        return []
    
    def _find_sensitive_fields(self, schema: GraphQLSchema) -> List[str]:
        """機密フィールド検出"""
        sensitive = []
        
        for t in schema.types:
            for f in t.fields:
                field_name = f.name.lower()
                for pattern in self.SENSITIVE_PATTERNS:
                    if pattern in field_name:
                        sensitive.append(f"{t.name}.{f.name}")
                        break
        
        return sensitive
    
    def _suggest_attack_vectors(self, result: GraphQLAnalysisResult) -> List[str]:
        """攻撃ベクトル提案"""
        vectors = []
        
        if result.introspection_enabled:
            vectors.append("Introspection有効 - スキーマ全体が露出")
        
        if result.sensitive_fields:
            vectors.append(f"機密フィールド検出: {len(result.sensitive_fields)}件")
        
        # 危険なMutation検出
        dangerous = []
        for m in result.mutations:
            m_lower = m.lower()
            for pattern in self.DANGEROUS_MUTATIONS:
                if pattern in m_lower:
                    dangerous.append(m)
                    break
        
        if dangerous:
            vectors.append(f"危険なMutation: {dangerous[:5]}")
        
        # バッチクエリ
        vectors.append("バッチクエリ攻撃の可能性を確認")
        
        # ネスト攻撃
        vectors.append("深いネストによるDoS可能性を確認")
        
        return vectors
    
    def get_summary(self) -> Dict:
        """サマリー"""
        total = len(self.results)
        introspection_enabled = sum(1 for r in self.results if r.introspection_enabled)
        
        return {
            "total_analyzed": total,
            "introspection_enabled": introspection_enabled,
            "total_sensitive_fields": sum(len(r.sensitive_fields) for r in self.results),
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"GraphQL Analysis: {summary['total_analyzed']} endpoints\n"
            f"Introspection enabled: {summary['introspection_enabled']}\n"
            f"Sensitive fields: {summary['total_sensitive_fields']}"
        )


def create_graphql_analyzer() -> GraphQLAnalyzer:
    """GraphQLAnalyzer作成ヘルパー"""
    return GraphQLAnalyzer()


def get_introspection_query() -> str:
    """Introspectionクエリ取得"""
    return INTROSPECTION_QUERY
