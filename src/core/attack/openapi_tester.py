"""
OpenAPI Tester - OpenAPI/Swagger自動テスト

全エンドポイント網羅テスト
"""

import logging
import json
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


@dataclass
class APIEndpoint:
    """APIエンドポイント"""
    path: str
    method: str
    operation_id: str = ""
    summary: str = ""
    parameters: List[Dict] = field(default_factory=list)
    request_body: Dict = field(default_factory=dict)
    security: List[Dict] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class APITestResult:
    """APIテスト結果"""
    endpoint: APIEndpoint
    status_code: int = 0
    response_time: float = 0.0
    auth_required: bool = False
    accessible_without_auth: bool = False
    error: str = ""


class OpenAPITester:
    """
    OpenAPI/Swaggerテスター
    
    機能:
    - OpenAPI仕様パース
    - 全エンドポイント抽出
    - 自動テスト生成
    - 認証バイパス検出
    """
    
    def __init__(self, base_url: str = ""):
        self.base_url = base_url
        self.spec: Dict = {}
        self.endpoints: List[APIEndpoint] = []
        self.results: List[APITestResult] = []
    
    def load_spec(self, spec_url: str = None, spec_data: Dict = None) -> bool:
        """
        OpenAPI仕様読み込み
        
        Args:
            spec_url: 仕様URL (e.g., /api/docs/openapi.json)
            spec_data: 仕様データ（直接指定）
        """
        if spec_data:
            self.spec = spec_data
            
        elif spec_url:
            try:
                # プレースホルダー
                # response = requests.get(spec_url)
                # self.spec = response.json()
                logger.info("Loading spec from %s", spec_url)
            except Exception as e:
                logger.error("Failed to load spec: %s", e)
                return False
        
        self._parse_endpoints()
        return len(self.endpoints) > 0
    
    def _parse_endpoints(self):
        """エンドポイント抽出"""
        self.endpoints = []
        
        paths = self.spec.get("paths", {})
        
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                    continue
                
                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    operation_id=details.get("operationId", ""),
                    summary=details.get("summary", ""),
                    parameters=details.get("parameters", []),
                    request_body=details.get("requestBody", {}),
                    security=details.get("security", []),
                    tags=details.get("tags", []),
                )
                
                self.endpoints.append(endpoint)
        
        logger.info("Parsed %d endpoints", len(self.endpoints))
    
    def discover_spec_urls(self, base_url: str) -> List[str]:
        """
        OpenAPI仕様URLを発見
        
        一般的なパスをチェック
        """
        common_paths = [
            "/openapi.json",
            "/swagger.json",
            "/api-docs",
            "/api/docs",
            "/api/openapi.json",
            "/api/swagger.json",
            "/v1/openapi.json",
            "/v2/openapi.json",
            "/docs/openapi.json",
            "/.well-known/openapi.json",
        ]
        
        found = []
        
        for path in common_paths:
            url = urljoin(base_url, path)
            # プレースホルダー: 実際にはリクエストして確認
            # if self._check_url(url):
            #     found.append(url)
            found.append(url)  # デモ用
        
        return found[:3]  # 最大3件
    
    def test_all(
        self,
        with_auth: bool = True,
        without_auth: bool = True
    ) -> List[APITestResult]:
        """
        全エンドポイントテスト
        
        Args:
            with_auth: 認証ありでテスト
            without_auth: 認証なしでテスト
        """
        results = []
        
        for endpoint in self.endpoints:
            result = self._test_endpoint(endpoint, with_auth, without_auth)
            results.append(result)
            self.results.append(result)
        
        return results
    
    def _test_endpoint(
        self,
        endpoint: APIEndpoint,
        with_auth: bool,
        without_auth: bool
    ) -> APITestResult:
        """
        エンドポイントテスト（プレースホルダー）
        """
        result = APITestResult(endpoint=endpoint)
        
        url = urljoin(self.base_url, endpoint.path)
        logger.info("Testing %s %s", endpoint.method, url)
        
        # プレースホルダー
        # 認証なしでのアクセス
        # response = requests.request(endpoint.method, url)
        # if response.status_code < 400:
        #     result.accessible_without_auth = True
        
        return result
    
    def find_auth_bypass(self) -> List[APITestResult]:
        """認証バイパス可能なエンドポイント"""
        return [r for r in self.results if r.accessible_without_auth and r.auth_required]
    
    def generate_test_requests(self) -> List[Dict]:
        """
        テストリクエスト生成
        
        各エンドポイント用のcurlコマンド/リクエスト情報を生成
        """
        requests_list = []
        
        for endpoint in self.endpoints:
            url = urljoin(self.base_url, endpoint.path)
            
            # パラメータをサンプル値で埋める
            sample_params = {}
            for param in endpoint.parameters:
                name = param.get("name", "")
                param_type = param.get("schema", {}).get("type", "string")
                
                if param_type == "integer":
                    sample_params[name] = 1
                elif param_type == "boolean":
                    sample_params[name] = True
                else:
                    sample_params[name] = "test"
            
            requests_list.append({
                "method": endpoint.method,
                "url": url,
                "params": sample_params,
                "operation": endpoint.operation_id,
            })
        
        return requests_list
    
    def get_summary(self) -> Dict:
        """サマリー"""
        by_method = {}
        for e in self.endpoints:
            by_method.setdefault(e.method, 0)
            by_method[e.method] += 1
        
        return {
            "total_endpoints": len(self.endpoints),
            "by_method": by_method,
            "tested": len(self.results),
            "auth_bypass_found": len(self.find_auth_bypass()),
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"OpenAPI: {summary['total_endpoints']} endpoints\n"
            f"By method: {summary['by_method']}\n"
            f"Auth bypass: {summary['auth_bypass_found']}"
        )


    def extract_privileged_properties(self) -> Dict[str, Any]:
        """
        OpenAPI仕様から特権昇格やIDORに繋がる可能性のあるプロパティを抽出・推測します。
        
        Returns:
            Dict[str, Any]: { プロパティ名: 推奨テスト値 }
        """
        privileged_keywords = [
            "admin", "role", "privilege", "permission", "status", "type", 
            "is_", "has_", "internal", "access", "level", "group", "verified"
        ]
        
        candidates = {}
        
        # 1. コンポーネント/スキーマの解析
        components = self.spec.get("components", {}).get("schemas", {})
        # Swagger 2.0 互換
        if not components:
            components = self.spec.get("definitions", {})
            
        for schema_name, schema in components.items():
            properties = schema.get("properties", {})
            for prop_name, prop_details in properties.items():
                low_name = prop_name.lower()
                if any(kw in low_name for kw in privileged_keywords):
                    # 型に基づいて値を推測
                    prop_type = prop_details.get("type", "string")
                    if prop_type == "boolean":
                        candidates[prop_name] = True
                    elif prop_type == "integer":
                        candidates[prop_name] = 1 # または 0
                    elif prop_type == "string":
                        # 列挙型があればそれを利用、なければ admin 等
                        enum = prop_details.get("enum")
                        if enum:
                            # 'admin' や 'root' などのキーワードが含まれるものを優先
                            admin_enum = [e for e in enum if any(kw in str(e).lower() for kw in ["admin", "root", "super", "master"])]
                            candidates[prop_name] = admin_enum[0] if admin_enum else enum[0]
                        else:
                            if "role" in low_name: candidates[prop_name] = "admin"
                            elif "status" in low_name: candidates[prop_name] = "active"
                            else: candidates[prop_name] = "admin"
        
        # 2. パスパラメータからも推測
        for endpoint in self.endpoints:
            for param in endpoint.parameters:
                name = param.get("name", "").lower()
                if any(kw in name for kw in privileged_keywords):
                    if name not in candidates:
                        candidates[param.get("name")] = "admin"

        logger.info("Extracted %d potential privileged properties from spec", len(candidates))
        return candidates


def create_openapi_tester(base_url: str = "") -> OpenAPITester:
    """OpenAPITester作成ヘルパー"""
    return OpenAPITester(base_url)
