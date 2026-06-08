"""
Prototype Pollution Tester - Prototype Pollution 検出

Node.js/JavaScriptアプリケーションにおける
__proto__ 汚染脆弱性を検出する非破壊的テスター。

⚠️ 注意: 検出のみ、シスム改変は行わない
"""

import logging
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class PollutionVector(Enum):
    """汚染ベクター"""
    PROTO = "__proto__"
    CONSTRUCTOR = "constructor"
    PROTOTYPE = "prototype"
    QUERY_STRING = "query_string"
    JSON_BODY = "json_body"


@dataclass
class PrototypePollutionResult:
    """Prototype Pollution検出結果"""
    url: str
    parameter: str
    vector: PollutionVector
    payload: str
    vulnerable: bool = False
    evidence: str = ""
    confidence: float = 0.0
    severity: str = "high"
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "vector": self.vector.value,
            "payload": self.payload,
            "vulnerable": self.vulnerable,
            "confidence": self.confidence,
        }


class PrototypePollutionTester:
    """
    Prototype Pollution Tester
    
    機能:
    - __proto__ 汚染検出
    - constructor.prototype 汚染検出
    - クエリストリング/JSONボディ両対応
    - マーカーベース検証
    
    ⚠️ 非破壊的ペイロードのみ使用
    """
    
    # __proto__ ペイロード（クエリストリング形式）
    QUERY_PAYLOADS = [
        # 基本形式
        ("__proto__[polluted]", "shigoku_test", "__proto__"),
        ("__proto__.polluted", "shigoku_test", "__proto__"),
        # 配列形式
        ("__proto__[0]", "shigoku_test", "__proto__"),
        # 深いネスト
        ("__proto__[a][b]", "shigoku_test", "__proto__"),
        # constructor 経由
        ("constructor[prototype][polluted]", "shigoku_test", "constructor"),
        ("constructor.prototype.polluted", "shigoku_test", "constructor"),
        # URLエンコード
        ("__%70roto__%5Bpolluted%5D", "shigoku_test", "__proto__"),
    ]
    
    # JSON ペイロード
    JSON_PAYLOADS = [
        # 基本
        {"__proto__": {"polluted": "shigoku_test"}},
        # ネスト
        {"a": {"__proto__": {"polluted": "shigoku_test"}}},
        # constructor
        {"constructor": {"prototype": {"polluted": "shigoku_test"}}},
        # 配列内
        [{"__proto__": {"polluted": "shigoku_test"}}],
    ]
    
    # 汚染を示すマーカー
    POLLUTION_MARKER = "shigoku_test"
    
    # エラーパターン
    ERROR_PATTERNS = [
        r"Cannot\s+set\s+property",
        r"Object\s+prototype",
        r"__proto__",
        r"prototype\s+pollution",
        r"RangeError",
        r"TypeError",
    ]
    
    def __init__(
        self,
        timeout: float = 10.0,
        delay: float = 0.5,
    ):
        self.timeout = timeout
        self.delay = delay
        self.results: List[PrototypePollutionResult] = []
    
    def test(
        self,
        url: str,
        method: str = "GET",
        test_query: bool = True,
        test_json: bool = True,
        existing_params: Optional[Dict[str, str]] = None,
    ) -> List[PrototypePollutionResult]:
        """
        Prototype Pollutionテスト
        
        Args:
            url: テスト対象URL
            method: HTTPメソッド
            test_query: クエリストリングテスト
            test_json: JSONボディテスト
            existing_params: 既存のパラメータ
        
        Returns:
            検出結果リスト
        """
        results = []
        
        if test_query and method in ("GET", "POST"):
            results.extend(self._test_query_pollution(url, method, existing_params))
        
        if test_json and method in ("POST", "PUT", "PATCH"):
            results.extend(self._test_json_pollution(url, method))
        
        self.results.extend(results)
        return results
    
    def _test_query_pollution(
        self,
        url: str,
        method: str,
        existing_params: Optional[Dict[str, str]],
    ) -> List[PrototypePollutionResult]:
        """クエリストリング形式のテスト"""
        results = []
        
        for param, value, vector_type in self.QUERY_PAYLOADS:
            result = self._test_payload(
                url=url,
                parameter=param,
                payload=f"{param}={value}",
                vector=PollutionVector.QUERY_STRING,
                method=method,
            )
            if result:
                results.append(result)
        
        return results
    
    def _test_json_pollution(
        self,
        url: str,
        method: str,
    ) -> List[PrototypePollutionResult]:
        """JSONボディ形式のテスト"""
        results = []
        
        for payload_obj in self.JSON_PAYLOADS:
            payload_str = json.dumps(payload_obj)
            result = self._test_payload(
                url=url,
                parameter="body",
                payload=payload_str,
                vector=PollutionVector.JSON_BODY,
                method=method,
            )
            if result:
                results.append(result)
        
        return results
    
    def _test_payload(
        self,
        url: str,
        parameter: str,
        payload: str,
        vector: PollutionVector,
        method: str,
    ) -> Optional[PrototypePollutionResult]:
        """
        単一ペイロードテスト（プレースホルダー）
        """
        logger.info(
            "Testing prototype pollution: %s on %s",
            payload[:50], url
        )
        
        result = PrototypePollutionResult(
            url=url,
            parameter=parameter,
            vector=vector,
            payload=payload,
        )
        
        # プレースホルダー
        # 実際:
        # 1. ペイロード送信
        # 2. レスポンスでマーカー検出
        # 3. 別エンドポイントでマーカー確認（汚染の伝播）
        
        return result
    
    def _verify_pollution(
        self,
        url: str,
        response_text: str,
    ) -> bool:
        """汚染が成功したか検証"""
        # マーカーがレスポンスに含まれるか
        if self.POLLUTION_MARKER in response_text:
            return True
        
        # 予期しないプロパティの出現
        try:
            data = json.loads(response_text)
            if self._check_pollution_in_object(data):
                return True
        except json.JSONDecodeError:
            pass
        
        return False
    
    def _check_pollution_in_object(
        self,
        obj: any,
        depth: int = 0,
    ) -> bool:
        """オブジェクト内の汚染チェック（再帰）"""
        if depth > 10:
            return False
        
        if isinstance(obj, dict):
            if "polluted" in obj:
                return True
            for value in obj.values():
                if self._check_pollution_in_object(value, depth + 1):
                    return True
        elif isinstance(obj, list):
            for item in obj:
                if self._check_pollution_in_object(item, depth + 1):
                    return True
        
        return False
    
    def test_specific_property(
        self,
        url: str,
        property_name: str,
        property_value: str = "true",
    ) -> Optional[PrototypePollutionResult]:
        """
        特定プロパティの汚染テスト
        
        Args:
            url: テスト対象URL
            property_name: 汚染したいプロパティ名（例: "isAdmin"）
            property_value: 設定したい値
        
        Returns:
            検出結果
        """
        payloads = [
            f"__proto__[{property_name}]={property_value}",
            json.dumps({"__proto__": {property_name: property_value}}),
        ]
        
        for payload in payloads:
            result = PrototypePollutionResult(
                url=url,
                parameter=f"__proto__[{property_name}]",
                vector=PollutionVector.PROTO,
                payload=payload,
            )
            self.results.append(result)
        
        return None
    
    def get_vulnerable(self) -> List[PrototypePollutionResult]:
        """脆弱と判定された結果のみ"""
        return [r for r in self.results if r.vulnerable]
    
    def get_summary(self) -> Dict:
        """サマリー"""
        by_vector = {}
        
        for r in self.results:
            by_vector[r.vector.value] = by_vector.get(r.vector.value, 0) + (1 if r.vulnerable else 0)
        
        return {
            "total_tests": len(self.results),
            "vulnerable": len(self.get_vulnerable()),
            "by_vector": by_vector,
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"Prototype Pollution Test: {summary['total_tests']} tests\n"
            f"Vulnerable: {summary['vulnerable']}\n"
            f"By vector: {summary['by_vector']}"
        )


def create_prototype_pollution_tester(
    timeout: float = 10.0,
) -> PrototypePollutionTester:
    """PrototypePollutionTester作成ヘルパー"""
    return PrototypePollutionTester(timeout=timeout)
