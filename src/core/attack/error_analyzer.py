"""
Error Message Analyzer - エラーメッセージ解析

サーバーからのエラーメッセージを解析し、
バリデーションルールや技術スタックを推測。

用途:
- バリデーションルールの逆算
- 技術スタック/フレームワーク推測
- 脆弱性ヒントの抽出
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class ErrorCategory(Enum):
    """エラーカテゴリ"""
    VALIDATION = "validation"       # バリデーションエラー
    DATABASE = "database"           # データベースエラー
    AUTHENTICATION = "authentication"  # 認証エラー
    AUTHORIZATION = "authorization"    # 認可エラー
    SERVER = "server"               # サーバーエラー
    FRAMEWORK = "framework"         # フレームワークエラー
    WAF = "waf"                     # WAFエラー
    UNKNOWN = "unknown"


@dataclass
class ValidationRule:
    """推測されたバリデーションルール"""
    field: str
    rule_type: str  # length, format, type, range, regex, etc.
    constraint: str
    confidence: float


@dataclass
class ErrorAnalysis:
    """エラー解析結果"""
    original_message: str
    category: ErrorCategory
    tech_stack: List[str]
    validation_rules: List[ValidationRule]
    hints: List[str]
    bypass_suggestions: List[str]
    severity: str = "info"


class ErrorMessageAnalyzer:
    """
    Error Message Analyzer
    
    機能:
    - エラーメッセージ分類
    - バリデーションルール抽出
    - 技術スタック推測
    - バイパス提案
    """
    
    # 技術スタック検出パターン
    TECH_STACK_PATTERNS = {
        # Frameworks
        "Django": [r"django", r"CSRF verification failed", r"DisallowedHost"],
        "Flask": [r"flask", r"werkzeug", r"Method Not Allowed"],
        "Rails": [r"ActionController", r"ActiveRecord", r"Ruby on Rails"],
        "Laravel": [r"laravel", r"Illuminate\\", r"CSRF token mismatch"],
        "Spring": [r"springframework", r"Whitelabel Error Page", r"Spring Boot"],
        "Express": [r"express", r"Cannot (GET|POST)", r"node_modules"],
        "ASP.NET": [r"ASP\.NET", r"Server Error in", r"__VIEWSTATE"],
        
        # Databases
        "MySQL": [r"mysql", r"MySQLSyntaxError", r"SQLSTATE\[42"],
        "PostgreSQL": [r"postgresql", r"PG::SyntaxError", r"SQLSTATE\[42"],
        "MongoDB": [r"mongodb", r"MongoError", r"BSONType"],
        "MSSQL": [r"mssql", r"SQL Server", r"ODBC Driver"],
        
        # Servers
        "Nginx": [r"nginx", r"502 Bad Gateway"],
        "Apache": [r"apache", r"mod_security", r"Bad Request"],
        
        # WAFs
        "Cloudflare": [r"cloudflare", r"cf-ray", r"Ray ID"],
        "ModSecurity": [r"mod_security", r"ModSecurity"],
        "AWS WAF": [r"aws", r"x-amzn-requestid"],
    }
    
    # バリデーションルール検出パターン
    VALIDATION_PATTERNS = [
        # 長さ
        (r"(must be|should be|maximum)\s*(less than|at most|under)?\s*(\d+)\s*(characters?|chars?|bytes?|length)?",
         "length", "max"),
        (r"(must be|should be|minimum)\s*(more than|at least|over)?\s*(\d+)\s*(characters?|chars?|bytes?|length)?",
         "length", "min"),
        (r"between\s*(\d+)\s*and\s*(\d+)",
         "length", "range"),
        
        # 型
        (r"must be\s*(a|an)?\s*(integer|number|numeric|string|boolean)",
         "type", "type"),
        (r"invalid\s*(integer|number|email|url|date)",
         "type", "type"),
        
        # フォーマット
        (r"invalid\s*(format|email|url|date|phone)",
         "format", "format"),
        (r"does not match\s*(pattern|format|regex)",
         "format", "regex"),
        
        # 文字種
        (r"(alphanumeric|letters?|digits?|special characters?)\s*(only|not allowed|required)",
         "charset", "charset"),
        (r"(cannot|must not)\s*contain\s*(special characters?|spaces?|symbols?)",
         "charset", "forbidden"),
    ]
    
    # バイパス提案マッピング
    BYPASS_SUGGESTIONS = {
        "length_max": [
            "ペイロードを短縮",
            "分割して複数リクエストで送信",
            "圧縮エンコーディング使用",
        ],
        "type_integer": [
            "文字列形式の数値を試行（'1'）",
            "科学表記を試行（1e0）",
            "16進数形式を試行（0x1）",
        ],
        "format_email": [
            "技術的に有効だが珍しい形式を使用",
            "コメント形式を使用（user(comment)@example.com）",
            "IPアドレス形式を使用（user@[127.0.0.1]）",
        ],
        "charset_forbidden": [
            "URLエンコード",
            "Unicodeエスケープ",
            "HTMLエンティティ",
        ],
        "waf_blocked": [
            "ケース変更（大小文字混合）",
            "コメント挿入",
            "ダブルURLエンコード",
        ],
    }
    
    def __init__(self):
        self.history: List[ErrorAnalysis] = []
    
    def analyze(
        self,
        error_message: str,
        status_code: int = 0,
        headers: Optional[Dict[str, str]] = None,
    ) -> ErrorAnalysis:
        """
        エラーメッセージを解析
        
        Args:
            error_message: エラーメッセージ
            status_code: HTTPステータスコード
            headers: レスポンスヘッダー
        
        Returns:
            解析結果
        """
        category = self._categorize_error(error_message, status_code)
        tech_stack = self._detect_tech_stack(error_message, headers)
        validation_rules = self._extract_validation_rules(error_message)
        hints = self._extract_hints(error_message)
        bypass_suggestions = self._generate_bypass_suggestions(
            category, validation_rules
        )
        
        analysis = ErrorAnalysis(
            original_message=error_message,
            category=category,
            tech_stack=tech_stack,
            validation_rules=validation_rules,
            hints=hints,
            bypass_suggestions=bypass_suggestions,
        )
        
        self.history.append(analysis)
        return analysis
    
    def _categorize_error(
        self,
        message: str,
        status_code: int,
    ) -> ErrorCategory:
        """エラーカテゴリ判定"""
        message_lower = message.lower()
        
        # ステータスコードベース
        if status_code == 400:
            return ErrorCategory.VALIDATION
        elif status_code == 401:
            return ErrorCategory.AUTHENTICATION
        elif status_code == 403:
            if "waf" in message_lower or "blocked" in message_lower:
                return ErrorCategory.WAF
            return ErrorCategory.AUTHORIZATION
        elif status_code >= 500:
            return ErrorCategory.SERVER
        
        # メッセージベース
        if any(kw in message_lower for kw in ["validation", "invalid", "required", "must be"]):
            return ErrorCategory.VALIDATION
        elif any(kw in message_lower for kw in ["sql", "database", "query"]):
            return ErrorCategory.DATABASE
        elif any(kw in message_lower for kw in ["login", "password", "credentials"]):
            return ErrorCategory.AUTHENTICATION
        elif any(kw in message_lower for kw in ["permission", "access denied", "forbidden"]):
            return ErrorCategory.AUTHORIZATION
        elif any(kw in message_lower for kw in ["blocked", "firewall", "security"]):
            return ErrorCategory.WAF
        
        return ErrorCategory.UNKNOWN
    
    def _detect_tech_stack(
        self,
        message: str,
        headers: Optional[Dict[str, str]],
    ) -> List[str]:
        """技術スタック検出"""
        detected = []
        combined = message
        
        if headers:
            combined += " ".join(f"{k}: {v}" for k, v in headers.items())
        
        for tech, patterns in self.TECH_STACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    if tech not in detected:
                        detected.append(tech)
                    break
        
        return detected
    
    def _extract_validation_rules(
        self,
        message: str,
    ) -> List[ValidationRule]:
        """バリデーションルール抽出"""
        rules = []
        
        for pattern, rule_type, subtype in self.VALIDATION_PATTERNS:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                constraint = match.group(0)
                rules.append(ValidationRule(
                    field="unknown",  # フィールド名は別途推測
                    rule_type=f"{rule_type}_{subtype}",
                    constraint=constraint,
                    confidence=0.7,
                ))
        
        # フィールド名抽出
        field_pattern = r"(\w+)\s+(is|must|should|cannot)"
        field_match = re.search(field_pattern, message, re.IGNORECASE)
        if field_match and rules:
            rules[0].field = field_match.group(1)
        
        return rules
    
    def _extract_hints(self, message: str) -> List[str]:
        """脆弱性ヒント抽出"""
        hints = []
        
        # SQLエラー
        if re.search(r"sql|syntax|query|select|from|where", message, re.IGNORECASE):
            hints.append("SQL injection possible - database error exposed")
        
        # パス情報漏洩
        if re.search(r"(/[a-z0-9_/]+\.py|\.php|\.rb|\.js)", message, re.IGNORECASE):
            hints.append("File path disclosure")
        
        # スタックトレース
        if re.search(r"traceback|stack trace|at line", message, re.IGNORECASE):
            hints.append("Stack trace exposed - debug mode may be enabled")
        
        # バージョン情報
        version_match = re.search(r"(version|v)\s*[:\s]?\s*([\d.]+)", message, re.IGNORECASE)
        if version_match:
            hints.append(f"Version disclosed: {version_match.group(0)}")
        
        return hints
    
    def _generate_bypass_suggestions(
        self,
        category: ErrorCategory,
        rules: List[ValidationRule],
    ) -> List[str]:
        """バイパス提案生成"""
        suggestions = []
        
        # カテゴリベース
        if category == ErrorCategory.WAF:
            suggestions.extend(self.BYPASS_SUGGESTIONS.get("waf_blocked", []))
        
        # ルールベース
        for rule in rules:
            key = rule.rule_type
            if key in self.BYPASS_SUGGESTIONS:
                suggestions.extend(self.BYPASS_SUGGESTIONS[key])
        
        return list(set(suggestions))  # 重複除去
    
    def analyze_for_payload_feedback(
        self,
        error_message: str,
        payload: str,
    ) -> Dict[str, any]:
        """
        ペイロードフィードバック用の分析
        
        Returns:
            フィードバック情報
        """
        analysis = self.analyze(error_message)
        
        return {
            "should_encode": "charset" in str(analysis.validation_rules),
            "should_truncate": "length" in str(analysis.validation_rules),
            "should_change_case": analysis.category == ErrorCategory.WAF,
            "detected_filter": analysis.category == ErrorCategory.WAF,
            "tech_hints": analysis.tech_stack,
            "suggestions": analysis.bypass_suggestions,
        }
    
    def get_summary(self) -> Dict:
        """サマリー"""
        by_category = {}
        techs = []
        
        for h in self.history:
            by_category[h.category.value] = by_category.get(h.category.value, 0) + 1
            techs.extend(h.tech_stack)
        
        return {
            "total_analyzed": len(self.history),
            "by_category": by_category,
            "detected_tech_stack": list(set(techs)),
        }


def create_error_analyzer() -> ErrorMessageAnalyzer:
    """ErrorMessageAnalyzer作成ヘルパー"""
    return ErrorMessageAnalyzer()
