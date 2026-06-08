"""
Parameter Semantic Analyzer - パラメータ意味論的解析

パラメータ名と値から意味を推測し、
適切な攻撃ベクターを選択する。

用途:
- パラメータ名からの役割推測
- 値の形式からの型推測
- 攻撃ベクター自動選択
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class ParameterRole(Enum):
    """パラメータの役割"""
    USER_ID = "user_id"
    USERNAME = "username"
    PASSWORD = "password"
    EMAIL = "email"
    PHONE = "phone"
    FILE_PATH = "file_path"
    URL = "url"
    SEARCH_QUERY = "search_query"
    FILTER = "filter"
    SORT = "sort"
    PAGE = "page"
    LIMIT = "limit"
    TOKEN = "token"
    API_KEY = "api_key"
    CALLBACK = "callback"
    REDIRECT = "redirect"
    DEBUG = "debug"
    ADMIN = "admin"
    JSON_DATA = "json_data"
    XML_DATA = "xml_data"
    COMMAND = "command"
    UNKNOWN = "unknown"


class AttackVector(Enum):
    """攻撃ベクター"""
    SQLI = "sqli"
    XSS = "xss"
    SSRF = "ssrf"
    LFI = "lfi"
    RFI = "rfi"
    COMMAND_INJECTION = "command_injection"
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    XXE = "xxe"
    SSTI = "ssti"
    NOSQLI = "nosqli"
    LDAPI = "ldapi"
    HEADER_INJECTION = "header_injection"


@dataclass
class ParameterAnalysis:
    """パラメータ解析結果"""
    name: str
    value: str
    role: ParameterRole
    suggested_vectors: List[AttackVector]
    value_type: str  # string, integer, boolean, json, etc.
    confidence: float
    notes: List[str] = field(default_factory=list)


class ParameterSemanticAnalyzer:
    """
    Parameter Semantic Analyzer
    
    機能:
    - パラメータ名からの役割推測
    - 値の形式分析
    - 攻撃ベクターの優先順位付け
    """
    
    # パラメータ名パターン → 役割
    NAME_PATTERNS = {
        ParameterRole.USER_ID: [
            r"^(user_?)?id$", r"uid", r"user_id", r"userid", r"member_?id",
        ],
        ParameterRole.USERNAME: [
            r"^user(name)?$", r"^login$", r"^account$", r"^name$",
        ],
        ParameterRole.PASSWORD: [
            r"^pass(word)?$", r"^pwd$", r"^secret$", r"^credential",
        ],
        ParameterRole.EMAIL: [
            r"^e?mail$", r"^email_?address$",
        ],
        ParameterRole.FILE_PATH: [
            r"^file$", r"^path$", r"^filename$", r"^filepath$",
            r"^doc$", r"^document$", r"^template$",
        ],
        ParameterRole.URL: [
            r"^url$", r"^uri$", r"^link$", r"^href$", r"^src$",
            r"^target$", r"^dest$", r"^return$",
        ],
        ParameterRole.SEARCH_QUERY: [
            r"^q$", r"^query$", r"^search$", r"^s$", r"^keyword",
        ],
        ParameterRole.FILTER: [
            r"^filter", r"^where$", r"^condition",
        ],
        ParameterRole.SORT: [
            r"^sort", r"^order", r"^orderby$",
        ],
        ParameterRole.PAGE: [
            r"^page$", r"^p$", r"^offset$",
        ],
        ParameterRole.LIMIT: [
            r"^limit$", r"^size$", r"^count$", r"^per_?page$",
        ],
        ParameterRole.TOKEN: [
            r"^token$", r"^csrf$", r"^_token$", r"^auth_?token$",
        ],
        ParameterRole.API_KEY: [
            r"^api_?key$", r"^key$", r"^access_?key$",
        ],
        ParameterRole.CALLBACK: [
            r"^callback$", r"^jsonp$", r"^cb$",
        ],
        ParameterRole.REDIRECT: [
            r"^redirect", r"^return", r"^next$", r"^goto$",
        ],
        ParameterRole.DEBUG: [
            r"^debug$", r"^test$", r"^dev$", r"^verbose$",
        ],
        ParameterRole.ADMIN: [
            r"^admin$", r"^is_?admin$", r"^role$", r"^privilege",
        ],
        ParameterRole.COMMAND: [
            r"^cmd$", r"^command$", r"^exec$", r"^run$",
        ],
    }
    
    # 役割 → 推奨攻撃ベクター
    ROLE_VECTORS = {
        ParameterRole.USER_ID: [AttackVector.IDOR, AttackVector.SQLI],
        ParameterRole.USERNAME: [AttackVector.SQLI, AttackVector.LDAPI],
        ParameterRole.PASSWORD: [AttackVector.SQLI],
        ParameterRole.FILE_PATH: [AttackVector.LFI, AttackVector.RFI],
        ParameterRole.URL: [AttackVector.SSRF, AttackVector.OPEN_REDIRECT],
        ParameterRole.SEARCH_QUERY: [AttackVector.SQLI, AttackVector.XSS, AttackVector.NOSQLI],
        ParameterRole.FILTER: [AttackVector.SQLI, AttackVector.NOSQLI],
        ParameterRole.SORT: [AttackVector.SQLI],
        ParameterRole.CALLBACK: [AttackVector.XSS],
        ParameterRole.REDIRECT: [AttackVector.OPEN_REDIRECT, AttackVector.SSRF],
        ParameterRole.DEBUG: [AttackVector.IDOR],
        ParameterRole.ADMIN: [AttackVector.IDOR],
        ParameterRole.COMMAND: [AttackVector.COMMAND_INJECTION],
        ParameterRole.JSON_DATA: [AttackVector.NOSQLI, AttackVector.XXE],
        ParameterRole.XML_DATA: [AttackVector.XXE],
    }
    
    # 値のパターン → 型
    VALUE_PATTERNS = {
        "integer": r"^\d+$",
        "float": r"^\d+\.\d+$",
        "boolean": r"^(true|false|0|1|yes|no)$",
        "email": r"^[\w.+-]+@[\w.-]+\.\w+$",
        "url": r"^https?://",
        "path": r"^[/\\]|\.\.\/",
        "json": r"^\s*[\[{]",
        "xml": r"^\s*<",
        "base64": r"^[A-Za-z0-9+/=]+$",
        "uuid": r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    }
    
    def __init__(self):
        self.history: List[ParameterAnalysis] = []
    
    def analyze(
        self,
        name: str,
        value: str,
    ) -> ParameterAnalysis:
        """
        単一パラメータを解析
        
        Args:
            name: パラメータ名
            value: パラメータ値
        
        Returns:
            解析結果
        """
        role = self._detect_role(name)
        value_type = self._detect_value_type(value)
        vectors = self._suggest_vectors(role, value_type, value)
        notes = self._generate_notes(name, value, role, value_type)
        
        analysis = ParameterAnalysis(
            name=name,
            value=value[:100] if len(value) > 100 else value,
            role=role,
            suggested_vectors=vectors,
            value_type=value_type,
            confidence=0.7 if role != ParameterRole.UNKNOWN else 0.3,
            notes=notes,
        )
        
        self.history.append(analysis)
        return analysis
    
    def analyze_all(
        self,
        parameters: Dict[str, str],
    ) -> List[ParameterAnalysis]:
        """
        複数パラメータを解析
        
        Args:
            parameters: パラメータ名と値の辞書
        
        Returns:
            解析結果リスト
        """
        return [self.analyze(name, value) for name, value in parameters.items()]
    
    def _detect_role(self, name: str) -> ParameterRole:
        """パラメータ名から役割を推測"""
        name_lower = name.lower()
        
        for role, patterns in self.NAME_PATTERNS.items():
            for pattern in patterns:
                if re.match(pattern, name_lower):
                    return role
        
        return ParameterRole.UNKNOWN
    
    def _detect_value_type(self, value: str) -> str:
        """値から型を推測"""
        for type_name, pattern in self.VALUE_PATTERNS.items():
            if re.match(pattern, value, re.IGNORECASE):
                return type_name
        
        return "string"
    
    def _suggest_vectors(
        self,
        role: ParameterRole,
        value_type: str,
        value: str,
    ) -> List[AttackVector]:
        """攻撃ベクターを提案"""
        vectors = []
        
        # 役割ベース
        if role in self.ROLE_VECTORS:
            vectors.extend(self.ROLE_VECTORS[role])
        
        # 値タイプベース
        if value_type == "url":
            if AttackVector.SSRF not in vectors:
                vectors.append(AttackVector.SSRF)
        elif value_type == "path":
            if AttackVector.LFI not in vectors:
                vectors.append(AttackVector.LFI)
        elif value_type == "json":
            if AttackVector.NOSQLI not in vectors:
                vectors.append(AttackVector.NOSQLI)
        elif value_type == "xml":
            if AttackVector.XXE not in vectors:
                vectors.append(AttackVector.XXE)
        
        # 値の内容ベース
        if ".." in value or "/" in value:
            if AttackVector.LFI not in vectors:
                vectors.append(AttackVector.LFI)
        
        # デフォルト
        if not vectors:
            vectors = [AttackVector.XSS, AttackVector.SQLI]
        
        return vectors
    
    def _generate_notes(
        self,
        name: str,
        value: str,
        role: ParameterRole,
        value_type: str,
    ) -> List[str]:
        """注意事項生成"""
        notes = []
        
        if role == ParameterRole.USER_ID and value.isdigit():
            notes.append("IDOR: Try incrementing/decrementing the ID")
        
        if role == ParameterRole.ADMIN:
            notes.append("Privilege escalation: Try setting to 'true' or '1'")
        
        if role == ParameterRole.DEBUG:
            notes.append("Debug mode: May expose sensitive information")
        
        if value_type == "base64":
            notes.append("Base64: May contain serialized data")
        
        if len(value) > 1000:
            notes.append("Large value: May be base64 encoded or serialized")
        
        return notes
    
    def prioritize_parameters(
        self,
        parameters: Dict[str, str],
    ) -> List[Tuple[str, List[AttackVector]]]:
        """
        パラメータを攻撃優先度順にソート
        
        Returns:
            [(param_name, [vectors]), ...] 優先度順
        """
        analyses = self.analyze_all(parameters)
        
        # 優先度スコア計算
        scored = []
        for a in analyses:
            score = len(a.suggested_vectors) * a.confidence
            # 特定の役割を優先
            if a.role in (ParameterRole.FILE_PATH, ParameterRole.URL, ParameterRole.COMMAND):
                score *= 2
            elif a.role in (ParameterRole.USER_ID, ParameterRole.ADMIN):
                score *= 1.5
            scored.append((a.name, a.suggested_vectors, score))
        
        # スコア順ソート
        scored.sort(key=lambda x: x[2], reverse=True)
        
        return [(name, vectors) for name, vectors, _ in scored]
    
    def get_high_value_targets(
        self,
        parameters: Dict[str, str],
    ) -> List[str]:
        """
        高価値ターゲットパラメータを取得
        
        Returns:
            高価値パラメータ名のリスト
        """
        high_value_roles = {
            ParameterRole.FILE_PATH,
            ParameterRole.URL,
            ParameterRole.COMMAND,
            ParameterRole.REDIRECT,
            ParameterRole.ADMIN,
            ParameterRole.USER_ID,
        }
        
        analyses = self.analyze_all(parameters)
        return [a.name for a in analyses if a.role in high_value_roles]
    
    def get_summary(self) -> Dict:
        """サマリー"""
        by_role = {}
        by_vector = {}
        
        for h in self.history:
            by_role[h.role.value] = by_role.get(h.role.value, 0) + 1
            for v in h.suggested_vectors:
                by_vector[v.value] = by_vector.get(v.value, 0) + 1
        
        return {
            "total_analyzed": len(self.history),
            "by_role": by_role,
            "by_vector": by_vector,
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"Parameter Analysis: {summary['total_analyzed']} params\n"
            f"By role: {summary['by_role']}\n"
            f"By vector: {summary['by_vector']}"
        )


def create_semantic_analyzer() -> ParameterSemanticAnalyzer:
    """ParameterSemanticAnalyzer作成ヘルパー"""
    return ParameterSemanticAnalyzer()
