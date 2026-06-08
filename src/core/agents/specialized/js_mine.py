"""
JSMineAgent: JavaScript深掘り解析エージェント

JSファイルから機密情報（HardcodedSecrets）やクライアントサイドロジックを抽出する。
APISpec復元とは別の観点で「何が漏れているか」を発見する。
"""

import re
import math
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SecretFinding:
    """発見された機密情報"""
    type: str  # api_key, aws_key, jwt, password, etc.
    value: str
    context: str  # 前後の文字列
    confidence: float  # 0.0 - 1.0
    line_hint: int = 0


@dataclass
class LogicFinding:
    """発見されたロジック断片"""
    type: str  # admin_check, validation, crypto
    snippet: str
    description: str


class JSMineAgent:
    """
    JavaScript深掘り解析エージェント
    
    機能:
    - Hardcoded Secret検出（Regex + エントロピー解析）
    - クライアントサイドロジックのスニペット抽出
    - 人間のレビュー用にサマリー生成
    """
    
    # Secrets検出パターン (type, regex, min_entropy)
    SECRET_PATTERNS = [
        ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}"), 3.5),
        ("aws_secret_key", re.compile(r"['\"][A-Za-z0-9/+=]{40}['\"]"), 4.0),
        ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"), 3.5),
        ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), 4.0),
        ("generic_api_key", re.compile(r"['\"]([a-zA-Z0-9]{32,64})['\"]"), 4.5),
        ("private_key", re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"), 0),
        ("password_assignment", re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]"), 3.0),
        ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+"), 3.5),
    ]
    
    # ロジック検出パターン
    LOGIC_PATTERNS = [
        ("admin_check", re.compile(r"(?:isAdmin|is_admin|role\s*===?\s*['\"]admin['\"]|userRole)"), "Admin権限チェックロジック"),
        ("validation_bypass", re.compile(r"if\s*\(\s*!?validate|skipValidation|bypassCheck"), "バリデーション関連ロジック"),
        ("crypto_usage", re.compile(r"(?:CryptoJS|crypto\.subtle|aes|encrypt|decrypt|sign|verify)"), "暗号化処理"),
        ("debug_mode", re.compile(r"(?:debugMode|DEBUG|isDebug)\s*[:=]\s*true"), "デバッグモード"),
        ("internal_url", re.compile(r"(?:localhost|127\.0\.0\.1|internal\.|staging\.|dev\.)"), "内部/開発用URL"),
    ]

    def __init__(self):
        pass

        pass
    
    async def analyze_async(self, js_content: str, source_name: str = "unknown") -> Dict[str, Any]:
        """
        JSコンテンツを非同期で解析（CPUバウンド処理をオフロード）
        
        Args:
            js_content: 解析対象のJavaScriptコード
            source_name: ソースファイル名（レポート用）
            
        Returns:
            解析結果辞書
        """
        import asyncio
        return await asyncio.to_thread(self.analyze, js_content, source_name)

    def analyze(self, js_content: str, source_name: str = "unknown") -> Dict[str, Any]:
        """
        JSコンテンツを解析
        
        Args:
            js_content: 解析対象のJavaScriptコード
            source_name: ソースファイル名（レポート用）
            
        Returns:
            解析結果辞書
        """
        secrets: List[SecretFinding] = []
        logic_findings: List[LogicFinding] = []
        
        # 1. Secretスキャン
        for secret_type, pattern, min_entropy in self.SECRET_PATTERNS:
            for match in pattern.finditer(js_content):
                value = match.group(0)
                # グループがあればそれを使う
                if match.lastindex:
                    value = match.group(1)
                
                # エントロピーチェック（min_entropyが0なら必ず検出）
                entropy = self._calculate_entropy(value)
                if min_entropy == 0 or entropy >= min_entropy:
                    # コンテキスト取得
                    start = max(0, match.start() - 30)
                    end = min(len(js_content), match.end() + 30)
                    context = js_content[start:end].replace("\n", " ")
                    
                    secrets.append(SecretFinding(
                        type=secret_type,
                        value=value[:50] + "..." if len(value) > 50 else value,
                        context=context,
                        confidence=min(1.0, entropy / 5.0) if min_entropy > 0 else 0.9
                    ))
        
        # 2. ロジックスキャン
        for logic_type, pattern, description in self.LOGIC_PATTERNS:
            for match in pattern.finditer(js_content):
                # スニペット取得（前後の行を含む）
                start = js_content.rfind("\n", 0, match.start()) + 1
                end = js_content.find("\n", match.end())
                if end == -1:
                    end = len(js_content)
                snippet = js_content[start:end].strip()
                
                logic_findings.append(LogicFinding(
                    type=logic_type,
                    snippet=snippet[:200],
                    description=description
                ))
        
        # 重複除去
        secrets = self._dedupe_secrets(secrets)
        logic_findings = self._dedupe_logic(logic_findings)
        
        return {
            "source": source_name,
            "secrets": [self._secret_to_dict(s) for s in secrets],
            "logic": [self._logic_to_dict(l) for l in logic_findings],
            "secret_count": len(secrets),
            "logic_count": len(logic_findings)
        }

    def _calculate_entropy(self, text: str) -> float:
        """シャノンエントロピー計算"""
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
        return entropy

    def _dedupe_secrets(self, secrets: List[SecretFinding]) -> List[SecretFinding]:
        """同じ値のSecretを重複除去"""
        seen = set()
        result = []
        for s in secrets:
            if s.value not in seen:
                seen.add(s.value)
                result.append(s)
        return result

    def _dedupe_logic(self, findings: List[LogicFinding]) -> List[LogicFinding]:
        """同じスニペットのロジックを重複除去"""
        seen = set()
        result = []
        for f in findings:
            if f.snippet not in seen:
                seen.add(f.snippet)
                result.append(f)
        return result

    def _secret_to_dict(self, s: SecretFinding) -> Dict[str, Any]:
        return {
            "type": s.type,
            "value": s.value,
            "context": s.context,
            "confidence": s.confidence
        }

    def _logic_to_dict(self, l: LogicFinding) -> Dict[str, Any]:
        return {
            "type": l.type,
            "snippet": l.snippet,
            "description": l.description
        }

    def execute(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """MasterConductor互換の実行メソッド"""
        js_content = params.get("js_content", "")
        source_name = params.get("source", target)
        
        if not js_content:
            return {
                "success": False,
                "error": "js_content is required in params"
            }
        
        result = self.analyze(js_content, source_name)
        result["success"] = True
        return result
