"""
ErrorDetector - WAF/Rate Limit ブロック検出

WAF によるブロックやレート制限を検出し、
SwarmRetryEngine にミューテーション戦略を提案する。

用途:
- HTTPレスポンスからブロック状態を検出
- WAF種類の特定（ミューテーション戦略選択用）
- 誤検知の排除
"""

import logging
import re
from dataclasses import dataclass
from typing import Dict, Optional, List, Tuple

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """ブロック検出結果"""
    is_blocked: bool           # ブロックされたか
    block_type: str            # "waf", "rate_limit", "auth", "server_error", "none"
    waf_signature: Optional[str]  # 検出されたWAFシグネチャ (e.g., "cloudflare")
    confidence: float          # 確信度 (0.0-1.0)
    details: Dict[str, str]    # 追加情報
    
    def to_dict(self) -> Dict:
        """辞書形式に変換"""
        return {
            "is_blocked": self.is_blocked,
            "block_type": self.block_type,
            "waf_signature": self.waf_signature,
            "confidence": self.confidence,
            "details": self.details,
        }


class ErrorDetector:
    """
    WAF/Rate Limit ブロック検出器
    
    レスポンスのステータスコード、ヘッダ、ボディを解析し、
    ブロック状態とWAF種類を特定する。
    """
    
    # WAFシグネチャ: {waf_name: [(header_or_body_pattern, weight)]}
    WAF_SIGNATURES: Dict[str, List[Tuple[str, float]]] = {
        "cloudflare": [
            ("cf-ray", 0.9),
            ("__cfduid", 0.7),
            ("cloudflare", 0.6),
            ("cf-cache-status", 0.5),
            ("attention required", 0.8),  # Cloudflare challenge page
        ],
        "akamai": [
            ("akamaized", 0.9),
            ("akamai", 0.7),
            ("x-akamai", 0.8),
            ("akamai ghost", 0.9),
        ],
        "aws_waf": [
            ("awswaf", 0.9),
            ("x-amzn-requestid", 0.5),
            ("x-amz-cf-id", 0.6),
            ("aws", 0.3),
        ],
        "modsecurity": [
            ("mod_security", 0.9),
            ("naxsi", 0.9),
            ("modsec", 0.8),
            ("owasp", 0.5),
        ],
        "incapsula": [
            ("incap_ses", 0.9),
            ("visid_incap", 0.9),
            ("incapsula", 0.8),
            ("imperva", 0.8),
        ],
        "azure_appgw": [
            ("x-azure-ref", 0.9),
            ("azure application gateway", 0.9),
            ("microsoft-azure", 0.6),
        ],
        "f5_bigip": [
            ("bigipserver", 0.9),
            ("f5-ltm", 0.9),
            ("ts=", 0.5),  # F5のセッションCookie
            ("bigip", 0.7),
        ],
    }
    
    # ステータスコードパターン
    STATUS_PATTERNS: Dict[int, Tuple[str, float]] = {
        403: ("waf", 0.7),           # Forbidden - 高確率でWAF
        429: ("rate_limit", 0.9),    # Too Many Requests
        503: ("server_error", 0.5),  # Service Unavailable
        406: ("waf", 0.6),           # Not Acceptable
        451: ("waf", 0.8),           # Unavailable For Legal Reasons
    }
    
    # ブロックを示すボディパターン
    BLOCK_BODY_PATTERNS: List[Tuple[str, str, float]] = [
        (r"access\s+denied", "waf", 0.8),
        (r"blocked", "waf", 0.6),
        (r"forbidden", "waf", 0.5),
        (r"security\s+check", "waf", 0.7),
        (r"rate\s+limit", "rate_limit", 0.9),
        (r"too\s+many\s+requests", "rate_limit", 0.9),
        (r"captcha", "waf", 0.7),
        (r"challenge", "waf", 0.6),
        (r"bot\s+detection", "waf", 0.8),
        (r"suspicious\s+activity", "waf", 0.7),
    ]
    
    def __init__(self, sensitivity: float = 0.5):
        """
        Args:
            sensitivity: 検出感度 (0.0-1.0)。高いほど誤検知しやすいがカバー率向上
        """
        self.sensitivity = sensitivity
    
    def analyze(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> DetectionResult:
        """
        レスポンスを解析してブロック状態を検出
        
        Args:
            status_code: HTTPステータスコード
            headers: レスポンスヘッダ
            body: レスポンスボディ
            
        Returns:
            DetectionResult: 検出結果
        """
        details: Dict[str, str] = {}
        
        # 1. ステータスコード判定
        status_type, status_confidence = self._check_status_code(status_code)
        
        # 2. WAFシグネチャ検出
        waf_signature, waf_confidence = self._detect_waf_signature(headers, body)
        
        # 3. ボディパターン検出
        body_type, body_confidence = self._check_body_patterns(body)
        
        # 4. 総合判定
        is_blocked, block_type, final_confidence = self._aggregate_results(
            status_type, status_confidence,
            waf_signature, waf_confidence,
            body_type, body_confidence,
        )
        
        # 詳細情報を記録
        details["status_code"] = str(status_code)
        if waf_signature:
            details["detected_waf"] = waf_signature
        if body_type:
            details["body_pattern"] = body_type
        
        return DetectionResult(
            is_blocked=is_blocked,
            block_type=block_type,
            waf_signature=waf_signature,
            confidence=final_confidence,
            details=details,
        )
    
    def _check_status_code(self, status_code: int) -> Tuple[str, float]:
        """ステータスコードからブロック種類を判定"""
        if status_code in self.STATUS_PATTERNS:
            return self.STATUS_PATTERNS[status_code]
        
        # 4xx系は何らかのブロックの可能性
        if 400 <= status_code < 500:
            return ("unknown", 0.3)
        
        return ("none", 0.0)
    
    def _detect_waf_signature(
        self,
        headers: Dict[str, str],
        body: str,
    ) -> Tuple[Optional[str], float]:
        """WAFシグネチャを検出"""
        # ヘッダとボディを連結して検索対象にする
        search_target = " ".join(
            [f"{k}: {v}" for k, v in headers.items()]
        ).lower() + " " + body.lower()
        
        best_match: Optional[str] = None
        best_score: float = 0.0
        
        for waf_name, patterns in self.WAF_SIGNATURES.items():
            score = 0.0
            matches = 0
            
            for pattern, weight in patterns:
                if pattern.lower() in search_target:
                    score += weight
                    matches += 1
            
            # 複数パターンマッチでスコアブースト
            if matches > 1:
                score *= 1.2
            
            if score > best_score:
                best_score = score
                best_match = waf_name
        
        # しきい値判定
        if best_score >= self.sensitivity:
            return (best_match, min(best_score, 1.0))
        
        return (None, 0.0)
    
    def _check_body_patterns(self, body: str) -> Tuple[str, float]:
        """ボディからブロックパターンを検出"""
        body_lower = body.lower()
        
        best_type = "none"
        best_confidence = 0.0
        
        for pattern, block_type, confidence in self.BLOCK_BODY_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                if confidence > best_confidence:
                    best_type = block_type
                    best_confidence = confidence
        
        return (best_type, best_confidence)
    
    def _aggregate_results(
        self,
        status_type: str,
        status_confidence: float,
        waf_signature: Optional[str],
        waf_confidence: float,
        body_type: str,
        body_confidence: float,
    ) -> Tuple[bool, str, float]:
        """
        各検出結果を総合してブロック判定
        
        Returns:
            (is_blocked, block_type, confidence)
        """
        # 各ソースの重み付け
        weights = {
            "status": 0.3,
            "waf": 0.4,
            "body": 0.3,
        }
        
        # 加重平均スコア
        total_confidence = (
            status_confidence * weights["status"] +
            waf_confidence * weights["waf"] +
            body_confidence * weights["body"]
        )
        
        # ブロック判定
        is_blocked = total_confidence >= self.sensitivity
        
        # ブロック種類決定（優先順位: WAF > body > status）
        if waf_signature and waf_confidence > 0.5:
            block_type = "waf"
        elif body_type != "none" and body_confidence > 0.5:
            block_type = body_type
        elif status_type != "none":
            block_type = status_type
        else:
            block_type = "unknown" if is_blocked else "none"
        
        return (is_blocked, block_type, total_confidence)
    
    def is_rate_limited(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> bool:
        """Rate Limit かどうかを簡易判定"""
        result = self.analyze(status_code, headers, body)
        return result.block_type == "rate_limit"
    
    def is_waf_blocked(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> bool:
        """WAF ブロックかどうかを簡易判定"""
        result = self.analyze(status_code, headers, body)
        return result.block_type == "waf"


def create_error_detector(sensitivity: float = 0.5) -> ErrorDetector:
    """ErrorDetector 作成ヘルパー"""
    return ErrorDetector(sensitivity=sensitivity)
