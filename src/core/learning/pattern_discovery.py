"""
PatternDiscovery: 蓄積データからの攻撃パターン抽出

LearningRepository に蓄積された実行データ、洞察、成功ペイロードを分析し、
統計的に有効な攻撃パターンやバイパス手法を抽出するプロトタイプ。
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from collections import Counter

from src.core.learning.repository import LearningRepository, get_learning_repository

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredPattern:
    """発見されたパターン"""
    category: str
    pattern_type: str  # "substring", "encoding", "structure"
    value: str
    confidence: float
    hit_count: int
    targets: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class PatternDiscovery:
    """
    パターン発見エンジン (Prototype)
    """
    
    def __init__(self, repository: Optional[LearningRepository] = None):
        self.repository = repository or get_learning_repository()
        
    def discover_success_tokens(self, min_confidence: float = 0.6) -> List[DiscoveredPattern]:
        """
        成功したペイロードに含まれる共通のトークン（シグネチャ）を抽出
        """
        success_entries = self.repository.list_by_category("success_payloads", limit=500)
        if not success_entries:
            return []
            
        payloads = [e.value.get("payload_used") for e in success_entries if e.value.get("payload_used")]
        if not payloads:
            return []
            
        # 簡易的な N-gram または 記号セットによる頻出パターン抽出
        # 今回は記号と重要キーワードの頻出度を計算
        tokens = []
        for p in payloads:
            # 攻撃に特徴的な記号等を抽出
            found = re.findall(r"['\"<>%;()&|\\]|union|select|script|alert|exec|system", p.lower())
            tokens.extend(found)
            
        counter = Counter(tokens)
        patterns = []
        
        total_successes = len(payloads)
        for token, count in counter.most_common(10):
            freq = count / total_successes
            if freq >= min_confidence:
                patterns.append(DiscoveredPattern(
                    category="injection",
                    pattern_type="substring",
                    value=token,
                    confidence=freq,
                    hit_count=count,
                    metadata={"explanation": f"Found in {freq:.0%} of successful payloads"}
                ))
                
        return patterns

    def get_most_effective_bypasses(self, target_stack: Optional[str] = None) -> List[str]:
        """
        統計的に最も成功率の高いバイパス手法（エンコーディング等）のリストを返す
        """
        # 現状の LearningRepository 構造から "modifications" の統計を取る（将来的な実装）
        # モックとして頻出なものを返す
        return ["url_encode", "double_url_encode", "case_swap"]

    def analyze_error_trends(self) -> Dict[str, Any]:
        """
        エラーの傾向を分析し、共通のボトルネックを特定
        """
        error_entries = self.repository.list_by_category("error_knowledge", limit=100)
        categories = [e.key.split(":")[0] for e in error_entries]
        
        return {
            "top_errors": Counter(categories).most_common(3),
            "total_analyzed": len(error_entries)
        }

# シングルトン取得
_instance: Optional[PatternDiscovery] = None

def get_pattern_discovery() -> PatternDiscovery:
    global _instance
    if _instance is None:
        _instance = PatternDiscovery()
    return _instance
