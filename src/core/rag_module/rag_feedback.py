"""
RAG Feedback - RAGフィードバックループ

False Positive学習。

SGK-2026-0262: LearningRepository 連携
- RAGFeedbackManager は従来の JSON ファイル永続化に加え、
  オプションで LearningRepository にも FP/TP 判定を記録する。
- LearningRepository に接続された場合、FP パターンは学習リポジトリ側でも
  caution_hint カテゴリに保存され、後続の RAG ヒントに活用できる。
"""

import logging
import json
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
import os

logger = logging.getLogger(__name__)


@dataclass
class FeedbackEntry:
    """フィードバックエントリー"""
    finding_hash: str
    finding_type: str
    url: str
    is_false_positive: bool
    reason: str = ""
    confirmed_by: str = ""  # user/automated
    created_at: str = ""
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat() + "Z"


class RAGFeedbackManager:
    """
    RAGフィードバック管理

    機能:
    - False Positive記録
    - True Positive確認
    - 学習データ蓄積
    - パターンベース自動判定

    SGK-2026-0262: LearningRepository に接続することで、
    FP/TP 判定を SHIGOKU 全体の横断メモリに統合できる。
    """

    def __init__(self, feedback_path: str = None, learning_repo=None):
        self.feedback_path = Path(
            feedback_path or os.path.expanduser("~/.shigoku/rag_feedback.json")
        )
        self.feedback_path.parent.mkdir(parents=True, exist_ok=True)

        self.entries: List[FeedbackEntry] = []
        self.fp_patterns: Dict[str, List[str]] = {}  # タイプ -> URLパターン

        # SGK-2026-0262: LearningRepository 連携（任意）
        self._learning_repo = learning_repo

        self._load()
    
    def _load(self):
        """フィードバックデータ読み込み"""
        if self.feedback_path.exists():
            try:
                with open(self.feedback_path, encoding="utf-8") as f:
                    data = json.load(f)
                    
                    for e in data.get("entries", []):
                        self.entries.append(FeedbackEntry(**e))
                    
                    self.fp_patterns = data.get("fp_patterns", {})
                    
                logger.info("Loaded %d feedback entries", len(self.entries))
            except (json.JSONDecodeError, IOError) as e:
                logger.warning("Failed to load feedback: %s", e)
    
    def _save(self):
        """フィードバックデータ保存"""
        data = {
            "entries": [
                {
                    "finding_hash": e.finding_hash,
                    "finding_type": e.finding_type,
                    "url": e.url,
                    "is_false_positive": e.is_false_positive,
                    "reason": e.reason,
                    "confirmed_by": e.confirmed_by,
                    "created_at": e.created_at,
                }
                for e in self.entries
            ],
            "fp_patterns": self.fp_patterns,
        }
        
        with open(self.feedback_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def mark_false_positive(
        self,
        finding: Dict,
        reason: str = "",
        confirmed_by: str = "user"
    ):
        """
        False Positiveとしてマーク

        Args:
            finding: Finding辞書
            reason: 理由
            confirmed_by: 確認者
        """
        entry = FeedbackEntry(
            finding_hash=self._generate_hash(finding),
            finding_type=finding.get("type", ""),
            url=finding.get("url", ""),
            is_false_positive=True,
            reason=reason,
            confirmed_by=confirmed_by,
        )

        self.entries.append(entry)
        self._learn_pattern(entry)
        self._save()

        # SGK-2026-0262: LearningRepository に FP 判定を記録
        self._sync_to_repository(entry)

        logger.info("Marked as FP: %s", entry.finding_hash)
    
    def mark_true_positive(
        self,
        finding: Dict,
        confirmed_by: str = "user"
    ):
        """True Positiveとして確認"""
        entry = FeedbackEntry(
            finding_hash=self._generate_hash(finding),
            finding_type=finding.get("type", ""),
            url=finding.get("url", ""),
            is_false_positive=False,
            confirmed_by=confirmed_by,
        )

        self.entries.append(entry)
        self._save()

        # SGK-2026-0262: LearningRepository に TP 判定を記録
        self._sync_to_repository(entry)

        logger.info("Confirmed as TP: %s", entry.finding_hash)
    
    def is_likely_fp(self, finding: Dict) -> tuple:
        """
        False Positiveの可能性判定
        
        Returns:
            (is_likely_fp, confidence, reason)
        """
        finding_type = finding.get("type", "")
        url = finding.get("url", "")
        
        # 既知のハッシュチェック
        finding_hash = self._generate_hash(finding)
        for entry in self.entries:
            if entry.finding_hash == finding_hash:
                if entry.is_false_positive:
                    return True, 1.0, "Exact match with known FP"
                else:
                    return False, 1.0, "Confirmed as TP"
        
        # パターンマッチ
        if finding_type in self.fp_patterns:
            for pattern in self.fp_patterns[finding_type]:
                if pattern in url:
                    return True, 0.7, f"URL matches FP pattern: {pattern}"
        
        return False, 0.0, ""
    
    def filter_likely_fps(
        self,
        findings: List[Dict],
        threshold: float = 0.7
    ) -> tuple:
        """
        FP候補をフィルタ
        
        Returns:
            (filtered_findings, fp_candidates)
        """
        filtered = []
        fp_candidates = []
        
        for finding in findings:
            is_fp, confidence, reason = self.is_likely_fp(finding)
            
            if is_fp and confidence >= threshold:
                finding["_fp_candidate"] = True
                finding["_fp_reason"] = reason
                finding["_fp_confidence"] = confidence
                fp_candidates.append(finding)
            else:
                filtered.append(finding)
        
        return filtered, fp_candidates
    
    def _generate_hash(self, finding: Dict) -> str:
        """Findingハッシュ生成"""
        import hashlib
        
        url = finding.get("url", "")
        if "?" in url:
            url = url.split("?")[0]
        
        elements = [
            finding.get("type", ""),
            url,
            finding.get("parameter", ""),
        ]
        
        hash_input = "|".join(str(e) for e in elements)
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    
    def _learn_pattern(self, entry: FeedbackEntry):
        """FPパターン学習"""
        if not entry.is_false_positive:
            return

        # URLからパターン抽出
        url = entry.url
        if "?" in url:
            url = url.split("?")[0]

        # パスの最後のセグメントをパターンとして登録
        parts = url.rstrip("/").split("/")
        if len(parts) >= 2:
            pattern = "/" + parts[-1]

            if entry.finding_type not in self.fp_patterns:
                self.fp_patterns[entry.finding_type] = []

            if pattern not in self.fp_patterns[entry.finding_type]:
                self.fp_patterns[entry.finding_type].append(pattern)
                logger.info("Learned FP pattern: %s -> %s",
                           entry.finding_type, pattern)

    # ── SGK-2026-0262: LearningRepository 連携 ──

    def _sync_to_repository(self, entry: FeedbackEntry):
        """FP/TP 判定を LearningRepository に記録する"""
        if self._learning_repo is None:
            return
        try:
            verdict_category = "tp_fp_verdict"
            self._learning_repo.store(
                category=verdict_category,
                key=entry.finding_hash,
                value={
                    "finding_type": entry.finding_type,
                    "url": entry.url,
                    "is_false_positive": entry.is_false_positive,
                    "reason": entry.reason,
                    "confirmed_by": entry.confirmed_by,
                    "created_at": entry.created_at,
                },
                ttl_days=90,  # FP/TP 判定は長期保存
            )
            # FP の場合は caution_hint にも保存
            if entry.is_false_positive and entry.reason:
                self._learning_repo.store(
                    category="caution_hint",
                    key=f"{entry.finding_type}:{entry.finding_hash}",
                    value={
                        "finding_type": entry.finding_type,
                        "url": entry.url,
                        "reason": entry.reason,
                    },
                    ttl_days=90,
                )
        except Exception:
            # LearningRepository の障害は RAGFeedback の動作を止めない
            pass
    
    def get_stats(self) -> Dict:
        """統計"""
        fps = sum(1 for e in self.entries if e.is_false_positive)
        tps = sum(1 for e in self.entries if not e.is_false_positive)
        
        return {
            "total_entries": len(self.entries),
            "false_positives": fps,
            "true_positives": tps,
            "learned_patterns": sum(len(p) for p in self.fp_patterns.values()),
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        stats = self.get_stats()
        return (
            f"RAG Feedback: {stats['total_entries']} entries\n"
            f"FP: {stats['false_positives']}, TP: {stats['true_positives']}\n"
            f"Learned patterns: {stats['learned_patterns']}"
        )


def create_rag_feedback_manager(feedback_path: str = None) -> RAGFeedbackManager:
    """RAGFeedbackManager作成ヘルパー

    SGK-2026-0262: LearningRepository を自動注入し、
    tp_fp_verdict / caution_hint カテゴリへの保存を有効化する。
    """
    try:
        from src.core.learning.repository import get_learning_repository
        repo = get_learning_repository()
    except Exception:
        repo = None
    return RAGFeedbackManager(feedback_path, learning_repo=repo)
