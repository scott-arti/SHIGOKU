"""
RAG data models: lightweight data carriers.

Split from rag.py (SGK-2026-0302) to reduce module size and avoid circular dependencies.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RAGDocument:
    """RAGドキュメント"""
    id: str
    content: str
    metadata: dict = field(default_factory=dict)
    source_file: str = ""


@dataclass
class RAGResult:
    """RAG検索結果"""
    content: str
    score: float
    source: str
    metadata: dict = field(default_factory=dict)


# ── SGK-2026-0262: RAG advisor / provenance / policy types ──

# hint_type 定数（str Enum の代替、dataclass との相性を優先）
HINT_CHECKLIST = "checklist"
HINT_SIMILAR_CASE = "similar_case"
HINT_CAUTION = "caution"
HINT_STRATEGY = "strategy"
VALID_HINT_TYPES = frozenset({HINT_CHECKLIST, HINT_SIMILAR_CASE, HINT_CAUTION, HINT_STRATEGY})


@dataclass
class RAGProvenance:
    """
    RAGクエリの出所追跡情報。

    SGK-2026-0262: RAG が返すすべてのヒントには provenance を付与し、
    後から「どのノートが判断に影響したか」を監査可能にする。
    """
    source_note: str = ""           # 出所ノートのファイル名
    chunk_id: str = ""              # チャンクID
    query: str = ""                 # 実行したクエリ文字列
    score: float = 0.0              # 類似度スコア
    retrieved_at: str = ""          # 取得日時（ISO 8601）


@dataclass
class RAGHint:
    """
    RAG が返すアドバイザリーヒント。

    SGK-2026-0262: RAG は raw chunk をそのまま返すのではなく、
    この正規化形式で MC / Swarm / Recipe に渡す。
    RAG を hypothesis advisor に限定する guardrail として、
    hint_type は checklist / similar_case / caution / strategy のみ許可する。
    """
    hint_type: str                  # checklist|similar_case|caution|strategy
    summary: str = ""               # ヒントの概要（人間が読める要約）
    reason: str = ""                # なぜこのヒントを出したか
    confidence: float = 0.0         # 信頼度 (0.0-1.0)
    provenance: Optional[RAGProvenance] = None  # 出所情報

    def is_valid(self) -> bool:
        """hint_type が許可された値か検証する"""
        return self.hint_type in VALID_HINT_TYPES


@dataclass
class LearningPolicy:
    """
    MC が RAG をいつ/どのように使うかを制御するポリシー設定。

    SGK-2026-0262: 以下の原則を実装レベルで固定する。
    - RAG は gating しない（novelty_budget で未知候補も探索）
    - RAG 推奨の逆も試す（counter_example_budget）
    - RAG provenance を記録する（record_provenance）
    - RAG が落ちても本流は止めない（graceful degradation）

    Attributes:
        novelty_budget: 既知パターンに似ない候補に割く最低割合 (0.0-1.0)
        counter_example_budget: RAG 推奨と逆の仮説を試す最低割合 (0.0-1.0)
        rag_usage_budget: 1ランあたりの最大 RAG クエリ回数
        confidence_threshold: RAG ヒント採用の最低信頼度
        max_retries: AgenticRAG の最大再試行回数
        enable_rag: RAG を有効にするか
        enable_agentic_rag: Agentic RAG フィードバックループを有効にするか
        record_provenance: RAG provenance を保存するか
    """
    novelty_budget: float = 0.15       # 15% は既知例に似なくても探索
    counter_example_budget: float = 0.05  # 5% は RAG 逆張り
    rag_usage_budget: int = 10         # 最大 RAG クエリ数/run
    confidence_threshold: float = 0.7  # RAG ヒント採用の最低信頼度
    max_retries: int = 3               # AgenticRAG の最大再試行
    enable_rag: bool = True
    enable_agentic_rag: bool = True
    record_provenance: bool = True     # provenance を記録する
