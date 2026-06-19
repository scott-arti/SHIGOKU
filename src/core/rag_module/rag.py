"""
Obsidian RAG: ナレッジベース検索システム

Obsidianノート（Markdown）をChromaDBにベクトル化して格納し、
セマンティック検索を可能にする。

RAG_SWITCH: エージェントがRAG利用をON/OFF選択可能。

このファイルは facade です。実装本体は各 sibling module に分割されています（SGK-2026-0302）。
import path 互換のため、既存の `from src.core.rag_module.rag import ...` はそのまま使用可能です。
"""

# Re-export public symbols from split modules (SGK-2026-0302)
from src.core.rag_module.rag_types import (  # noqa: F401
    RAGDocument,
    RAGResult,
    # SGK-2026-0262: RAG advisor / provenance / policy types
    HINT_CHECKLIST,
    HINT_SIMILAR_CASE,
    HINT_CAUTION,
    HINT_STRATEGY,
    VALID_HINT_TYPES,
    RAGHint,
    RAGProvenance,
    LearningPolicy,
)
from src.core.rag_module.rag_pdf_ingester import PDFIngester  # noqa: F401
from src.core.rag_module.rag_ingester import KnowledgeIngester  # noqa: F401
from src.core.rag_module.rag_switch import (  # noqa: F401
    RAGSwitch,
    get_rag_switch,
    init_rag,
)
# SGK-2026-0262: RAG usage policy module
from src.core.rag_module.rag_policy import (  # noqa: F401
    RAGUsageDecision,
    RAGBudgetState,
    should_use_rag_for_component,
    should_explore_novelty,
    should_try_counter_example,
    check_rag_usage_budget,
    get_default_policy,
    set_default_policy,
)
