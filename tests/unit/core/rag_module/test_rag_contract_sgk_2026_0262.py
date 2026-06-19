"""
SGK-2026-0262: RAG API 契約一本化・ポリシー・provenance の回帰テスト。

テスト観点:
1. 統一 API 契約 (retrieve/query)
2. RAGHint / RAGProvenance 型検証
3. RAG ポリシー（コンポーネント別・novelty/counter-example budget）
4. RAG 断時フォールバック（無効/未初期化）
5. RAG 未ヒット時の探索継続（空結果）
6. AgenticRAG async/sync 互換性
7. LearningRepository 連携
"""

import pytest
from unittest.mock import MagicMock, AsyncMock

from src.core.rag_module.rag_types import (
    RAGHint, RAGProvenance, LearningPolicy,
    HINT_CHECKLIST, HINT_SIMILAR_CASE, HINT_CAUTION, HINT_STRATEGY,
    VALID_HINT_TYPES, RAGResult,
)
from src.core.rag_module.rag_policy import (
    RAGUsageDecision, RAGBudgetState,
    should_use_rag_for_component, should_explore_novelty,
    should_try_counter_example, check_rag_usage_budget,
    get_default_policy,
)
from src.core.rag_module.rag_switch import RAGSwitch


# ── 1. 統一 API 契約（retrieve/query） ──

class TestUnifiedAPIContract:
    """RAGSwitch と KnowledgeIngester の retrieve/query 契約"""

    def test_rag_switch_has_retrieve_method(self):
        """RAGSwitch に retrieve() が存在する"""
        switch = RAGSwitch()
        assert hasattr(switch, 'retrieve')
        assert callable(switch.retrieve)

    def test_rag_switch_retrieve_delegates_to_query(self):
        """retrieve() が query() に委譲する"""
        switch = RAGSwitch()

        # インジェスター未設定 → retrieve も空リスト
        results = switch.retrieve("test query")
        assert results == []

    def test_rag_switch_retrieve_disabled(self):
        """RAG 無効時は retrieve も空リスト"""
        switch = RAGSwitch(default_enabled=False)
        results = switch.retrieve("test")
        assert results == []

    def test_knowledge_ingester_has_retrieve(self):
        """KnowledgeIngester にも retrieve() が存在する"""
        from src.core.rag_module.rag_ingester import KnowledgeIngester
        ingester = KnowledgeIngester()
        assert hasattr(ingester, 'retrieve')
        assert callable(ingester.retrieve)


# ── 2. RAGHint / RAGProvenance 型検証 ──

class TestRAGHintTypes:
    """RAGHint と RAGProvenance のバリデーション"""

    def test_rag_hint_valid_types(self):
        """許可された hint_type は is_valid() が True"""
        for hint_type in VALID_HINT_TYPES:
            hint = RAGHint(hint_type=hint_type, summary="test", reason="test")
            assert hint.is_valid(), f"{hint_type} should be valid"

    def test_rag_hint_invalid_type(self):
        """許可されていない hint_type は is_valid() が False"""
        hint = RAGHint(hint_type="payload", summary="test", reason="test")
        assert not hint.is_valid()

    def test_rag_hint_invalid_empty(self):
        """空文字列は is_valid() が False"""
        hint = RAGHint(hint_type="", summary="test", reason="test")
        assert not hint.is_valid()

    def test_rag_provenance_fields(self):
        """RAGProvenance の全フィールド設定"""
        prov = RAGProvenance(
            source_note="OAuth_Writeups.md",
            chunk_id="oauth_chunk_07",
            query="oauth callback token exchange",
            score=0.85,
            retrieved_at="2026-06-18T12:00:00Z",
        )
        assert prov.source_note == "OAuth_Writeups.md"
        assert prov.chunk_id == "oauth_chunk_07"
        assert prov.score == 0.85

    def test_rag_hint_with_provenance(self):
        """RAGHint に provenance を付与できる"""
        prov = RAGProvenance(source_note="test.md", chunk_id="c1")
        hint = RAGHint(
            hint_type=HINT_CAUTION,
            summary="Test caution",
            reason="Testing",
            confidence=0.9,
            provenance=prov,
        )
        assert hint.provenance is prov
        assert hint.is_valid()

    def test_rag_hint_defaults(self):
        """デフォルト値の確認"""
        hint = RAGHint(hint_type=HINT_CHECKLIST)
        assert hint.summary == ""
        assert hint.reason == ""
        assert hint.confidence == 0.0
        assert hint.provenance is None


# ── 3. LearningPolicy / RAGPolicy ──

class TestLearningPolicy:
    """LearningPolicy のデフォルト値とカスタマイズ"""

    def test_default_values(self):
        policy = LearningPolicy()
        assert policy.novelty_budget == 0.15
        assert policy.counter_example_budget == 0.05
        assert policy.rag_usage_budget == 10
        assert policy.confidence_threshold == 0.7
        assert policy.max_retries == 3
        assert policy.enable_rag is True
        assert policy.enable_agentic_rag is True
        assert policy.record_provenance is True

    def test_custom_policy(self):
        policy = LearningPolicy(
            novelty_budget=0.25,
            enable_rag=False,
            rag_usage_budget=5,
        )
        assert policy.novelty_budget == 0.25
        assert policy.enable_rag is False
        assert policy.rag_usage_budget == 5
        # 未指定はデフォルトのまま
        assert policy.counter_example_budget == 0.05


class TestRAGPolicyDecisions:
    """コンポーネント別 RAG 参照ポリシー"""

    def test_recon_no_rag_by_default(self):
        assert should_use_rag_for_component("recon") == RAGUsageDecision.NO_RAG

    def test_recon_rag_assist_with_checklist(self):
        assert should_use_rag_for_component("recon", {"needs_checklist": True}) == RAGUsageDecision.RAG_ASSIST

    def test_mc_no_rag_by_default(self):
        assert should_use_rag_for_component("mc") == RAGUsageDecision.NO_RAG

    def test_mc_rag_assist_ambiguous(self):
        assert should_use_rag_for_component("mc", {"ambiguous_surface": True}) == RAGUsageDecision.RAG_ASSIST

    def test_mc_rag_fallback(self):
        assert should_use_rag_for_component("mc", {"is_fallback": True}) == RAGUsageDecision.RAG_FALLBACK

    def test_mc_rag_assist_many_candidates(self):
        assert should_use_rag_for_component("mc", {"candidates": ["a", "b", "c", "d"]}) == RAGUsageDecision.RAG_ASSIST

    def test_swarm_rag_assist(self):
        assert should_use_rag_for_component("swarm") == RAGUsageDecision.RAG_ASSIST

    def test_recipe_no_rag_by_default(self):
        assert should_use_rag_for_component("recipe") == RAGUsageDecision.NO_RAG

    def test_recipe_rag_assist_followup(self):
        assert should_use_rag_for_component("recipe", {"is_followup": True}) == RAGUsageDecision.RAG_ASSIST

    def test_disabled_rag_returns_no_rag(self):
        policy = LearningPolicy(enable_rag=False)
        for comp in ["recon", "mc", "swarm", "recipe"]:
            assert should_use_rag_for_component(comp, policy=policy) == RAGUsageDecision.NO_RAG


class TestNoveltyBudget:
    """Novelty / Counter-Example Budget"""

    def test_explore_novelty_under_budget(self):
        policy = LearningPolicy(novelty_budget=0.15)
        state = RAGBudgetState(total_candidates=20, novelty_used=2)  # 10%
        assert should_explore_novelty(state, policy) is True

    def test_explore_novelty_over_budget(self):
        policy = LearningPolicy(novelty_budget=0.15)
        state = RAGBudgetState(total_candidates=20, novelty_used=4)  # 20%
        assert should_explore_novelty(state, policy) is False

    def test_explore_novelty_zero_budget(self):
        policy = LearningPolicy(novelty_budget=0.0)
        state = RAGBudgetState(total_candidates=10, novelty_used=0)
        assert should_explore_novelty(state, policy) is False

    def test_counter_example_under_budget(self):
        policy = LearningPolicy(counter_example_budget=0.05)
        state = RAGBudgetState(total_candidates=100, counter_example_used=4)  # 4%
        assert should_try_counter_example(state, policy) is True

    def test_counter_example_over_budget(self):
        policy = LearningPolicy(counter_example_budget=0.05)
        state = RAGBudgetState(total_candidates=100, counter_example_used=6)  # 6%
        assert should_try_counter_example(state, policy) is False

    def test_rag_usage_budget(self):
        policy = LearningPolicy(rag_usage_budget=10)
        assert check_rag_usage_budget(9, policy) is True
        assert check_rag_usage_budget(10, policy) is False
        assert check_rag_usage_budget(11, policy) is False


# ── 4. RAG 断時フォールバック ──

class TestRAGFallback:
    """RAG 無効/未初期化時のフォールバック"""

    def test_query_disabled_returns_empty(self):
        """RAG 無効時は query() が空リストを返す"""
        switch = RAGSwitch(default_enabled=False)
        results = switch.query("test")
        assert results == []

    def test_retrieve_disabled_returns_empty(self):
        """RAG 無効時は retrieve() が空リストを返す"""
        switch = RAGSwitch(default_enabled=False)
        results = switch.retrieve("test")
        assert results == []

    def test_query_no_ingester_returns_empty(self):
        """インジェスター未設定時は query() が空リストを返す"""
        switch = RAGSwitch(default_enabled=True)
        # _ingester は None
        results = switch.query("test")
        assert results == []

    def test_get_bypass_techniques_disabled(self):
        """RAG 無効時は get_bypass_techniques() が空リストを返す"""
        switch = RAGSwitch(default_enabled=False)
        results = switch.get_bypass_techniques("jwt_alg_none")
        assert results == []


# ── 5. RAG 未ヒット時の探索継続 ──

class TestExplorationContinuity:
    """RAG 未ヒット時も探索を継続できることの確認"""

    def test_empty_rag_results_does_not_block(self):
        """空の RAG 結果が返ってもエラーにならない"""
        switch = RAGSwitch(default_enabled=False)
        # 無効状態でも例外を投げずに空リスト
        results = switch.query("any query")
        assert isinstance(results, list)
        assert len(results) == 0

    def test_policy_allows_exploration_without_rag(self):
        """RAG がなくても MC は探索を継続できる"""
        policy = LearningPolicy(enable_rag=False)
        decision = should_use_rag_for_component("mc", {"ambiguous_surface": True}, policy)
        assert decision == RAGUsageDecision.NO_RAG
        # NO_RAG でも処理は継続する（呼び出し側の責任）


# ── 6. AgenticRAG async/sync 互換性 ──

# 環境不整合（pydantic-core バージョン競合等）で intelligence/__init__.py
# 経由のインポートが失敗する場合、このクラス全体をスキップする。
_agentic_rag_import_error = None
try:
    from src.core.intelligence.agentic_rag import AgenticRAGFeedbackLoop  # noqa: F811
except Exception as _e:
    _agentic_rag_import_error = str(_e)


@pytest.mark.skipif(
    _agentic_rag_import_error is not None,
    reason=f"AgenticRAGFeedbackLoop import failed: {_agentic_rag_import_error}",
)
class TestAgenticRAGCompatibility:
    """AgenticRAG が sync/async 両方の rag_client で動作すること"""

    @pytest.mark.asyncio
    async def test_with_sync_rag_client(self):
        """同期 rag_client（retrieve が sync）で動作する"""
        from src.core.intelligence.agentic_rag import AgenticRAGFeedbackLoop

        mock_rag = MagicMock()
        mock_rag.retrieve.return_value = ["sync context"]
        # hasattr check → True、かつ __await__ なし → 同期パス

        mock_llm = AsyncMock()
        mock_llm.ask_json.return_value = {
            "confidence": 0.9,
            "is_sufficient": True,
            "suggested_query": None,
        }

        loop = AgenticRAGFeedbackLoop(mock_rag, mock_llm, threshold=0.7)
        results = await loop.retrieve_with_feedback("query", "goal")
        assert results == ["sync context"]

    @pytest.mark.asyncio
    async def test_rag_client_without_retrieve_falls_back_to_query(self):
        """retrieve がなく query のみの rag_client でも動作する"""
        from src.core.intelligence.agentic_rag import AgenticRAGFeedbackLoop

        mock_rag = MagicMock(spec=["query"])  # retrieve なし
        mock_rag.query.return_value = ["fallback context"]

        mock_llm = AsyncMock()
        mock_llm.ask_json.return_value = {
            "confidence": 0.9,
            "is_sufficient": True,
            "suggested_query": None,
        }

        loop = AgenticRAGFeedbackLoop(mock_rag, mock_llm, threshold=0.7)
        results = await loop.retrieve_with_feedback("query", "goal")
        assert results == ["fallback context"]

    @pytest.mark.asyncio
    async def test_rag_result_content_extraction(self):
        """RAGResult の content が正しく抽出される"""
        from src.core.intelligence.agentic_rag import AgenticRAGFeedbackLoop

        mock_rag = MagicMock()
        mock_rag.retrieve.return_value = [
            RAGResult(content="useful content", score=0.9, source="test.md"),
        ]

        mock_llm = AsyncMock()
        mock_llm.ask_json.return_value = {
            "confidence": 0.9,
            "is_sufficient": True,
            "suggested_query": None,
        }

        loop = AgenticRAGFeedbackLoop(mock_rag, mock_llm, threshold=0.7)
        results = await loop.retrieve_with_feedback("query", "goal")
        assert len(results) == 1
        assert results[0].content == "useful content"


# ── 7. LearningRepository 連携 ──

class TestRAGFeedbackLearningRepoIntegration:
    """RAGFeedbackManager と LearningRepository の連携"""

    def test_create_without_learning_repo(self):
        """LearningRepository なしでも作成できる"""
        from src.core.rag_module.rag_feedback import RAGFeedbackManager
        fm = RAGFeedbackManager()
        assert fm._learning_repo is None

    def test_create_with_learning_repo(self):
        """LearningRepository ありで作成できる"""
        from src.core.rag_module.rag_feedback import RAGFeedbackManager
        from src.core.learning.repository import get_learning_repository
        fm = RAGFeedbackManager(learning_repo=get_learning_repository())
        assert fm._learning_repo is not None

    def test_mark_fp_syncs_to_repo(self):
        """FP マーク時に LearningRepository に記録される"""
        from src.core.rag_module.rag_feedback import RAGFeedbackManager
        from src.core.learning.repository import get_learning_repository
        repo = get_learning_repository()
        fm = RAGFeedbackManager(learning_repo=repo)
        import uuid
        unique_param = str(uuid.uuid4())[:8]
        before_count = len(repo.list_by_category("tp_fp_verdict"))
        fm.mark_false_positive(
            {"type": "test_xss", "url": f"http://test-{unique_param}.com/q", "parameter": unique_param},
            reason="test fp",
        )
        after_count = len(repo.list_by_category("tp_fp_verdict"))
        assert after_count >= before_count + 1, f"Expected tp_fp_verdict to grow, before={before_count} after={after_count}"

    def test_tp_fp_verdict_category_present(self):
        """tp_fp_verdict カテゴリにエントリが保存される"""
        from src.core.rag_module.rag_feedback import RAGFeedbackManager
        from src.core.learning.repository import get_learning_repository
        import uuid
        repo = get_learning_repository()
        fm = RAGFeedbackManager(learning_repo=repo)
        unique_param = str(uuid.uuid4())[:8]
        fm.mark_true_positive(
            {"type": "test_sqli", "url": f"http://test-{unique_param}.com/login", "parameter": unique_param},
        )
        entries = repo.list_by_category("tp_fp_verdict", limit=100)
        assert len(entries) >= 1, f"Expected at least 1 entry in tp_fp_verdict, got {len(entries)}"
