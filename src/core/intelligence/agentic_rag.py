"""
Agentic RAG Feedback Loop: LLMによる自律的な検索信頼度評価と再検索の仕組み

このモジュールは、RAG（Retrieval-Augmented Generation）の検索結果が
現在のタスクに対して十分な情報を含んでいるかをLLMで自己評価し、
不十分な場合は検索クエリを動的に修正して再試行するループを提供する。

ロードマップ Tier 4, REQ_tier4_mc_intelligence 準拠
"""

import logging
import json
from typing import List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class AgenticRAGFeedbackLoop:
    """
    RAGの検索結果を評価し、信頼度が低い場合に再検索を行うフィードバックループ
    """
    
    def __init__(self, rag_client: Any, llm_client: Any, threshold: float = 0.7, max_retries: int = 3):
        """
        Args:
            rag_client: 既存の RAG インスタンス（retrieve または query メソッドを持つことを期待）
            llm_client: LLM 連携用クライアント
            threshold: 再試行の閾値 (0.0 - 1.0)
            max_retries: 最大リトライ回数
        """
        self.rag = rag_client
        self.llm = llm_client
        self.threshold = threshold
        self.max_retries = max_retries

    async def evaluate_confidence(self, query: str, context: List[str], goal: str) -> Tuple[float, Optional[str]]:
        """
        LLMを使用して取得したコンテキストの十分性を評価する
        
        Returns:
            (confidence_score, feedback_for_improvement)
        """
        prompt = f"""
あなたはセキュリティエキスパートかつRAG評価者です。
与えられた検索クエリとその結果のリスト（コンテキスト）が、最終的な「ゴール」を達成するために十分な情報を含んでいるかを厳格に評価してください。

【ゴール】
{goal}

【検索クエリ】
{query}

【検索結果（コンテキスト）】
{json.dumps(context, ensure_ascii=False)}

以下のJSONフォーマットで回答してください：
{{
    "confidence": 0.0から1.0の数値。十分なら高得点、不足があれば低得点。
    "is_sufficient": boolean。自信を持って後続処理に進めるか。
    "missing_info": 不足している具体的な情報やキーワードがあれば記述。なければnull。
    "suggested_query": 再検索する場合、より良い結果を得るための改善されたクエリ案。
}}
"""
        try:
            # LLM クライアントのAPI仕様に合わせて呼び出し
            # ここでは一般的な ask_json 的なメソッドがあることを想定
            response = await self.llm.ask_json(prompt, system_context="You are a RAG evaluator.")
            
            confidence = response.get("confidence", 0.0)
            suggested_query = response.get("suggested_query")
            
            logger.info("[AgenticRAG] Confidence: %.2f, Sufficient: %s", confidence, response.get('is_sufficient'))
            if suggested_query:
                logger.debug("[AgenticRAG] Suggested improvement: %s", suggested_query)
                
            return float(confidence), suggested_query
            
        except (ValueError, KeyError, RuntimeError) as e:
            logger.error("[AgenticRAG] Confidence evaluation failed: %s", str(e))
            return 1.0, None  # エラー時は安全のためそのまま続行させる
        except Exception as e:
            logger.error("[AgenticRAG] Unexpected error in evaluation: %s", str(e))
            return 1.0, None

    async def retrieve_with_feedback(self, query: str, goal: str) -> List[Any]:
        """
        自信が持てるまで（または上限まで）再検索を繰り返してコンテキストを取得する
        """
        current_query = query
        all_contexts = []
        
        for attempt in range(self.max_retries + 1):
            logger.info("[AgenticRAG] Attempt %d: Retrieving for '%s'", attempt, current_query)
            
            # RAGから検索 (既存のRAGモジュールを呼び出し)
            # retrieve があればそれを使い、なければ query にフォールバック
            if hasattr(self.rag, 'retrieve'):
                result = self.rag.retrieve(current_query)
            else:
                result = self.rag.query(current_query)
            # async rag_client (AsyncMock等) の場合は await、同期ならそのまま使う
            if hasattr(result, '__await__'):
                contexts = await result
            else:
                contexts = result
            all_contexts.extend(contexts)
            
            # 重複除去や整形が必要ならここで実施
            
            if attempt == self.max_retries:
                logger.warning("[AgenticRAG] Max retries reached. Returning best available context.")
                break
                
            # LLMによる信頼度評価
            confidence, next_query = await self.evaluate_confidence(
                current_query,
                [c.content if hasattr(c, 'content') else str(c) for c in contexts],
                goal,
            )
            
            if confidence >= self.threshold:
                logger.info("[AgenticRAG] Confidence threshold met (%.2f >= %.2f).", confidence, self.threshold)
                break
            
            if next_query:
                logger.info("[AgenticRAG] Improving query: '%s' -> '%s'", current_query, next_query)
                current_query = next_query
            else:
                logger.warning("[AgenticRAG] Confidence low but no query improvement suggested. Stopping.")
                break
                
        return all_contexts

