"""
LocalLLMProvider: Ollama経由のローカルLLM統合

Qwen3:8b等のローカルモデルを使用してAPIコストを削減する。
litellm経由でOllamaに接続。
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import litellm

logger = logging.getLogger(__name__)


class LocalLLMProvider:
    """
    Ollamaを使用したローカルLLMプロバイダ
    
    単純なタスク（分類、要約等）をローカルモデルにオフロードし、
    APIコストを削減する。
    
    使用例:
        provider = LocalLLMProvider(model="qwen3:8b")
        if provider.is_available():
            response = await provider.generate([
                {"role": "user", "content": "Classify this vulnerability..."}
            ])
    """
    
    def __init__(
        self,
        model: str = "qwen3:8b",
        base_url: str = "http://localhost:11434",
        timeout: float = 60.0,
    ):
        """
        初期化
        
        Args:
            model: Ollamaモデル名
            base_url: Ollama APIベースURL
            timeout: リクエストタイムアウト（秒）
        """
        self.model = f"ollama/{model}"
        self.base_url = base_url
        self.timeout = timeout
        self._available: Optional[bool] = None
        
        # litellmの設定
        os.environ["OLLAMA_API_BASE"] = base_url
    
    def is_available(self) -> bool:
        """
        Ollamaが利用可能かチェック
        
        Returns:
            利用可能ならTrue
        """
        if self._available is not None:
            return self._available
        
        try:
            import httpx
            response = httpx.get(
                f"{self.base_url}/api/tags",
                timeout=5.0
            )
            self._available = response.status_code == 200
            if self._available:
                logger.info(f"Ollama is available at {self.base_url}")
            return self._available
        except Exception as e:
            logger.warning(f"Ollama not available: {e}")
            self._available = False
            return False
    
    def _optimize_messages(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        メッセージをローカルモデル向けに最適化
        
        思考の連鎖（CoT）を簡略化し、冗長な説明を避けるよう
        システムプロンプトを調整する。
        """
        # すでに最適化済みの場合はスキップ
        if any("[LOCAL_OPTIMIZED]" in msg.get("content", "") for msg in messages):
            return messages
            
        optimized_messages = messages[:]
        
        local_instruction = (
            "\n\n[LOCAL_OPTIMIZED]\n"
            "あなたは軽量LLMとして動作しています。以下のルールに従ってください:\n"
            "1. 簡潔に答えてください。前置き（「はい、理解しました」等）は不要です。\n"
            "2. 分類、抽出、整形のタスクでは、思考プロセスを最小限にし、結果のみを出力してください。\n"
            "3. 不明な点は推論せず「不明」と回答してください。"
        )
        
        # システムプロンプトを探して追記、なければ作成
        for msg in optimized_messages:
            if msg["role"] == "system":
                msg["content"] += local_instruction
                return optimized_messages
                
        # システムプロンプトがない場合は先頭に追加
        optimized_messages.insert(0, {
            "role": "system",
            "content": f"You are a specialized security analysis assistant.{local_instruction}"
        })
        return optimized_messages

    def generate(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.0,
    ) -> Any:
        """
        ローカルLLMで応答を生成
        
        Args:
            messages: チャットメッセージリスト
            tools: ツール定義（Ollamaの一部モデルでサポート）
            temperature: サンプリング温度
            
        Returns:
            litellm応答オブジェクト
        """
        # メッセージの最適化
        optimized_messages = self._optimize_messages(messages)
        
        try:
            response = litellm.completion(
                model=self.model,
                messages=optimized_messages,
                tools=tools,
                tool_choice="auto" if tools else None,
                temperature=temperature,
                timeout=self.timeout,
            )
            logger.debug(f"Local LLM response generated: {len(str(response))} chars")
            return response
        except Exception as e:
            logger.error(f"Local LLM generation failed: {e}")
            raise
    
    async def agenerate(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.0,
    ) -> Any:
        """
        非同期でローカルLLM応答を生成
        
        Args:
            messages: チャットメッセージリスト
            tools: ツール定義
            temperature: サンプリング温度
            
        Returns:
            litellm応答オブジェクト
        """
        # メッセージの最適化
        optimized_messages = self._optimize_messages(messages)
        
        try:
            response = await litellm.acompletion(
                model=self.model,
                messages=optimized_messages,
                tools=tools,
                tool_choice="auto" if tools else None,
                temperature=temperature,
                timeout=self.timeout,
            )
            logger.debug(f"Local LLM async response generated")
            return response
        except Exception as e:
            logger.error(f"Local LLM async generation failed: {e}")
            raise


class TaskComplexityClassifier:
    """
    タスク複雑度を判定し、ローカル/クラウドLLMを選択
    
    単純なタスク: ローカルLLM
    複雑なタスク: クラウドLLM (GPT-4等)
    """
    
    # 判定閾値（文字数）
    # 大規模なプロンプトはローカルモデルのコンテキスト制限や指示追従低下を招くため
    # 1500文字（約1.5k-2kトークン）を目安にクラウドへ切り替える
    MAX_SIMPLE_CHARS = 1500
    
    # 単純タスクのキーワード（ローカルLLMで処理可能）
    SIMPLE_TASK_PATTERNS = [
        "classify", "categorize", "summarize", "extract", "parse", "format", "translate",
        "分類", "要約", "抽出", "パース", "整形", "翻訳",
        "check output", "parse response", "extract links",
        "json", "xml", "csv", "table", "表形式"
    ]
    
    # 複雑タスクのキーワード（クラウドLLM推奨）
    COMPLEX_TASK_PATTERNS = [
        "analyze vulnerability", "generate exploit", "reason about", "plan attack",
        "chain", "complex logic", "bypass", "escalation",
        "脆弱性分析", "攻撃計画", "推論", "連鎖", "バイパス", "昇格",
        "critic", "review", "audit", "deep dive", "再考", "批判"
    ]
    
    @classmethod
    def is_simple_task(cls, messages: List[Dict[str, str]]) -> bool:
        """
        タスクが単純かどうかを判定
        
        Args:
            messages: チャットメッセージリスト
            
        Returns:
            単純タスクならTrue
        """
        content = " ".join(
            (msg.get("content") or "").lower()
            for msg in messages
        )
        
        # 1. 複雑パターンに該当すれば即座にクラウド判定
        for pattern in cls.COMPLEX_TASK_PATTERNS:
            if pattern in content:
                logger.debug("Complexity: High (Complex pattern matched: '%s')", pattern)
                return False
        
        # 2. 文字数が閾値を超えていればクラウド判定
        if len(content) > cls.MAX_SIMPLE_CHARS:
            logger.debug("Complexity: High (Content length %d > %d)", len(content), cls.MAX_SIMPLE_CHARS)
            return False
            
        # 3. 単純パターンに該当すればローカル判定
        for pattern in cls.SIMPLE_TASK_PATTERNS:
            if pattern in content:
                logger.debug("Complexity: Low (Simple pattern matched: '%s')", pattern)
                return True
        
        # 4. デフォルト判定: 短いメッセージはローカル
        if len(content) < 300:
            logger.debug("Complexity: Low (Short message default)")
            return True
        
        return False
