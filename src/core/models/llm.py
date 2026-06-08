import hashlib
import json
import logging
import asyncio
import inspect
import os
from typing import Any, Dict, List, Optional
import litellm
from pydantic import BaseModel

from src.core.security.pii_masker import get_pii_masker
from src.core.infra.cache_manager import get_cache
from src.core.utils.llm_retry import retry_llm

logger = logging.getLogger(__name__)


class Message(BaseModel):
    role: str
    content: str


class DictToObject:
    def __init__(self, dictionary):
        for key, value in dictionary.items():
            if isinstance(value, dict):
                setattr(self, key, DictToObject(value))
            elif isinstance(value, list):
                setattr(self, key, [DictToObject(x) if isinstance(x, dict) else x for x in value])
            else:
                setattr(self, key, value)
    
    def __getitem__(self, key):
        return getattr(self, key)
        
    def get(self, key, default=None):
        return getattr(self, key, default)


class LLMClient:
    """
    LLMクライアント（ローカル/クラウド自動ルーティング対応）
    
    設定に応じてローカルLLM（Ollama）とクラウドLLM（GPT-4等）を
    自動的に使い分ける。単純タスクはローカル、複雑タスクはクラウド。
    """
    
    def __init__(
        self,
        model: Optional[str] = None,
        use_local: Optional[bool] = None,
        local_model: Optional[str] = None,
        local_base_url: Optional[str] = None,
        auto_route: Optional[bool] = None,
    ):
        """
        初期化
        
        Args:
            model: クラウドLLMモデル名
            use_local: ローカルLLMを優先使用するか（Noneの場合は設定値を使用）
            local_model: ローカルLLMモデル名
            local_base_url: Ollama APIベースURL
            auto_route: タスク複雑度に基づく自動ルーティング（Noneの場合は設定値を使用）
        """
        from src.core.config.settings import get_settings
        
        # 設定値の読み込み
        try:
            settings = get_settings()
            default_use_local = settings.llm_use_local
            default_auto_route = settings.llm_auto_route
        except Exception:
            # 設定が読み込めない場合のデフォルト
            default_use_local = False
            default_auto_route = True

        try:
            from src.config import settings as app_settings
            default_model = getattr(app_settings, "model_output", None) or getattr(app_settings, "model", None)
            default_local_model = getattr(app_settings, "local_llm_model", None)
            default_local_base_url = getattr(app_settings, "local_llm_base_url", None)
        except Exception:
            default_model = None
            default_local_model = None
            default_local_base_url = None

        self.model = model or default_model or os.getenv("SHIGOKU_MODEL_OUTPUT") or os.getenv("SHIGOKU_MODEL") or "deepseek/deepseek-chat"
        self.use_local = use_local if use_local is not None else default_use_local
        self.auto_route = auto_route if auto_route is not None else default_auto_route
        self._local_provider: Optional[Any] = None
        self._local_model = local_model or default_local_model or os.getenv("SHIGOKU_LOCAL_LLM_MODEL") or "qwen3.5:latest"
        self._local_base_url = local_base_url or default_local_base_url or "http://localhost:11434"
        
        if self.use_local or self.auto_route:
            self._init_local_provider()
    
    def _init_local_provider(self) -> None:
        """ローカルLLMプロバイダを初期化"""
        try:
            from src.core.llm.local_provider import LocalLLMProvider
            self._local_provider = LocalLLMProvider(
                model=self._local_model,
                base_url=self._local_base_url,
            )
        except ImportError:
            logger.warning("LocalLLMProvider not available")
            self._local_provider = None

    def _run_safe(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        """
        同期/非同期関数を安全に実行
        主に同期的コンテキスト (generate) から非同期キャッシュを呼ぶために使用
        """
        try:
            # 現在のイベントループを取得
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                # ループがない場合は新しく作成
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            if loop.is_running():
                # ループが実行中の場合（別のスレッドなどで実行されている場合）
                # 注意: 同一スレッドでループが実行中の場合、run_until_complete は使えない
                res = func(*args, **kwargs)
                if inspect.isawaitable(res):
                    # 実行中のループに投げ込んで待機（デッドロックに注意）
                    # LLMClient は通常 Conductor の別スレッド loop で動くため run_coroutine_threadsafe が無難
                    future = asyncio.run_coroutine_threadsafe(res, loop)
                    return future.result(timeout=10)
                return res
            else:
                # ループが実行中でない場合
                res = func(*args, **kwargs)
                if inspect.isawaitable(res):
                    return loop.run_until_complete(res)
                return res
        except Exception as e:
            logger.debug(f"LLMClient._run_safe failed: {e}")
            return None
    
    def _should_use_local(self, messages: List[Dict[str, str]]) -> bool:
        """
        ローカルLLMを使用すべきか判定
        
        Args:
            messages: チャットメッセージリスト
            
        Returns:
            ローカルLLMを使用すべきならTrue
        """
        if self._local_provider is None:
            return False
        
        if not self._local_provider.is_available():
            return False
        
        if self.use_local:
            return True
        
        if self.auto_route:
            try:
                from src.core.llm.local_provider import TaskComplexityClassifier
                return TaskComplexityClassifier.is_simple_task(messages)
            except ImportError:
                return False
        
        return False

    def _normalize_messages_for_provider(self, messages: List[Any]) -> List[Any]:
        """プロバイダ送信前に message 形式を正規化する。"""
        normalized: List[Any] = []
        converted_count = 0

        for idx, message in enumerate(messages or []):
            # LiteLLM/OpenAI 由来オブジェクトを dict に展開し、reasoning_content を保持する
            # （DeepSeek thinking + tool-call 連鎖での 400 回避）
            if hasattr(message, "role") and not isinstance(message, dict):
                obj_payload: Dict[str, Any] = {
                    "role": getattr(message, "role", ""),
                    "content": getattr(message, "content", ""),
                }
                if hasattr(message, "reasoning_content"):
                    obj_payload["reasoning_content"] = getattr(message, "reasoning_content")
                if hasattr(message, "tool_calls"):
                    obj_payload["tool_calls"] = getattr(message, "tool_calls")
                if hasattr(message, "tool_call_id"):
                    obj_payload["tool_call_id"] = getattr(message, "tool_call_id")
                if hasattr(message, "name"):
                    obj_payload["name"] = getattr(message, "name")
                message = obj_payload
                converted_count += 1

            if not isinstance(message, dict):
                normalized.append(message)
                continue

            role = str(message.get("role", ""))
            if role != "function":
                normalized.append(message)
                continue

            converted = dict(message)
            converted["role"] = "tool"
            if not converted.get("tool_call_id"):
                tool_name = str(converted.get("name") or "legacy_function")
                converted["tool_call_id"] = f"legacy_{tool_name}_{idx}"
            if converted.get("content") is None:
                converted["content"] = ""

            normalized.append(converted)
            converted_count += 1

        if converted_count:
            logger.debug("Normalized %d provider message(s) for request payload", converted_count)

        return normalized

    @staticmethod
    def _is_deepseek_model(model_name: str) -> bool:
        lowered = str(model_name or "").strip().lower()
        return lowered.startswith("deepseek/") or lowered in {
            "deepseek-chat",
            "deepseek-reasoner",
            "deepseek-v4-flash",
            "deepseek-v4-pro",
        }

    @staticmethod
    def _normalize_reasoning_effort(raw: Any) -> str:
        value = str(raw or "").strip().lower()
        if value in {"max", "xhigh"}:
            return "max"
        # DeepSeek docs: low/medium are compatibility-mapped to high.
        return "high"

    def _prepare_deepseek_request_kwargs(
        self,
        *,
        model_name: str,
        request_kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        DeepSeek v4 向けに thinking / reasoning_effort を安全に補完する。
        """
        prepared = dict(request_kwargs)
        if not self._is_deepseek_model(model_name):
            return prepared

        try:
            from src.config import settings as app_settings
            lightweight_model = str(
                app_settings.get_lightweight_model()
                if hasattr(app_settings, "get_lightweight_model")
                else getattr(app_settings, "model_lightweight", "")
            )
            if model_name == lightweight_model:
                thinking_enabled = bool(
                    getattr(app_settings, "deepseek_thinking_enabled_for_lightweight", False)
                )
                effort = getattr(app_settings, "deepseek_reasoning_effort_lightweight", "high")
            else:
                thinking_enabled = bool(
                    getattr(app_settings, "deepseek_thinking_enabled_for_output", True)
                )
                effort = getattr(app_settings, "deepseek_reasoning_effort_output", "high")

            # compatibility alias の明示補正
            lowered = model_name.strip().lower()
            if lowered.endswith("deepseek-chat"):
                thinking_enabled = False
            elif lowered.endswith("deepseek-reasoner"):
                thinking_enabled = True

            extra_body = prepared.get("extra_body")
            if not isinstance(extra_body, dict):
                extra_body = {}
            thinking_payload = extra_body.get("thinking")
            if not isinstance(thinking_payload, dict):
                thinking_payload = {}
            thinking_payload.setdefault("type", "enabled" if thinking_enabled else "disabled")
            extra_body["thinking"] = thinking_payload
            prepared["extra_body"] = extra_body

            if thinking_enabled and "reasoning_effort" not in prepared:
                prepared["reasoning_effort"] = self._normalize_reasoning_effort(effort)

            # non-thinking では余計な effort 指定を消して provider 側の解釈ぶれを防ぐ
            if not thinking_enabled and "reasoning_effort" in prepared:
                prepared.pop("reasoning_effort", None)
        except Exception as exc:
            logger.debug("DeepSeek request preparation skipped: %s", exc)

        return prepared

    def _get_cache_key(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> str:
        """キャッシュキーを生成"""
        # クエリに関係する要素を正規化してハッシュ化
        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "params": {k: v for k, v in kwargs.items() if k != "timeout"}
        }
        dump = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        return f"llm_cache_{hashlib.sha256(dump.encode()).hexdigest()}"

    @retry_llm(max_retries=3)
    def _completion_with_retry(self, **kwargs) -> Any:
        """リトライ付きの同期的API呼び出し"""
        return litellm.completion(**kwargs)

    @retry_llm(max_retries=3)
    async def _acompletion_with_retry(self, **kwargs) -> Any:
        """リトライ付きの非同期的API呼び出し"""
        return await litellm.acompletion(**kwargs)

    def generate(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        force_cloud: bool = False,
        mask_pii: bool = True,
        **kwargs,
    ) -> Any:
        """
        LLMから応答を生成

        Args:
            messages: チャットメッセージリスト
            tools: ツール定義
            force_cloud: クラウドLLMを強制使用
            mask_pii: PII/機密情報をマスクするか（デフォルト: True）
            **kwargs: Note: temperatureなどの追加パラメータ

        Returns:
            LLM応答オブジェクト
        """
        # 文字列が渡された場合はメッセージ形式に変換
        if isinstance(messages, str):
            messages = [{"role": "user", "content": messages}]

        # PIIマスキング
        if mask_pii:
            masker = get_pii_masker()
            messages = masker.mask_messages(messages)

        messages = self._normalize_messages_for_provider(messages)

        # 1. キャッシュチェック（ローカル/クラウド両方に適用）
        cache = get_cache()
        cache_key = self._get_cache_key(messages, tools, **kwargs)
        cached_response = self._run_safe(cache.get, cache_key)
        if cached_response and not kwargs.get("force_cloud"):
            logger.debug("LLM cache hit: %s", cache_key)
            if isinstance(cached_response, dict):
                return DictToObject(cached_response)
            return cached_response

        # 2. ローカルLLMを試行
        if not force_cloud and self._should_use_local(messages):
            try:
                logger.debug("Using local LLM: %s", self._local_model)
                response = self._local_provider.generate(messages, tools)
                # ローカルの結果もキャッシュに保存
                if response:
                    resp_dict = response.dict() if hasattr(response, "dict") else response
                    self._run_safe(cache.set, cache_key, resp_dict)
                if isinstance(response, dict):
                    return DictToObject(response)
                return response
            except Exception as e:
                logger.warning("Local LLM failed, falling back to cloud: %s", e)

        # 3. クラウドLLM
        try:
            from src.core.config.settings import get_settings
            settings = get_settings()
            # Note: src.core.config.Settings doesn't have llm_request_timeout directly, 
            # it might be in a sub-config or we use a default. 
            # Checking src/config.py, it was 300.
            timeout = kwargs.pop("timeout", 300) 

            # Any-LLM Proxy Injection
            if settings.llm_use_any_llm_proxy:
                kwargs["api_base"] = settings.any_llm_base_url
                kwargs["api_key"] = settings.any_llm_api_key

            # Provider Safety Settings (Security Tool requirements)

            # Fix for empty tools list causing issues in some providers
            if tools is not None and len(tools) == 0:
                tools = None

            logger.debug("Using cloud LLM: %s (timeout=%s)", self.model, timeout)
            
            # 関数呼び出しを処理するためのループ
            max_tool_call_rounds = 5  # 最大5回のツール呼び出しを許可
            current_messages = messages[:]
            final_response = None
            
            for round_num in range(max_tool_call_rounds):
                request_messages = self._normalize_messages_for_provider(current_messages)
                cloud_kwargs = self._prepare_deepseek_request_kwargs(
                    model_name=str(self.model or ""),
                    request_kwargs={
                        "model": self.model,
                        "messages": request_messages,
                        "tools": tools,
                        "tool_choice": "auto" if tools else None,
                        "temperature": kwargs.get("temperature", 0),
                        "timeout": timeout,
                        **{k: v for k, v in kwargs.items() if k != "temperature"},
                    },
                )
                response = self._completion_with_retry(**cloud_kwargs)
                
                # 関数呼び出しがあるか確認
                if hasattr(response, 'choices') and response.choices:
                    choice = response.choices[0]
                    if hasattr(choice, 'message') and choice.message.tool_calls:
                        # 関数呼び出しがある場合、関数を実行して結果を取得
                        tool_calls = choice.message.tool_calls
                        
                        # 関数呼び出しをメッセージ履歴に追加
                        current_messages.append(choice.message)
                        
                        # 各ツール呼び出しを実行
                        for tool_call in tool_calls:
                            # ツール名と引数を取得
                            function_name = tool_call.function.name
                            function_args = tool_call.function.arguments
                            
                            # ツール実行結果を取得（ここではダミーの実装）
                            # 実際には、ツール名に応じた実装が必要
                            logger.debug(f"Executing tool: {function_name} with args: {function_args}")
                            
                            # ツール実行結果のダミー
                            tool_result = f"Result from {function_name}"
                            
                            # ツール実行結果をメッセージ履歴に追加
                            current_messages.append({
                                "role": "tool",
                                "name": function_name,
                                "content": tool_result,
                                "tool_call_id": tool_call.id
                            })
                        
                        # 次のラウンドのためにループを続ける
                        continue
                    else:
                        # 関数呼び出しがない場合はループを抜ける
                        break
                else:
                    # 選択肢がないか、ツール呼び出しが終わった場合は終了
                    final_response = response
                    break
            
            # 最大ラウンドに達した場合のフォールバック
            if final_response is None and 'response' in locals():
                final_response = response

            # 結果をキャッシュ (ModelResponseオブジェクトをそのまま保存)
            if final_response:
                # pydanticモデル(litellm.ModelResponse)は dict に変換してキャッシュするのが安全
                resp_dict = final_response.dict() if hasattr(final_response, "dict") else final_response
                self._run_safe(cache.set, cache_key, resp_dict)

            if isinstance(final_response, dict):
                return DictToObject(final_response)
            return final_response
        except litellm.exceptions.AuthenticationError as e:
            # 認証エラー時は設定されたフォールバックモデルへ退避
            try:
                from src.core.config.settings import get_settings
                fallback_model = (
                    getattr(get_settings(), "llm_fallback_model", None)
                    or os.getenv("SHIGOKU_MODEL_OUTPUT")
                    or os.getenv("SHIGOKU_MODEL")
                    or "deepseek/deepseek-v4-flash"
                )
            except Exception:
                fallback_model = os.getenv("SHIGOKU_MODEL_OUTPUT") or os.getenv("SHIGOKU_MODEL") or "deepseek/deepseek-v4-flash"
            logger.error("LLM Authentication Error: %s. Attempting fallback to %s...", e, fallback_model)
            if self.model != fallback_model:
                original_model = self.model
                self.model = fallback_model
                try:
                    return self.generate(messages, tools, force_cloud=True, mask_pii=mask_pii, **kwargs)
                finally:
                    self.model = original_model
            raise
        except Exception as e:
            logger.error("Error generating response: %s", e)
            raise
    
    def generate_thought(self, prompt: str, **kwargs) -> str:
        """
        プロンプトから思考プロセス（テキストのみ）を生成
        ActorCriticFuzzer等の互換性のために維持
        """
        response = self.generate(prompt, **kwargs)
        if hasattr(response, 'choices') and response.choices:
            return response.choices[0].message.content
        return str(response)
    
    async def agenerate(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict[str, Any]]] = None,
        force_cloud: bool = False,
        mask_pii: bool = True,
        **kwargs,
    ) -> Any:
        """
        非同期でLLM応答を生成
        
        Args:
            messages: チャットメッセージリスト
            tools: ツール定義
            force_cloud: クラウドLLMを強制使用
            **kwargs: 追加パラメータ
        Returns:
            LLM応答オブジェクト
        """
        # 文字列が渡された場合はメッセージ形式に変換
        if isinstance(messages, str):
            messages = [{"role": "user", "content": messages}]

        # PIIマスキング
        if mask_pii:
            masker = get_pii_masker()
            messages = masker.mask_messages(messages)

        messages = self._normalize_messages_for_provider(messages)
        
        # 1. キャッシュチェック (非同期)
        cache = get_cache()
        cache_key = self._get_cache_key(messages, tools, **kwargs)
        cached_response = await cache.get(cache_key)
        if cached_response and not kwargs.get("force_cloud"):
            logger.debug("LLM cache hit (async): %s", cache_key)
            if isinstance(cached_response, dict):
                return DictToObject(cached_response)
            return cached_response

        # 2. ローカルLLMを試行
        if not force_cloud and self._should_use_local(messages):
            try:
                logger.debug("Using local LLM (async): %s", self._local_model)
                response = await self._local_provider.agenerate(messages, tools)
                # ローカルの結果もキャッシュに保存
                if response:
                    resp_dict = response.dict() if hasattr(response, "dict") else response
                    await cache.set(cache_key, resp_dict)
                return response
            except Exception as e:
                logger.warning("Local LLM failed, falling back to cloud: %s", e)
        
        # 3. クラウドLLM
        try:
            from src.core.config.settings import get_settings
            settings = get_settings()
            timeout = kwargs.pop("timeout", 300)
            
            # Any-LLM Proxy Injection
            if settings.llm_use_any_llm_proxy:
                kwargs["api_base"] = settings.any_llm_base_url
                kwargs["api_key"] = settings.any_llm_api_key

            # Provider Safety Settings (Security Tool requirements)
            
            # Fix for empty tools list
            if tools is not None and len(tools) == 0:
                tools = None

            logger.debug("Using cloud LLM (async): %s (timeout=%s)", self.model, timeout)
            
            # 関数呼び出しを処理するためのループ
            max_tool_call_rounds = 5  # 最大5回のツール呼び出しを許可
            current_messages = messages[:]
            final_response = None
            
            for round_num in range(max_tool_call_rounds):
                request_messages = self._normalize_messages_for_provider(current_messages)
                cloud_kwargs = self._prepare_deepseek_request_kwargs(
                    model_name=str(self.model or ""),
                    request_kwargs={
                        "model": self.model,
                        "messages": request_messages,
                        "tools": tools,
                        "tool_choice": "auto" if tools else None,
                        "temperature": kwargs.get("temperature", 0),
                        "timeout": timeout,
                        **{k: v for k, v in kwargs.items() if k != "temperature"},
                    },
                )
                response = await self._acompletion_with_retry(**cloud_kwargs)
                
                # 関数呼び出しがあるか確認
                if hasattr(response, 'choices') and response.choices:
                    choice = response.choices[0]
                    if hasattr(choice, 'message') and choice.message.tool_calls:
                        # 関数呼び出しがある場合、関数を実行して結果を取得
                        tool_calls = choice.message.tool_calls
                        
                        # 関数呼び出しをメッセージ履歴に追加
                        current_messages.append(choice.message)
                        
                        # 各ツール呼び出しを実行
                        for tool_call in tool_calls:
                            # ツール名と引数を取得
                            function_name = tool_call.function.name
                            function_args = tool_call.function.arguments
                            
                            # ツール実行結果を取得（ここではダミーの実装）
                            # 実際には、ツール名に応じた実装が必要
                            logger.debug(f"Executing tool: {function_name} with args: {function_args}")
                            
                            # ツール実行結果のダミー
                            tool_result = f"Result from {function_name}"
                            
                            # ツール実行結果をメッセージ履歴に追加
                            current_messages.append({
                                "role": "tool",
                                "name": function_name,
                                "content": tool_result,
                                "tool_call_id": tool_call.id
                            })
                        
                        # 次のラウンドのためにループを続ける
                        continue
                    else:
                        # 関数呼び出しがない場合はループを抜ける
                        break
                else:
                    # 選択肢がないか、ツール呼び出しが終わった場合は終了
                    final_response = response
                    break

            # 最大ラウンドに達した場合のフォールバック
            if final_response is None and 'response' in locals():
                final_response = response

            # 結果をキャッシュ
            if final_response:
                resp_dict = final_response.dict() if hasattr(final_response, "dict") else final_response
                await cache.set(cache_key, resp_dict)

            if isinstance(final_response, dict):
                return DictToObject(final_response)
            return final_response
        except litellm.exceptions.AuthenticationError as e:
            # 非同期版認証エラーフォールバック
            try:
                from src.core.config.settings import get_settings
                fallback_model = (
                    getattr(get_settings(), "llm_fallback_model", None)
                    or os.getenv("SHIGOKU_MODEL_OUTPUT")
                    or os.getenv("SHIGOKU_MODEL")
                    or "deepseek/deepseek-v4-flash"
                )
            except Exception:
                fallback_model = os.getenv("SHIGOKU_MODEL_OUTPUT") or os.getenv("SHIGOKU_MODEL") or "deepseek/deepseek-v4-flash"
            logger.error("LLM Authentication Error (Async): %s. Attempting fallback to %s...", e, fallback_model)
            if self.model != fallback_model:
                original_model = self.model
                self.model = fallback_model
                try:
                    return await self.agenerate(messages, tools, force_cloud=True, mask_pii=mask_pii, **kwargs)
                finally:
                    self.model = original_model
            raise
        except Exception as e:
            logger.error("Error generating async response: %s", e)
            raise

    async def agenerate_thought(self, prompt: str, **kwargs) -> str:
        """
        非同期で思考プロセス（テキストのみ）を生成
        """
        response = await self.agenerate(prompt, **kwargs)
        if hasattr(response, 'choices') and response.choices:
            return response.choices[0].message.content
        return str(response)
