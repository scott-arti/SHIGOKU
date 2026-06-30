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
from src.core.engine.run_ledger_llm_usage import (
    try_record_llm_usage, try_record_llm_cache_hit,
    try_record_llm_failed, try_record_provider_fallback,
)

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
    """LLM client with role-based model resolution via LLMRoleResolver.

Resolves model, provider, API keys, and system prompt from config/shigoku.yaml
role definitions. Supports sync and async generation with caching, PII masking,
and deepseek thinking configuration.
"""
    
    def __init__(
        self,
        model: Optional[str] = None,
        use_local: Optional[bool] = None,       # [DEPRECATED] ignored
        local_model: Optional[str] = None,       # [DEPRECATED] ignored
        local_base_url: Optional[str] = None,    # [DEPRECATED] ignored
        auto_route: Optional[bool] = None,       # [DEPRECATED] ignored
        role: Optional[str] = None,
        _llm_config: Optional[object] = None,  # injection point for tests
    ):
        """Initialize LLM client.

        Args:
            model: Cloud LLM model name (takes precedence over role).
            use_local: [DEPRECATED] No-op, kept for backward compatibility.
            local_model: [DEPRECATED] No-op.
            local_base_url: [DEPRECATED] No-op.
            auto_route: [DEPRECATED] No-op.
            role: LLM role name. Resolved via LLMRoleResolver when model not specified.
            _llm_config: Test injection point for LLMSettings.
        """
        # Phase 2: role-based resolution
        self._role_name: Optional[str] = None
        self._resolved_profile: Optional[str] = None
        self._resolved_provider: Optional[str] = None
        self._role_result: Optional[object] = None
        self._resolver: Optional[object] = None
        self.model_extra: Dict[str, Any] = {}

        # If model specified directly, use it (takes precedence over role)
        if model:
            self.model = model
        elif role and not model:
            self._resolve_from_role(role, _llm_config)
        else:
            # No role, no model: fallback to env or default
            self.model = os.getenv("SHIGOKU_MODEL") or "deepseek/deepseek-chat"

    def _actor_name(self) -> str:
        """Return the actor name for run ledger recording."""
        return self._role_name or "LLMClient"
    
    def _resolve_from_role(self, role: str, llm_config: Optional[object] = None) -> None:
        """Resolve model/provider from role using LLMRoleResolver."""
        from src.core.config.llm_resolver import LLMRoleResolver, LLMResolutionResult
        from src.core.config.settings import LLMSettings

        if llm_config is not None and isinstance(llm_config, LLMSettings):
            llm = llm_config
        else:
            from src.core.config.settings import get_settings
            llm = get_settings().llm

        self._resolver = LLMRoleResolver(llm)
        self._role_result: LLMResolutionResult = self._resolver.resolve(role)

        self._role_name = self._role_result.role_name
        self._resolved_profile = self._role_result.profile_name
        self._resolved_provider = self._role_result.provider
        self.model = self._role_result.model
        self.model_extra = dict(self._role_result.extra)
        self.temperature = self._role_result.temperature

        # Role-based clients always use cloud API
        pass
    
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
            # Extract thinking config from role profile's extra (config/shigoku.yaml)
            thinking_config = self.model_extra.get("thinking", {})
            if isinstance(thinking_config, dict):
                thinking_type = thinking_config.get("type", "disabled")
                thinking_enabled = thinking_type == "enabled"
                effort = thinking_config.get("reasoning_effort", "high")
            else:
                thinking_enabled = False
                effort = "high"

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
        """キャッシュキーを生成（Phase 4: role文脈を含めて分離）"""
        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "params": {k: v for k, v in kwargs.items() if k != "timeout"}
        }
        # Phase 4: include role context to prevent cross-role cache collisions
        if self._role_name:
            payload["_role"] = {
                "role_name": self._role_name,
                "profile": self._resolved_profile,
                "provider": self._resolved_provider,
                "template": self._role_result.system_prompt_template if self._role_result else None,
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

    def _maybe_inject_system_prompt(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Phase 4: Inject role's system_prompt_template as default system message.
        Only injects if no system message already exists (preserves caller's prompt)."""
        if self._role_result is None or not self._role_result.system_prompt_template:
            return messages
        # Only inject if no system message already present
        if messages and messages[0].get("role") == "system":
            return messages
        try:
            from src.prompts import get_renderer
            rendered = get_renderer().render(self._role_result.system_prompt_template)
            if rendered.strip():
                return [{"role": "system", "content": rendered.strip()}] + list(messages)
        except Exception as e:
            logger.debug("Failed to render system prompt template '%s': %s",
                         self._role_result.system_prompt_template, e)
        return messages

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

        # Phase 4: inject role system prompt template
        messages = self._maybe_inject_system_prompt(messages)

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
            try_record_llm_cache_hit(model=self.model, actor=self._actor_name())
            if isinstance(cached_response, dict):
                return DictToObject(cached_response)
            return cached_response

        # 2. クラウドLLM
        try:
            from src.core.config.settings import get_settings
            settings = get_settings()
            # Note: src.core.config.Settings doesn't have llm_request_timeout directly, 
            # it might be in a sub-config or we use a default. 
            # Checking src/config.py, it was 300.
            timeout = kwargs.pop("timeout", 300)

            # Phase 2: use role-resolved timeout if available
            if self._role_result is not None:
                timeout = self._role_result.timeout_seconds

            # Phase 2: role-resolved API key and base_url
            if self._role_result is not None:
                role_api_key = os.getenv(self._role_result.api_key_env, "")
                if role_api_key:
                    kwargs["api_key"] = role_api_key
                if self._role_result.base_url:
                    kwargs["api_base"] = self._role_result.base_url

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

            if final_response:
                try_record_llm_usage(response=final_response, model=self.model, actor=self._actor_name())
            if isinstance(final_response, dict):
                return DictToObject(final_response)
            return final_response
        except litellm.exceptions.AuthenticationError as e:
            # Phase 2: use role-based fallback resolution if available
            if self._resolver is not None and self._role_name:
                try:
                    fallback_result = self._resolver.resolve_fallback(self._role_name)
                    logger.error("LLM Authentication Error for role '%s': %s. Falling back to profile '%s'.",
                                 self._role_name, e, fallback_result.profile_name)
                    try_record_provider_fallback(
                        from_model=self.model, to_model=fallback_result.model,
                        actor=self._actor_name(), reason=str(e)[:200],
                    )
                    self._role_result = fallback_result
                    self._resolved_profile = fallback_result.profile_name
                    self._resolved_provider = fallback_result.provider
                    self.model = fallback_result.model
                    self.model_extra = dict(fallback_result.extra)
                    self.temperature = fallback_result.temperature
                    return self.generate(messages, tools, force_cloud=True, mask_pii=mask_pii, **kwargs)
                except Exception as fallback_err:
                    logger.error("Role fallback also failed: %s", fallback_err)
                    raise

            # Legacy fallback (non-role clients)
            fallback_model = os.getenv("SHIGOKU_MODEL") or "deepseek/deepseek-v4-flash"
            logger.error("LLM Authentication Error: %s. Attempting fallback to %s...", e, fallback_model)
            if self.model != fallback_model:
                original_model = self.model
                self.model = fallback_model
                try_record_provider_fallback(
                    from_model=original_model, to_model=fallback_model,
                    actor=self._actor_name(), reason=str(e)[:200],
                )
                try:
                    return self.generate(messages, tools, force_cloud=True, mask_pii=mask_pii, **kwargs)
                finally:
                    self.model = original_model
            raise
        except Exception as e:
            logger.error("Error generating response: %s", e)
            try_record_llm_failed(model=self.model, actor=self._actor_name(), error=str(e)[:500])
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

        # Phase 4: inject role system prompt template
        messages = self._maybe_inject_system_prompt(messages)

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
            try_record_llm_cache_hit(model=self.model, actor=self._actor_name())
            if isinstance(cached_response, dict):
                return DictToObject(cached_response)
            return cached_response

        # 2. クラウドLLM
        try:
            from src.core.config.settings import get_settings
            settings = get_settings()
            timeout = kwargs.pop("timeout", 300)

            # Phase 2: use role-resolved timeout if available
            if self._role_result is not None:
                timeout = self._role_result.timeout_seconds

            # Phase 2: role-resolved API key and base_url
            if self._role_result is not None:
                role_api_key = os.getenv(self._role_result.api_key_env, "")
                if role_api_key:
                    kwargs["api_key"] = role_api_key
                if self._role_result.base_url:
                    kwargs["api_base"] = self._role_result.base_url
            
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

            if final_response:
                try_record_llm_usage(response=final_response, model=self.model, actor=self._actor_name())
            if isinstance(final_response, dict):
                return DictToObject(final_response)
            return final_response
        except litellm.exceptions.AuthenticationError as e:
            # Phase 2: use role-based fallback resolution if available
            if self._resolver is not None and self._role_name:
                try:
                    fallback_result = self._resolver.resolve_fallback(self._role_name)
                    logger.error("LLM Auth Error (Async) for role '%s': %s. Falling back to '%s'.",
                                 self._role_name, e, fallback_result.profile_name)
                    try_record_provider_fallback(
                        from_model=self.model, to_model=fallback_result.model,
                        actor=self._actor_name(), reason=str(e)[:200],
                    )
                    self._role_result = fallback_result
                    self._resolved_profile = fallback_result.profile_name
                    self._resolved_provider = fallback_result.provider
                    self.model = fallback_result.model
                    self.model_extra = dict(fallback_result.extra)
                    self.temperature = fallback_result.temperature
                    return await self.agenerate(messages, tools, force_cloud=True, mask_pii=mask_pii, **kwargs)
                except Exception as fallback_err:
                    logger.error("Async role fallback also failed: %s", fallback_err)
                    raise

            # 非同期版認証エラーフォールバック (legacy)
            fallback_model = os.getenv("SHIGOKU_MODEL") or "deepseek/deepseek-v4-flash"
            logger.error("LLM Authentication Error (Async): %s. Attempting fallback to %s...", e, fallback_model)
            if self.model != fallback_model:
                original_model = self.model
                self.model = fallback_model
                try_record_provider_fallback(
                    from_model=original_model, to_model=fallback_model,
                    actor=self._actor_name(), reason=str(e)[:200],
                )
                try:
                    return await self.agenerate(messages, tools, force_cloud=True, mask_pii=mask_pii, **kwargs)
                finally:
                    self.model = original_model
            raise
        except Exception as e:
            logger.error("Error generating async response: %s", e)
            try_record_llm_failed(model=self.model, actor=self._actor_name(), error=str(e)[:500])
            raise

    async def agenerate_thought(self, prompt: str, **kwargs) -> str:
        """
        非同期で思考プロセス（テキストのみ）を生成
        """
        response = await self.agenerate(prompt, **kwargs)
        if hasattr(response, 'choices') and response.choices:
            return response.choices[0].message.content
        return str(response)
