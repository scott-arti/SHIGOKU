import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
import litellm
try:
    from litellm.exceptions import RateLimitError
except ImportError:
    class RateLimitError(Exception): pass

from src.core.models.llm import LLMClient
from src.core.config.settings import LLMSettings, LLMRoleSettings, LLMProfileSettings, LLMProviderSettings
from src.core.infra.cache_manager import get_cache

# Module-level env setup: the new YAML-based LLM config requires API keys to be set
import os
os.environ.setdefault("DEEPSEEK_API_KEY", "test-key")
os.environ.setdefault("OPENAI_API_KEY", "test-key")
os.environ.setdefault("ANY_LLM_API_KEY", "test-key")

# ============================================================
# Role-aware LLMClient tests
# ============================================================

class TestLLMClientRoleAware:
    """TDD: LLMClient accepts role parameter and resolves via LLMRoleResolver."""

    @pytest.fixture
    def role_llm_config(self):
        """Minimal LLMSettings for role-based testing."""
        return LLMSettings(
            schema_version=1,
            default_role="specialist_light",
            providers={
                "deepseek": {"api_key_env": "DEEPSEEK_API_KEY"},
            },
            profiles={
                "cheap": {"provider": "deepseek", "model": "ds/flash", "temperature": 0.0},
                "reasoning": {"provider": "deepseek", "model": "ds/pro", "temperature": 0.0,
                              "extra": {"thinking": {"type": "enabled"}}},
            },
            roles={
                "specialist_light": {"profile": "cheap"},
                "planner": {"profile": "reasoning"},
            },
        )

    def test_role_sets_model(self, role_llm_config):
        """LLMClient(role='planner') should set the correct model from config."""
        client = LLMClient(role="planner", _llm_config=role_llm_config)
        assert client.model == "ds/pro"

    def test_role_sets_temperature(self, role_llm_config):
        """LLMClient(role='planner') should inherit profile temperature."""
        client = LLMClient(role="planner", _llm_config=role_llm_config)
        assert client.temperature == 0.0

    def test_role_accepts_deprecated_params(self, role_llm_config):
        """When using role, deprecated Ollama params should be accepted silently."""
        client = LLMClient(role="planner", _llm_config=role_llm_config,
                           use_local=True, auto_route=True)
        assert client.model == "ds/pro"

    def test_model_param_precedence_over_role(self, role_llm_config):
        """Explicit model parameter should win over role."""
        client = LLMClient(model="custom/model", role="planner", _llm_config=role_llm_config)
        assert client.model == "custom/model"

    def test_role_unknown_falls_back_to_default(self, role_llm_config):
        """Unknown role should resolve to default_role."""
        client = LLMClient(role="nonexistent", _llm_config=role_llm_config)
        assert client.model == "ds/flash"

    def test_backward_compat_no_role(self, role_llm_config):
        """Without role, LLMClient works as before."""
        client = LLMClient(model="legacy-model", _llm_config=role_llm_config)
        assert client.model == "legacy-model"

    def test_role_sets_extra_for_thinking(self, role_llm_config):
        """Profile extra fields should be accessible."""
        client = LLMClient(role="planner", _llm_config=role_llm_config)
        assert client.model_extra == {"thinking": {"type": "enabled"}}

    def test_role_default_model_construction_works(self, role_llm_config):
        """Default construction without role should work with explicit model."""
        client = LLMClient(model="test", _llm_config=role_llm_config)
        assert client.model == "test"

    def test_role_api_key_env_propagated(self, role_llm_config):
        """LLMClient(role='planner') should store api_key_env from resolution."""
        client = LLMClient(role="planner", _llm_config=role_llm_config)
        assert client._role_result is not None
        assert client._role_result.api_key_env == "DEEPSEEK_API_KEY"

    def test_role_base_url_propagated(self, role_llm_config):
        """LLMClient(role='planner') should store base_url from resolution."""
        client = LLMClient(role="planner", _llm_config=role_llm_config)
        assert client._role_result.base_url is None  # deepseek provider has no base_url

    def test_role_timeout_propagated(self, role_llm_config):
        """LLMClient(role='planner') should store timeout from resolution."""
        client = LLMClient(role="planner", _llm_config=role_llm_config)
        assert client._role_result.timeout_seconds == 300

    def test_role_resolver_stored(self, role_llm_config):
        """LLMClient(role='planner') should store the resolver for fallback."""
        client = LLMClient(role="planner", _llm_config=role_llm_config)
        assert client._resolver is not None

@pytest.fixture
def llm_client():
    return LLMClient(model="gpt-4o", use_local=False)

@pytest.mark.asyncio
async def test_llm_cache_integration(llm_client):
    """キャッシュが正常に機能することを検証"""
    messages = [{"role": "user", "content": "Hello, cache test"}]
    
    # 1回目の呼び出し (Mock)
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.tool_calls = None
    mock_response.choices[0].message.content = "Hello back"
    # dict() 呼び出し時に返される内容 (キャッシュに保存される)
    mock_response.dict.return_value = {"choices": [{"message": {"content": "Hello back"}}]}
    # item access (__getitem__) をサポートさせる (テストの assert res1["choices"] 用)
    mock_response.__getitem__.side_effect = lambda k: mock_response.dict.return_value[k]

    with patch("litellm.acompletion", AsyncMock(return_value=mock_response)) as mock_completion:
        # 初回: キャッシュミス
        res1 = await llm_client.agenerate(messages)
        assert res1["choices"][0]["message"]["content"] == "Hello back"
        assert mock_completion.call_count == 1
        
        # 2回目: キャッシュヒット (litellm.acompletion が呼ばれないはず)
        # キャッシュからは dict が返ってくる
        res2 = await llm_client.agenerate(messages)
        assert res2["choices"][0]["message"]["content"] == "Hello back"
        assert mock_completion.call_count == 1  # 増えていない

@pytest.mark.asyncio
async def test_llm_retry_on_ratelimit(llm_client):
    """RateLimitError時にリトライされることを検証"""
    messages = [{"role": "user", "content": "Retry test"}]
    
    # 最初はエラーを投げ、次に成功するモック
    err = RateLimitError("Rate limit reached", model="gpt-4o", llm_provider="openai")
    
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.tool_calls = None
    mock_response.choices[0].message.content = "Success after retry"
    mock_response.dict.return_value = {"choices": [{"message": {"content": "Success after retry"}}]}
    mock_response.__getitem__.side_effect = lambda k: mock_response.dict.return_value[k]
    
    with patch("litellm.acompletion", AsyncMock(side_effect=[err, mock_response])) as mock_completion:
        # force_cloud=Trueでキャッシュを回避
        res = await llm_client.agenerate(messages, force_cloud=True)
        
        assert res["choices"][0]["message"]["content"] == "Success after retry"
        assert mock_completion.call_count == 2

