import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
import litellm
try:
    from litellm.exceptions import RateLimitError
except ImportError:
    class RateLimitError(Exception): pass

from src.core.models.llm import LLMClient
from src.core.infra.cache_manager import get_cache

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

