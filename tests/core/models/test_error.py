import pytest
from src.core.models.error import ErrorCode, SHIGOKUError

def test_shigoku_error_from_timeout():
    exc = TimeoutError("Request timed out")
    error = SHIGOKUError.from_exception(exc)
    assert error.code == ErrorCode.AGENT_TIMEOUT
    assert error.retryable is True

def test_shigoku_error_from_network_error():
    exc = Exception("Connection refused by host")
    error = SHIGOKUError.from_exception(exc)
    assert error.code == ErrorCode.NETWORK_ERROR
    assert error.retryable is True

def test_shigoku_error_from_rate_limit():
    exc = Exception("Rate limit reached. 429 Too Many Requests")
    error = SHIGOKUError.from_exception(exc)
    assert error.code == ErrorCode.RATE_LIMIT_EXCEEDED
    assert error.retryable is True

def test_shigoku_error_from_context_length():
    exc = Exception("context_length_exceeded: maximum context length is 8192")
    error = SHIGOKUError.from_exception(exc)
    assert error.code == ErrorCode.CONTEXT_LENGTH_EXCEEDED
    assert error.retryable is False

def test_shigoku_error_from_mcp_error():
    exc = Exception("MCP communication error: bad credentials")
    error = SHIGOKUError.from_exception(exc)
    assert error.code == ErrorCode.MCP_COMMUNICATION_ERROR
    assert error.retryable is False

def test_shigoku_error_from_ethics_blocked():
    exc = Exception("Request blocked by ethics guard")
    error = SHIGOKUError.from_exception(exc)
    assert error.code == ErrorCode.ETHICS_GUARD_BLOCKED
    assert error.retryable is False

def test_shigoku_error_with_context():
    exc = Exception("Unknown error")
    context = {"target": "example.com", "step": "recon"}
    error = SHIGOKUError.from_exception(exc, context=context)
    assert error.context == context
    assert error.code == ErrorCode.UNKNOWN
