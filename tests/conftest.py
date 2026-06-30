import sys
import os
from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def _ensure_llm_api_keys(monkeypatch):
    """Ensure LLM API key env vars exist before each test."""
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key-session")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-session")
    monkeypatch.setenv("ANY_LLM_API_KEY", "test-key-session")


# Mock requests if not installed or not found, to allow collection of tests
# that don't actually need it (we use httpx)
try:
    import requests
except ImportError:
    sys.modules["requests"] = MagicMock()

try:
    import cryptography
except ImportError:
    sys.modules["cryptography"] = MagicMock()
    sys.modules["cryptography.hazmat"] = MagicMock()
    sys.modules["cryptography.hazmat.primitives"] = MagicMock()
    sys.modules["cryptography.hazmat.primitives.asymmetric"] = MagicMock()

try:
    import litellm
except ImportError:
    sys.modules["litellm"] = MagicMock()
