import sys
from unittest.mock import MagicMock

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
except Exception:
    # litellm import can fail with environment-level dependency mismatches
    # (for example incompatible pydantic / pydantic-core versions).
    sys.modules["litellm"] = MagicMock()
