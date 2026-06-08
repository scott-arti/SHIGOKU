"""
Attack Package - 脆弱性テストモジュール群

Phase 7: 脆弱性テスト機能

⚠️ 注意: 全テスターは非破壊的ペイロードのみ使用
"""

from .ssrf_tester import (
    SSRFTester,
    SSRFResult,
    SSRFPayloadType,
    create_ssrf_tester,
)
from .lfi_tester import (
    LFITester,
    LFIResult,
    create_lfi_tester,
)
from .cors_tester import (
    CORSTester,
    CORSResult,
    create_cors_tester,
)
from .open_redirect_tester import (
    OpenRedirectTester,
    OpenRedirectResult,
    create_open_redirect_tester,
)
from .xss_tester import (
    XSSTester,
    XSSResult,
    create_xss_tester,
)
from .crlf_tester import (
    CRLFTester,
    CRLFResult,
    create_crlf_tester,
)
from .graphql_analyzer import (
    GraphQLAnalyzer,
    GraphQLAnalysisResult,
    create_graphql_analyzer,
    get_introspection_query,
)
from .native_param_fuzzer import (
    NativeParamFuzzer,
    FuzzResult,
)
from .websocket_tester import (
    WebSocketTester,
    WSTestResult,
    WSVulnType,
    create_websocket_tester,
)
from .openapi_tester import (
    OpenAPITester,
    APIEndpoint,
    APITestResult,
    create_openapi_tester,
)
from .ssti_scanner import (
    SSTIScanner,
    SSTIResult,
    TemplateEngine,
    create_ssti_scanner,
)
from .param_fuzzer import (
    ParameterFuzzer,
    FuzzResult as ParamFuzzResult,
    create_param_fuzzer,
)
# # Auth Bypass Tools (relocated from src/agents/swarm/)
# from .auth import (
#     BaseAuthAgent,
#     JWTInspector,
#     OAuthDancer,
#     MFABypasser,
# )
# # Business Logic Tools (relocated from src/agents/swarm/)
# from .logic import (
#     BizLogicHunter,
#     VerifyResult,
#     VerifyContext,
# )


__all__ = [
    # SSRF
    "SSRFTester",
    "SSRFResult",
    "SSRFPayloadType",
    "create_ssrf_tester",
    # LFI
    "LFITester",
    "LFIResult",
    "create_lfi_tester",
    # CORS
    "CORSTester",
    "CORSResult",
    "create_cors_tester",
    # Open Redirect
    "OpenRedirectTester",
    "OpenRedirectResult",
    "create_open_redirect_tester",
    # XSS
    "XSSTester",
    "XSSResult",
    "create_xss_tester",
    # CRLF
    "CRLFTester",
    "CRLFResult",
    "create_crlf_tester",
    # GraphQL
    "GraphQLAnalyzer",
    "GraphQLAnalysisResult",
    "create_graphql_analyzer",
    "get_introspection_query",
    # Parameter Fuzzer
    "ParameterFuzzer",
    "ParamFuzzResult",
    "ParamLocation",
    "ReflectionType",
    "create_param_fuzzer",
    # WebSocket
    "WebSocketTester",
    "WSTestResult",
    "WSVulnType",
    "create_websocket_tester",
    # OpenAPI
    "OpenAPITester",
    "APIEndpoint",
    "APITestResult",
    "create_openapi_tester",
    # SSTI
    "SSTIScanner",
    "SSTIResult",
    "TemplateEngine",
    "create_ssti_scanner",
    # Auth Bypass
    "BaseAuthAgent",
    "JWTInspector",
    "OAuthDancer",
    "MFABypasser",
    # Business Logic
    "BizLogicHunter",
    "VerifyResult",
    "VerifyContext",
]

