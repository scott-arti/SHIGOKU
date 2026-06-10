"""InjectionManager の LLM ツール定義。

_register_manager_tools / _register_initial_tools の登録実装本体。
登録実行は facade の register_tool を使用する。
"""

from typing import Any, Callable, Dict


def register_manager_tool_scans(
    register_tool: Callable[[str, Callable[..., Any], str], None],
    specialists: Dict[str, Any],
    run_sqli_hunter: Callable[..., Any],
    run_xss_hunter: Callable[..., Any],
    run_lfi_check: Callable[..., Any],
    run_open_redirect_check: Callable[..., Any],
    run_cmd_ssrf_hunter: Callable[..., Any],
    run_ssrf_hunter: Callable[..., Any],
    run_ssti_hunter: Callable[..., Any],
    run_cors_hunter: Callable[..., Any],
    run_crlf_hunter: Callable[..., Any],
) -> None:
    if "sqli" in specialists:
        register_tool(
            "sqli_scan",
            run_sqli_hunter,
            "\u30b9\u30ad\u30e3\u30f3\u3092\u5b9f\u884c\u3057\u307e\u3059\u3002URL\u3068\u95a2\u9023\u30d1\u30e9\u30e1\u30fc\u30bf\u3092\u81ea\u52d5\u3067\u30c6\u30b9\u30c8\u3057\u307e\u3059\u3002"
        )
    if "xss" in specialists:
        register_tool(
            "xss_scan",
            run_xss_hunter,
            "\u30b9\u30ad\u30e3\u30f3\u3092\u5b9f\u884c\u3057\u307e\u3059\u3002\u53cd\u5c04\u30fb\u683c\u7d0d\u578b\u306a\u3069\u3092\u30c6\u30b9\u30c8\u3057\u307e\u3059\u3002"
        )
    if "lfi" in specialists:
        register_tool(
            "lfi_scan",
            run_lfi_check,
            "\u3084\u30c7\u30a3\u30ec\u30af\u30c8\u30ea\u30c8\u30e9\u30d0\u30fc\u30b5\u30eb\u8106\u5f31\u6027\u3092\u30b9\u30ad\u30e3\u30f3\u3057\u307e\u3059\u3002"
        )
    if "redirect" in specialists:
        register_tool(
            "open_redirect_scan",
            run_open_redirect_check,
            "\u8a73\u7d30\u30b9\u30ad\u30e3\u30f3\u3092\u5b9f\u884c\u3057\u307e\u3059\u3002"
        )
    if "cmd_ssrf" in specialists:
        register_tool(
            "cmd_ssrf_scan",
            run_cmd_ssrf_hunter,
            "\u304a\u3088\u3073SSRF\u8106\u5f31\u6027\u306e\u8a73\u7d30\u30b9\u30ad\u30e3\u30f3\u3092\u5b9f\u884c\u3057\u307e\u3059\u3002"
        )
    if "ssrf" in specialists:
        register_tool(
            "ssrf_scan",
            run_ssrf_hunter,
            "\u3092\u5b9f\u884c\u3057\u307e\u3059\u3002"
        )
    if "ssti" in specialists:
        register_tool(
            "ssti_scan",
            run_ssti_hunter,
            "\u306e\u6c7a\u5b9a\u8ad6\u7684\u30b9\u30ad\u30e3\u30f3\u3092\u5b9f\u884c\u3057\u307e\u3059\u3002"
        )
    if "cors" in specialists:
        register_tool(
            "cors_scan",
            run_cors_hunter,
            "\u306e\u691c\u51fa\u3092\u5b9f\u884c\u3057\u307e\u3059\u3002"
        )
    if "crlf" in specialists:
        register_tool(
            "crlf_scan",
            run_crlf_hunter,
            "\u306e\u6c7a\u5b9a\u8ad6\u7684\u30b9\u30ad\u30e3\u30f3\u3092\u5b9f\u884c\u3057\u307e\u3059\u3002"
        )


def register_initial_tools(
    register_tool: Callable[[str, Callable[..., Any], str], None],
    specialists: Dict[str, Any],
    analyze_parameters: Callable[..., Any],
    run_sqli_hunter: Callable[..., Any],
    run_open_redirect_check: Callable[..., Any],
    run_lfi_check: Callable[..., Any],
    run_xss_hunter: Callable[..., Any],
    run_cmd_ssrf_hunter: Callable[..., Any],
    run_ssrf_hunter: Callable[..., Any],
    run_graphql_hunter: Callable[..., Any],
) -> None:
    register_tool(
        "analyze_parameters",
        analyze_parameters,
        "Analyze URL parameters for injection entry points. Args: url (str)"
    )
    register_tool(
        "run_sqli_hunter",
        run_sqli_hunter,
        "Run Smart SQL Injection Hunter on a target. Args: url (str), params (dict)"
    )
    register_tool(
        "run_open_redirect_check",
        run_open_redirect_check,
        "Check for Open Redirect vulnerabilities. Args: url (str), params (dict)"
    )
    register_tool(
        "run_lfi_check",
        run_lfi_check,
        "Check for LFI/Path Traversal vulnerabilities. Args: url (str), params (dict)"
    )
    register_tool(
        "run_xss_hunter",
        run_xss_hunter,
        "Run Smart XSS Hunter on a target. Args: url (str), params (dict)"
    )
    register_tool(
        "run_cmd_ssrf_hunter",
        run_cmd_ssrf_hunter,
        "Run Smart Command Injection & SSRF Hunter on a target. Args: url (str), params (dict)"
    )
    register_tool(
        "run_ssrf_hunter",
        run_ssrf_hunter,
        "Run deterministic SSRF Hunter on a target. Args: url (str), params (dict)"
    )
    if "graphql" in specialists:
        register_tool(
            "graphql_scan",
            run_graphql_hunter,
            "GraphQL Introspection\u6709\u52b9\u6027\u3092\u691c\u51fa\u3057\u307e\u3059\u3002"
        )
