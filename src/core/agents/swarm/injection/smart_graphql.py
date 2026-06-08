"""
SmartGraphQLHunter - GraphQL Introspection 検出スペシャリスト

機能:
- GraphQL Introspection有効性検出
- GraphiQL Explorer UI検出
- Field Suggestions有効性検出
- Evidence・PoC生成
"""

import html
import logging
from typing import Dict, List

from src.core.agents.swarm.base import Specialist
from src.core.models.finding import Finding, Severity, VulnType, Evidence
from src.core.attack.graphql_analyzer import GraphQLAnalyzer, INTROSPECTION_QUERY

logger = logging.getLogger(__name__)


class SmartGraphQLHunter(Specialist):
    name = "SmartGraphQLHunter"
    description = "GraphQL introspection, schema exposure, and GraphiQL detector"
    timeout_seconds = 120
    is_aggressive = False

    def __init__(self, config: Dict = None):
        super().__init__()
        self.config = config or {}
        self.last_results: List = []

    # META_KEYS定義（control params除外用）
    META_KEYS = {
        "_auth", "method", "content_type", "task_id",
        "targets", "targets_file", "source_file", "cookies",
        "tags", "category", "_context", "extra_targets",
        "auth_headers", "headers", "count",
        "forms", "url_evidence", "scan_profile", "profile",
        "detection_mode", "phase", "phase_hint",
        "phase2_on_empty_phase1", "phase2_max_seconds",
        "phase2_max_seconds_risk_forced", "phase2_risk_force_vuln_types",
        "phase1_force_full_coverage", "phase1_stop_on_first_hit",
        "phase1_early_return_on_findings", "per_url_timeout_seconds",
        "per_url_timeout_by_type", "unknown_classification_only",
        "phase1_auto_early_return_on_findings", "phase1_auto_early_return_cmd",
    }

    async def run_as_tool(self, url: str, params: Dict = None, **_kwargs) -> Dict:
        """Tool execution entry point"""
        _auth = (params or {}).get("_auth", {})
        auth_headers = dict(_auth.get("auth_headers", {}))
        cookies = _auth.get("cookies", "")
        if cookies:
            auth_headers["Cookie"] = cookies

        # 設定継承（大規模スキーマ対応timeout等）
        config_override = params.get("_graphql_config", {}) if params else {}

        analyzer = GraphQLAnalyzer(auth_headers=auth_headers, config=config_override)
        try:
            result = await analyzer.analyze_async(url)
        except Exception as exc:  # Intentional broad catch: external HTTP errors, timeouts, parse errors
            logger.error("GraphQLAnalyzer error on %s: %s", url, exc)
            return {
                "vulnerable": False,
                "findings_count": 0,
                "tested_params": [],
                "introspection_enabled": False,
                "graphiql_enabled": False,
                "field_suggestions_enabled": False,
                "sensitive_fields": [],
                "suggested_fields": [],
                "mutations": [],
                "attack_vectors": [],
                "error": str(exc),
            }
        finally:
            analyzer.close()

        has_sensitive = bool(result.sensitive_fields)
        is_vulnerable = (
            result.introspection_enabled
            or result.graphiql_enabled
            or result.field_suggestions_enabled
        )

        self.last_results = [result]  # type: ignore
        return {
            "vulnerable": is_vulnerable,
            "findings_count": 1 if is_vulnerable else 0,
            "tested_params": [],
            "introspection_enabled": result.introspection_enabled,
            "graphiql_enabled": result.graphiql_enabled,
            "field_suggestions_enabled": result.field_suggestions_enabled,
            "is_large_schema": result.is_large_schema,
            "sensitive_fields": result.sensitive_fields,
            "suggested_fields": result.suggested_fields,
            "mutations": result.mutations,
            "attack_vectors": result.attack_vectors,
            "queries_count": len(result.queries),
            "mutations_count": len(result.mutations),
            "has_sensitive_fields": has_sensitive,
        }

    async def execute(self, task, _quick_mode: bool = False) -> List[Finding]:
        """Specialist execution entry point"""
        result = await self.run_as_tool(task.target, task.params or {})
        return self._convert_to_findings(result, task.target)

    def _convert_to_findings(self, result: dict, target_url: str) -> List[Finding]:
        """Convert analysis result to Finding objects"""
        findings = []

        if not result.get("vulnerable"):
            return findings

        # Severity決定（複合的）
        has_sensitive = result.get("has_sensitive_fields", False)
        has_graphiql = result.get("graphiql_enabled", False)
        has_suggestions = result.get("field_suggestions_enabled", False)
        is_large = result.get("is_large_schema", False)

        if has_sensitive or has_graphiql:
            sev = Severity.HIGH
        elif has_suggestions:
            sev = Severity.MEDIUM
        else:
            sev = Severity.MEDIUM

        # Evidence作成
        evidence_list = []
        if result.get("introspection_enabled"):
            evidence_list.append(Evidence(
                request_method="POST",
                request_url=target_url,
                request_headers={"Content-Type": "application/json"},
                request_body='{"query": "INTROSPECTION_QUERY"}',
                response_status=200,
                response_headers={"Content-Type": "application/json"},
            ))

        if has_graphiql:
            evidence_list.append(Evidence(
                request_method="GET",
                request_url=target_url,
                request_headers={"Accept": "text/html"},
                request_body="",
                response_status=200,
                response_headers={"Content-Type": "text/html"},
            ))

        if has_suggestions:
            evidence_list.append(Evidence(
                request_method="POST",
                request_url=target_url,
                request_headers={"Content-Type": "application/json"},
                request_body='{"query": "{ thisFieldDoesNotExist12345 }"}',
                response_status=200,
            ))

        # PoC生成
        poc_html = self._generate_poc_html_safe(target_url, result)
        poc_request = f"POST {target_url} HTTP/1.1\nContent-Type: application/json\n\n{{\"query\": \"...\"}}"
        poc_response = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{...}"

        # 説明構築
        desc_parts = ["GraphQL endpoint has information disclosure vulnerabilities:"]

        if result.get("introspection_enabled"):
            desc_parts.append(
                f"- Introspection enabled ({result.get('queries_count', 0)} queries, "
                f"{result.get('mutations_count', 0)} mutations)"
            )

        if has_graphiql:
            desc_parts.append(
                "- GraphiQL Explorer UI accessible (allows interactive schema exploration)"
            )

        if has_suggestions:
            desc_parts.append(
                f"- Field suggestions enabled ({len(result.get('suggested_fields', []))} fields suggested)"
            )

        if is_large:
            desc_parts.append("- Large schema detected (potential DoS via complex queries)")

        if result.get("sensitive_fields"):
            desc_parts.append(f"- Sensitive fields: {', '.join(result['sensitive_fields'][:5])}")

        if result.get("attack_vectors"):
            desc_parts.append(f"- Attack vectors: {', '.join(result['attack_vectors'][:3])}")

        # Title構築
        title_parts = ["GraphQL"]
        if result.get("introspection_enabled"):
            title_parts.append("Introspection")
        if has_graphiql:
            title_parts.append("GraphiQL")
        if has_suggestions:
            title_parts.append("Field Suggestions")
        if has_sensitive:
            title_parts.append("Sensitive Data")

        findings.append(Finding(
            target_url=target_url,
            vuln_type=VulnType.GRAPHQL_INTROSPECTION,
            severity=sev,
            title=" ".join(title_parts) + " Enabled",
            description=" ".join(desc_parts),
            source_agent="SmartGraphQLHunter",
            confidence=0.95,
            tags=["graphql", "introspection", sev.value],
            evidence=evidence_list[0] if evidence_list else None,
            additional_info={
                "tested_params": [],
                "introspection_enabled": result.get("introspection_enabled", False),
                "graphiql_enabled": has_graphiql,
                "field_suggestions_enabled": has_suggestions,
                "is_large_schema": is_large,
                "sensitive_fields": result.get("sensitive_fields", []),
                "suggested_fields": result.get("suggested_fields", []),
                "mutations": result.get("mutations", []),
                "attack_vectors": result.get("attack_vectors", []),
                "queries_count": result.get("queries_count", 0),
                "mutations_count": result.get("mutations_count", 0),
                "evidence_count": len(evidence_list),
                "poc_html": poc_html,
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        ))

        return findings

    def _generate_poc_html_safe(self, target_url: str, result: dict) -> str:
        """PoC HTML生成（完全エスケープ）"""
        target_url_escaped = html.escape(target_url, quote=True)
        query_escaped = html.escape(INTROSPECTION_QUERY, quote=True)
        query_js_escaped = query_escaped.replace("\\", "\\\\").replace("'", "\\'")

        features = []
        if result.get("introspection_enabled"):
            features.append("Introspection")
        if result.get("graphiql_enabled"):
            features.append("GraphiQL")
        if result.get("field_suggestions_enabled"):
            features.append("Field Suggestions")

        features_text = html.escape(", ".join(features)) if features else "GraphQL Endpoint"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GraphQL PoC - {features_text}</title>
    <style>
        body {{ font-family: sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }}
        pre {{ background: #f5f5f5; padding: 1rem; overflow-x: auto; }}
        button {{ padding: 0.5rem 1rem; margin: 0.5rem 0; cursor: pointer; }}
        .success {{ color: green; }}
        .error {{ color: red; }}
    </style>
</head>
<body>
    <h1>GraphQL Information Disclosure PoC</h1>
    <p><strong>Target:</strong> <code>{target_url_escaped}</code></p>
    <p><strong>Features Detected:</strong> {features_text}</p>

    <h2>Test Introspection</h2>
    <button onclick="testIntrospection()">Send Introspection Query</button>
    <pre id="result">Click button to test...</pre>

    <h2>Test Field Suggestion</h2>
    <button onclick="testSuggestion()">Send Invalid Field Query</button>
    <pre id="suggestion-result">Click button to test...</pre>

    <script>
        const TARGET_URL = '{target_url_escaped}';
        const INTROSPECTION_QUERY = '{query_js_escaped}';

        async function testIntrospection() {{
            const resultEl = document.getElementById('result');
            resultEl.textContent = 'Loading...';

            try {{
                const response = await fetch(TARGET_URL, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ query: INTROSPECTION_QUERY }})
                }});

                const data = await response.json();
                resultEl.textContent = JSON.stringify(data, null, 2);
                resultEl.className = 'success';
            }} catch (e) {{
                resultEl.textContent = 'Error: ' + e.message;
                resultEl.className = 'error';
            }}
        }}

        async function testSuggestion() {{
            const resultEl = document.getElementById('suggestion-result');
            resultEl.textContent = 'Loading...';

            try {{
                const response = await fetch(TARGET_URL, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ query: '{{ thisFieldDoesNotExist12345 }}' }})
                }});

                const data = await response.json();
                resultEl.textContent = JSON.stringify(data, null, 2);
                resultEl.className = data.errors && data.errors[0].message.includes('did you mean') ? 'success' : '';
            }} catch (e) {{
                resultEl.textContent = 'Error: ' + e.message;
                resultEl.className = 'error';
            }}
        }}
    </script>
</body>
</html>"""
