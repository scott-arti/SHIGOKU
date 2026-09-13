"""
SmartGraphQLHunter - GraphQL Introspection 検出スペシャリスト

機能:
- GraphQL Introspection有効性検出
- GraphiQL Explorer UI検出
- Field Suggestions有効性検出
- Evidence・PoC生成
"""

import html
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Specialist
from src.core.models.finding import Finding, Severity, VulnType, Evidence
from src.core.attack.graphql_analyzer import GraphQLAnalyzer, INTROSPECTION_QUERY

logger = logging.getLogger(__name__)

# SGK-2026-0484: GraphQL 認可欠陥（認証なしで機微データ取得）検出用。
# 機微スカラーフィールド名（値ではなくキー名）にマッチ。製品非依存
# （フィールド名/エンドポイントはハードコードせずスキーマ駆動で発見）。
_GQL_SENSITIVE_FIELD_RE = re.compile(
    r"pass|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|apikey",
    re.I,
)
# built-in scalar leaf types（object でなくスカラー扱い）
_GQL_SCALAR_LEAF = {"String", "Int", "Boolean", "ID", "Float"}
# exposure 応答本文の保存上限（値 redact 済み）
_GQL_BODY_CAP = 4000
# スキーマ取得用の軽量イントロスペクション（type/field/arg の kind まで）
_GQL_SCHEMA_QUERY = (
    "{__schema{queryType{name} types{name kind "
    "fields{name args{name type{kind ofType{kind}}} "
    "type{name kind ofType{name kind ofType{name kind}}}}}}}"
)


def _gql_unwrap_type_name(tp: Optional[dict]) -> Optional[str]:
    """NON_NULL/LIST ラッパを剥がして基底型名を返す。"""
    seen = 0
    while isinstance(tp, dict) and tp.get("ofType") and seen < 10:
        tp = tp["ofType"]
        seen += 1
    return tp.get("name") if isinstance(tp, dict) else None


def _gql_arg_required(arg: dict) -> bool:
    """引数がデフォルトなしの NON_NULL（必須）か。"""
    tp = arg.get("type") if isinstance(arg, dict) else None
    return isinstance(tp, dict) and tp.get("kind") == "NON_NULL"


def _redact_graphql_body(node: Any) -> Any:
    """応答 JSON を再帰し、機微キー名の文字列値を ``<redacted len=N>`` に
    置換（キー・構造は保持）。値は不要（照合はキー側で行う）。"""
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if isinstance(value, str) and _GQL_SENSITIVE_FIELD_RE.search(str(key)):
                out[key] = f"<redacted len={len(value)}>"
            else:
                out[key] = _redact_graphql_body(value)
        return out
    if isinstance(node, list):
        return [_redact_graphql_body(x) for x in node]
    return node


def _collect_sensitive_keys(node: Any, out: List[str]) -> None:
    """応答 JSON に実在する「機微キー名かつ非空値」のキー名を収集（順序維持）。"""
    if isinstance(node, dict):
        for key, value in node.items():
            if (
                _GQL_SENSITIVE_FIELD_RE.search(str(key))
                and value not in (None, "", [], {})
                and key not in out
            ):
                out.append(key)
            _collect_sensitive_keys(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_sensitive_keys(item, out)


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
        findings = self._convert_to_findings(result, task.target)
        # SGK-2026-0484: 認証なしで機微データが取得できる認可欠陥を実クエリで
        # 検証し、実害 Finding を追加する（情報開示の GRAPHQL_INTROSPECTION
        # Finding は非回帰で温存）。probe は自前でイントロスペクションを行い
        # スキーマ解析不能/機微データ非取得なら None（fail-closed 自己ガード）
        # のため、run_as_tool の結果に依存せず常時試行する（本 specialist は
        # GraphQL エンドポイントにのみディスパッチされる）。
        try:
            probe = await self._probe_authz_exposure(task.target)
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug(
                "GraphQL authz exposure probe error on %s: %s", task.target, exc
            )
            probe = None
        if probe is not None:
            findings.append(self._build_exposure_finding(task.target, probe))
        return findings

    async def _gql_post(self, endpoint: str, query: str) -> Tuple[int, str]:
        """POST a GraphQL query UNAUTHENTICATED via an injected client
        (``self._client``; E2E/test seam, mirrors the other specialists) or a
        fresh AsyncNetworkClient. No auth headers are sent — the test is
        whether sensitive data is served WITHOUT authorization. Returns
        ``(status, body_text)``."""
        headers = {"Content-Type": "application/json"}
        data = json.dumps({"query": query})
        injected = getattr(self, "_client", None)
        if injected is not None:
            resp = await injected.request(
                "POST", endpoint, data=data, headers=headers, use_proxy=True
            )
        else:
            from src.core.infra.network_client import AsyncNetworkClient
            async with AsyncNetworkClient() as client:
                resp = await client.request(
                    "POST", endpoint, data=data, headers=headers, use_proxy=True
                )
        status = int(getattr(resp, "status", 0) or 0)
        body = getattr(resp, "body", None)
        if body is None:
            body = getattr(resp, "text", "") or ""
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        return status, str(body)

    async def _probe_authz_exposure(self, endpoint: str) -> Optional[dict]:
        """スキーマ駆動で「機微スカラーフィールドを持つ型を返す root Query
        フィールド」を特定し、認証なしで実クエリを実行して機微データが返るか
        検証する。返れば exposure 記述子、そうでなければ None（fail-closed）。
        製品固有のフィールド名/エンドポイントはハードコードしない。"""
        status, body = await self._gql_post(endpoint, _GQL_SCHEMA_QUERY)
        if status != 200 or not body:
            return None
        try:
            schema = json.loads(body)["data"]["__schema"]
        except (ValueError, KeyError, TypeError):
            return None
        crafted = self._craft_sensitive_query(schema)
        if crafted is None:
            return None
        root_field, query = crafted
        status2, body2 = await self._gql_post(endpoint, query)
        if status2 != 200 or not body2:
            return None
        try:
            data = json.loads(body2)
        except (ValueError, TypeError):
            return None
        payload = data.get("data") if isinstance(data, dict) else None
        if not isinstance(payload, dict) or payload.get(root_field) in (None, [], {}):
            return None
        matched: List[str] = []
        _collect_sensitive_keys(payload, matched)
        if not matched:
            return None
        redacted = _redact_graphql_body(data)
        served_body = json.dumps(redacted, ensure_ascii=False)[:_GQL_BODY_CAP]
        return {
            "endpoint": endpoint,
            "query": query,
            "root_field": root_field,
            "response_status": status2,
            "matched_fields": matched,
            "served_body": served_body,
        }

    def _craft_sensitive_query(self, schema: dict) -> Optional[Tuple[str, str]]:
        """スキーマから機微スカラーフィールドを持つ root Query フィールドを
        探し、最小クエリ ``{ <root> { <scalars...> } }`` を組み立てる。
        引数必須の root フィールドは避ける（無効クエリを作らない）。"""
        qt = (schema.get("queryType") or {}).get("name")
        types = {t.get("name"): t for t in schema.get("types", []) if t.get("name")}
        root = types.get(qt)
        if not isinstance(root, dict):
            return None

        def scalar_fields(objname: str) -> List[str]:
            t = types.get(objname) or {}
            names: List[str] = []
            for f in (t.get("fields") or []):
                rn = _gql_unwrap_type_name(f.get("type"))
                rt = types.get(rn)
                is_scalar = (
                    rn in _GQL_SCALAR_LEAF
                    or (isinstance(rt, dict) and rt.get("kind") == "SCALAR")
                    or rt is None
                )
                if is_scalar and not any(
                    _gql_arg_required(a) for a in (f.get("args") or [])
                ):
                    names.append(f["name"])
            return names

        for f in (root.get("fields") or []):
            if any(_gql_arg_required(a) for a in (f.get("args") or [])):
                continue
            rn = _gql_unwrap_type_name(f.get("type"))
            if not rn or rn not in types:
                continue
            names = scalar_fields(rn)
            if not any(_GQL_SENSITIVE_FIELD_RE.search(n) for n in names):
                continue
            sel = list(dict.fromkeys((["id"] if "id" in names else []) + names))
            if not sel:
                continue
            return f["name"], "{%s{%s}}" % (f["name"], " ".join(sel))
        return None

    def _build_exposure_finding(self, endpoint: str, probe: dict) -> Finding:
        """認証なしで機微データが返る GraphQL 認可欠陥の実害 Finding を構築。
        Evidence/PoC には値 redact 済みの応答のみ格納（秘密値は非永続）。"""
        query = probe["query"]
        served_body = probe["served_body"]
        matched = probe["matched_fields"]
        status = probe["response_status"]
        request_body = json.dumps({"query": query})
        poc_request = (
            f"POST {endpoint} HTTP/1.1\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            f"{request_body}"
        )
        poc_response = (
            f"HTTP/1.1 {status} OK\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            f"{served_body}"
        )
        matched_disp = ", ".join(matched[:8])
        impact = (
            "認証なしの単一 GraphQL クエリが、認可ゲート付きの機微データ"
            f"（フィールド: {matched_disp}）を返した。攻撃者は無認証で資格情報等の"
            "機微情報を列挙・取得できる（GraphQL 認可欠陥／過剰取得）。"
        )
        evidence = Evidence(
            request_method="POST",
            request_url=endpoint,
            request_headers={"Content-Type": "application/json"},
            request_body=request_body,
            response_status=status,
            response_headers={"Content-Type": "application/json"},
            response_body=served_body,
        )
        return Finding(
            target_url=endpoint,
            vuln_type=VulnType.GRAPHQL_AUTHZ_EXPOSURE,
            severity=Severity.CRITICAL,
            title="GraphQL Broken Authorization: Unauthenticated Sensitive Data Access",
            description=(
                "An unauthenticated GraphQL query returned authorization-gated "
                f"sensitive data (fields: {matched_disp})."
            ),
            source_agent="SmartGraphQLHunter",
            confidence=0.95,
            tags=[
                "graphql",
                "broken_access_control",
                "graphql_sensitive_exposed",
                Severity.CRITICAL.value,
            ],
            evidence=evidence,
            impact=impact,
            reproduction_steps=[
                f"認証情報を付けずに次の GraphQL クエリを POST する: {query}",
                f"HTTP {status} の応答本文に機微フィールド（{matched_disp}）が"
                "含まれることを確認する。",
            ],
            additional_info={
                "graphql_exposure_evidence": {
                    "endpoint": endpoint,
                    "query": query,
                    "response_status": status,
                    "matched_fields": matched,
                    "served_body": served_body,
                },
                "graphql_bola_replay": {
                    "method": "POST",
                    "url": endpoint,
                    "body": {"query": query},
                    "reflect_fields": matched,
                },
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )

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
