---
task_id: SGK-2026-0061
doc_type: plan
doc_usage: implementation_plan
status: backlog
parent_task_id: null
related_docs: []
created_at: '2026-05-16'
updated_at: '2026-05-19'
---

# B-1: GraphQL Introspection 実装計画書（アップデート版）
**作成日**: 2026-05-16  
**適用仕様書**: /home/bbb/Documents/App/Shigoku/docs/standards/vulnerability_feature_implementation_spec.md  
**前提**: A-2 (CORS), A-3 (CRLF) 実装済み・教訓反映

---

## 概要

| 項目 | 内容 |
|-----|------|
| **機能** | GraphQL Introspection 有効性検出・スキーマ抽出・機密フィールド識別 |
| **推定時間** | 3〜4時間（L3/L4テスト・formatter対応含む） |
| **AI使用** | ❌ 不使用（決定論的実装） |
| **優先度** | 4（B-2 SSRFの前に実施） |

---

## 実装前必須確認（仕様書0章準拠）

### タスク B1-0: 事前確認

```bash
# 0.1 VulnTypeファイルパス確認
find src/ -name "finding.py" | head -5
grep -rn "class VulnType" src/

# 0.2 既存 GRAPHQL エントリ確認
grep -n "GRAPHQL" src/core/models/finding.py

# 0.3 ポート競合確認
grep -rn "FLASK_PORT\|start_server.*port\|run.*port" tests/helpers/ | grep -E "1555[0-9]"
# → 15558 が未使用であることを確認
```

---

## 実装タスク

### タスク B1-1: `GraphQLAnalyzer` 実装強化

**ファイル**: `src/core/attack/graphql_analyzer.py`

#### 変更内容

1. `__init__` に `auth_headers` 追加（仕様書2.1 Scanner Core準拠）
2. `_try_introspection()` をhttpx実装（プレースホルダー置き換え）
3. `analyze_async()` 非同期対応完成
4. **GETベースIntrospectionフォールバック追加**（Bug Bounty視点）
5. **Content-Typeバイパス確認追加**（Bug Bounty視点）

```python
import httpx
import asyncio
from urllib.parse import urlencode

class GraphQLAnalyzer:
    TIMEOUT = 15
    
    def __init__(self, auth_headers: Optional[Dict] = None):
        self.auth_headers = auth_headers or {}
        self.results: List[GraphQLAnalysisResult] = []
    
    def _try_introspection(self, endpoint: str) -> Optional[Dict]:
        """POSTベースIntrospection試行"""
        headers = {
            **self.auth_headers,
            "Content-Type": "application/json",
        }
        payload = {"query": INTROSPECTION_QUERY}
        
        try:
            with httpx.Client(timeout=self.TIMEOUT, follow_redirects=False) as client:
                response = client.post(endpoint, json=payload, headers=headers)
        except httpx.TimeoutException:
            logger.warning("GraphQL introspection timeout on %s", endpoint)
            return None
        except httpx.ConnectError as e:
            logger.warning("GraphQL connection error: %s", e)
            return None
        except Exception as exc:
            logger.warning("GraphQL introspection request failed: %s", exc)
            return None
        
        if not response.is_success:
            return None
        
        try:
            data = response.json()
        except json.JSONDecodeError:
            return None
        
        schema = data.get("data", {}).get("__schema")
        if schema:
            return schema
        
        # エラーレスポンスも記録
        errors = data.get("errors", [])
        if errors:
            logger.info("GraphQL introspection disabled or errored: %s", errors[:1])
        return None
    
    def _try_introspection_get(self, endpoint: str) -> Optional[Dict]:
        """GETベースIntrospection試行（一部エンドポイントで有効）"""
        headers = {**self.auth_headers}
        query_param = urlencode({"query": INTROSPECTION_QUERY})
        url = f"{endpoint}?{query_param}"
        
        try:
            with httpx.Client(timeout=self.TIMEOUT, follow_redirects=False) as client:
                response = client.get(url, headers=headers)
        except Exception:
            return None
        
        if not response.is_success:
            return None
        
        try:
            data = response.json()
        except Exception:
            return None
        
        return data.get("data", {}).get("__schema")
    
    def _try_content_type_bypass(self, endpoint: str) -> Optional[Dict]:
        """Content-Typeバイパス試行"""
        headers = {
            **self.auth_headers,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        payload = urlencode({"query": INTROSPECTION_QUERY})
        
        try:
            with httpx.Client(timeout=self.TIMEOUT, follow_redirects=False) as client:
                response = client.post(endpoint, content=payload, headers=headers)
        except Exception:
            return None
        
        if not response.is_success:
            return None
        
        try:
            data = response.json()
        except Exception:
            return None
        
        return data.get("data", {}).get("__schema")
    
    def analyze(self, endpoint: str) -> GraphQLAnalysisResult:
        """複数手法でIntrospection試行"""
        result = GraphQLAnalysisResult()
        
        # 複数手法で試行
        schema_data = (
            self._try_introspection(endpoint)
            or self._try_introspection_get(endpoint)
            or self._try_content_type_bypass(endpoint)
        )
        
        if schema_data:
            result.introspection_enabled = True
            result.schema = self._parse_schema(schema_data)
            result.queries = self._extract_operations(result.schema, "Query")
            result.mutations = self._extract_operations(result.schema, "Mutation")
            result.sensitive_fields = self._find_sensitive_fields(result.schema)
            result.attack_vectors = self._suggest_attack_vectors(result)
        
        self.results.append(result)
        return result
    
    async def analyze_async(self, endpoint: str,
                             auth_headers: Optional[Dict] = None) -> GraphQLAnalysisResult:
        """非同期分析エントリポイント"""
        if auth_headers:
            self.auth_headers = auth_headers
        return await asyncio.to_thread(self.analyze, endpoint)
```

#### 合格基準
- POST/GET/Content-TypeバイパスすべてでIntrospection検出
- `auth_headers` がCookieヘッダーに含まれる
- `httpx.TimeoutException` / `ConnectError` を区別してハンドリング

---

### タスク B1-2: `SmartGraphQLHunter` 新規作成

**新規ファイル**: `src/core/agents/swarm/injection/smart_graphql.py`

```python
import json
from typing import Dict, List, Any, Optional
from src.core.agents.swarm.injection.base import Specialist
from src.core.models.finding import Finding, Severity, VulnType, Evidence
from src.core.attack.graphql_analyzer import GraphQLAnalyzer, GraphQLAnalysisResult

class SmartGraphQLHunter(Specialist):
    name = "SmartGraphQLHunter"
    description = "GraphQL introspection and schema exposure detector"
    timeout_seconds = 120
    is_aggressive = False
    
    SENSITIVE_KEYWORDS = [
        "password", "secret", "token", "key", "auth",
        "credential", "private", "ssn", "credit",
        "admin", "role", "permission", "internal",
    ]
    
    async def run_as_tool(self, url: str, params: Dict = None, **_kwargs) -> Dict:
        """Tool execution entry point"""
        _auth = (params or {}).get("_auth", {})
        auth_headers = dict(_auth.get("auth_headers", {}))
        cookies = _auth.get("cookies", "")
        if cookies:
            auth_headers["Cookie"] = cookies
        
        analyzer = GraphQLAnalyzer(auth_headers=auth_headers)
        try:
            result = await analyzer.analyze_async(url)
        except Exception as exc:
            logger.error("GraphQLAnalyzer error: %s", exc)
            return {
                "vulnerable": False,
                "findings_count": 0,
                "tested_params": [],
                "introspection_enabled": False,
                "sensitive_fields": [],
                "mutations": [],
                "attack_vectors": [],
                "error": str(exc),
            }
        
        has_sensitive = bool(result.sensitive_fields)
        
        self.last_results = [result]
        return {
            "vulnerable": result.introspection_enabled,
            "findings_count": 1 if result.introspection_enabled else 0,
            "tested_params": [],  # GraphQLはパラメータベースでない
            "introspection_enabled": result.introspection_enabled,
            "sensitive_fields": result.sensitive_fields,
            "mutations": result.mutations,
            "attack_vectors": result.attack_vectors,
            "queries_count": len(result.queries),
            "mutations_count": len(result.mutations),
            "has_sensitive_fields": has_sensitive,
        }
    
    async def execute(self, task, quick_mode: bool = False) -> List[Finding]:
        """Specialist execution entry point"""
        result = await self.run_as_tool(task.target, task.params or {})
        return self._convert_to_findings(result, task.target)
    
    def _convert_to_findings(self, result: dict, target_url: str) -> List[Finding]:
        """Convert analysis result to Finding objects"""
        findings = []
        
        if not result.get("introspection_enabled"):
            return findings
        
        # Severity決定
        has_sensitive = result.get("has_sensitive_fields", False)
        sev = Severity.HIGH if has_sensitive else Severity.MEDIUM
        
        # Evidenceオブジェクト作成（仕様書2.4必須）
        evidence = Evidence(
            request_method="POST",
            request_url=target_url,
            request_headers={"Content-Type": "application/json"},
            request_body=json.dumps({"query": "INTROSPECTION_QUERY"}),
            response_status=200,
            response_headers={"Content-Type": "application/json"},
        )
        
        # PoC生成
        poc_html = self._generate_poc_html(target_url, result)
        poc_request = f"POST {target_url} HTTP/1.1\nContent-Type: application/json\n\n{{\"query\": \"INTROSPECTION_QUERY\"}}"
        poc_response = f"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{{\"data\": {{\"__schema\": {{...}}}}}}"
        
        # 説明構築
        desc_parts = [
            "GraphQL Introspection is enabled on this endpoint.",
            f"Schema exposes {result.get('queries_count', 0)} queries and {result.get('mutations_count', 0)} mutations.",
        ]
        
        if result.get("sensitive_fields"):
            desc_parts.append(f"Sensitive fields detected: {', '.join(result['sensitive_fields'][:5])}")
        
        if result.get("attack_vectors"):
            desc_parts.append(f"Attack vectors: {', '.join(result['attack_vectors'][:3])}")
        
        findings.append(Finding(
            target_url=target_url,
            vuln_type=VulnType.GRAPHQL_INTROSPECTION,
            severity=sev,
            title=f"GraphQL Introspection Enabled{' - Sensitive Data Exposed' if has_sensitive else ''}",
            description=" ".join(desc_parts),
            source_agent="SmartGraphQLHunter",
            confidence=0.95,
            tags=["graphql", "introspection", sev.value],
            evidence=evidence,  # ← 仕様書2.4必須
            additional_info={
                "tested_params": [],
                "introspection_enabled": True,
                "sensitive_fields": result.get("sensitive_fields", []),
                "mutations": result.get("mutations", []),
                "attack_vectors": result.get("attack_vectors", []),
                "queries_count": result.get("queries_count", 0),
                "mutations_count": result.get("mutations_count", 0),
                "poc_html": poc_html,  # ← 必須
                "poc_request": poc_request,  # ← A-2発覚・必須
                "poc_response": poc_response,  # ← A-2発覚・必須
            },
        ))
        
        return findings
    
    def _generate_poc_html(self, target_url: str, result: dict) -> str:
        """Generate PoC HTML for manual verification"""
        introspection_query_escaped = INTROSPECTION_QUERY.replace('"', '&quot;').replace('\n', '\\n')
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>GraphQL Introspection PoC</title>
</head>
<body>
    <h2>GraphQL Introspection PoC</h2>
    <p>Target: {target_url}</p>
    <pre id="result"></pre>
    <script>
        const query = `{introspection_query_escaped}`;
        fetch("{target_url}", {{
            method: "POST",
            headers: {{
                "Content-Type": "application/json"
            }},
            body: JSON.stringify({{query: query}})
        }})
        .then(r => r.json())
        .then(data => {{
            document.getElementById("result").textContent = JSON.stringify(data, null, 2);
        }})
        .catch(e => {{
            document.getElementById("result").textContent = "Error: " + e;
        }});
    </script>
</body>
</html>"""
```

#### 合格基準
- `Evidence` オブジェクトが設定される
- `additional_info` に `poc_request`/`poc_response`/`poc_html` が存在
- Sensitive fieldsあり → HIGH、なし → MEDIUM

---

### タスク B1-3: `tagging_rules.yaml` に GraphQL ルール追加

**ファイル**: `config/tagging_rules.yaml`

```yaml
  # GraphQL: パスベース検出
  - name: graphql_path_hint
    tag: graphql_candidate
    match_on: path
    pattern: "(graphql|gql|graph|api/graph)"

  # GraphQL: クエリパラメータ検出
  - name: graphql_param_hint
    tag: graphql_candidate
    match_on: query
    pattern: "(^|[?&])(query|mutation|operationName|variables)="
    param_extract: 2

  # GraphQL: Content-Type検出（レスポンスヘッダー）
  - name: graphql_content_type_hint
    tag: graphql_candidate
    match_on: response_headers
    header_name: "Content-Type"
    pattern: "application/graphql"
```

---

### タスク B1-4: InjectionManager 配線（8箇所）

**ファイル**: `src/core/agents/swarm/injection/manager.py`

```python
# 1. PER_URL_TIMEOUT_BY_TYPE
PER_URL_TIMEOUT_BY_TYPE: Dict[str, int] = {
    "graphql": 120,
    # ... 既存
}

# 2. _classify_url()
@staticmethod
def _classify_url(url: str, category: str = "") -> str:
    path = url.lower()
    category_hint = category.lower().strip()
    
    if category_hint == "graphql_candidate":
        return "graphql"
    
    # パスヒューリスティック（既存より前に配置）
    if "/graphql" in path or "/gql" in path:
        return "graphql"
    
    # ... 既存ロジック

# 3. _build_unknown_hypotheses() — 重要！ A-3発覚で必須化
def _build_unknown_hypotheses(self, url: str, all_param_keys: set) -> tuple:
    hypotheses = []
    signals = []
    
    path = url.lower()
    
    # GraphQLキーワードセット
    graphql_keys = {"query", "mutation", "operationname", "variables"}
    
    # パスヒューリスティック OR パラメータキーセット交差
    if any(kw in path for kw in ["graphql", "gql", "graph"]) or (all_param_keys & graphql_keys):
        hypotheses.append("graphql")
        signals.append("graphql_signal")
    
    # specialist_map に追加（必須。ないと無視される）
    specialist_map = {
        "graphql": "graphql",  # ← 必須追加
        # ... 既存
    }
    
    return hypotheses, signals, specialist_map

# 4. _initialize_specialists()
def _initialize_specialists(self):
    # ... 既存
    try:
        from src.core.agents.swarm.injection.smart_graphql import SmartGraphQLHunter
        self.specialists["graphql"] = SmartGraphQLHunter(config=self.config)
    except ImportError:
        logger.warning("SmartGraphQLHunter not available")

# 5. _register_manager_tools()
def _register_manager_tools(self):
    if "graphql" in self.specialists:
        self.register_tool(
            "graphql_scan",
            self.run_graphql_hunter,
            "GraphQL Introspection有効性を検出します。"
        )

# 6. run_graphql_hunter() — current_contextガード必須（A-2発覚）
async def run_graphql_hunter(self, url: str, params: dict = None,
                              quick_mode: bool = False, **_kwargs) -> dict:
    if "graphql" not in self.specialists:
        return {"error": "GraphQL Specialist not available", "findings_count": 0}
    
    logger.info("[%s] Delegating GraphQL check to SmartGraphQLHunter", self.name)
    
    # ← 必須: current_context未初期化ガード（A-2発覚）
    if not isinstance(self.current_context, dict):
        self.current_context = {}
    self.current_context.setdefault("findings", [])
    self.current_context.setdefault("auth_headers", {})
    self.current_context.setdefault("params", {})
    
    effective_params = self._normalize_tool_supplied_params(params, _kwargs)
    
    cookies_str = _kwargs.get("cookies") or self.current_context.get("params", {}).get("cookies", "")
    effective_params["_auth"] = {
        "auth_headers": _kwargs.get("auth_headers", self.current_context.get("auth_headers", {})),
        "cookies": cookies_str,
    }
    
    # Task作成 → execute呼び出し
    from src.core.agents.base import Task
    target_task = Task(
        id=f"inj_graphql_{id(url)}",
        name="GraphQL Introspection Check",
        target=url,
        params=effective_params,
        tags=["graphql"],
    )
    findings = await self.specialists["graphql"].execute(target_task, quick_mode=quick_mode) or []
    self.current_context["findings"].extend(findings)
    
    return self._format_findings_result(findings)

# 7. _run_unknown_hypothesis_scans()
async def _run_unknown_hypothesis_scans(self, ...):
    # ... 既存
    elif specialist == "graphql":
        result = await self.run_graphql_hunter(url=url, params=base_params, quick_mode=quick_mode)
        unknown_results.append(result)

# 8. _resolve_risk_force_allowlist()
def _resolve_risk_force_allowlist(self, vuln_type: str) -> bool:
    allow = {"sqli", "cmd_ssrf", "lfi", "csrf", "api", "redirect", "ssti", "cors", "crlf", "graphql"}
    return vuln_type in allow
```

---

### タスク B1-5: ReconPipeline 統合

**ファイル**: `src/recon/pipeline.py`

```python
# task_mapping に追加
task_mapping: Dict[str, Dict[str, Any]] = {
    "graphql_candidate": {
        "agent_type": "InjectionManagerAgent",
        "priority": 72,
        "vuln_type": "graphql",
        "description": "GraphQL Introspection有効確認",
    },
    # ... 既存
}

# _map_tagged_category_to_tags() に追加
def _map_tagged_category_to_tags(self, category: str) -> List[str]:
    mapping = {
        "graphql_candidate": ["graphql_candidate"],
        # ... 既存
    }
```

---

### タスク B1-6: Haddix Formatter 対応

**ファイル**: `src/reporting/haddix_formatter.py`

```python
def _cia_impact_assessment(self, vuln_type: str) -> Dict[str, str]:
    assessments = {
        # ... 既存
        VulnType.GRAPHQL_INTROSPECTION: {
            "confidentiality": "High - Full schema exposure enables targeted attacks",
            "integrity": "Medium - Mutation analysis enables data manipulation attacks",
            "availability": "Low - No direct availability impact",
            "overall": "High",
        },
    }
    return assessments.get(vuln_type, {...})

def _remediation(self, vuln_type: str) -> str:
    remediations = {
        # ... 既存
        VulnType.GRAPHQL_INTROSPECTION: (
            "Disable introspection in production environments. "
            "Apollo Server: introspection: false. "
            "Strawberry: schema = strawberry.Schema(..., disable_introspection=True). "
            "Consider implementing query depth limiting and complexity analysis."
        ),
    }
    return remediations.get(vuln_type, "Review and remediate.")
```

---

### タスク B1-7: テスト（L1〜L4 4層構成）

**新規ファイル**: `tests/core/agents/swarm/injection/test_smart_graphql.py`  
**新規ファイル**: `tests/core/agents/swarm/injection/test_graphql_classification.py`  
**新規ファイル**: `tests/core/agents/swarm/injection/test_graphql_pipeline.py`  
**新規ファイル**: `tests/helpers/graphql_flask_target.py`

#### L1 ユニットテスト（9件）

```python
# tests/core/agents/swarm/injection/test_smart_graphql.py

async def test_execute_returns_finding_when_introspection_enabled()
async def test_execute_returns_empty_when_introspection_disabled()
async def test_finding_severity_high_with_sensitive_fields()
async def test_finding_severity_medium_without_sensitive_fields()
async def test_finding_has_schema_info_in_additional_info()
async def test_run_as_tool_initializes_result_shape()
async def test_auth_headers_forwarded_to_analyzer()
async def test_tested_params_excludes_control_params()  # ← 追加
async def test_finding_has_evidence_object()  # ← 追加
async def test_finding_has_poc_request_response()  # ← 追加
```

#### L2 統合テスト（3件）

```python
# tests/helpers/graphql_flask_target.py
from flask import Flask, request, jsonify

FLASK_PORT = 15558

SCHEMA_RESPONSE = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": None,
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "Query",
                    "fields": [
                        {"name": "getUser", "args": [{"name": "id"}]},
                        {"name": "getPassword", "description": "Sensitive field"},
                    ],
                }
            ],
        }
    }
}

def create_app() -> Flask:
    app = Flask(__name__)
    
    @app.route("/graphql", methods=["POST", "GET"])
    def graphql_endpoint():
        if request.method == "POST":
            return jsonify(SCHEMA_RESPONSE)
        # GETベースもサポート
        if "query" in request.args:
            return jsonify(SCHEMA_RESPONSE)
        return jsonify({"errors": [{"message": "No query"}]}), 400
    
    @app.route("/graphql-disabled", methods=["POST"])
    def graphql_disabled():
        return jsonify({"errors": [{"message": "Introspection disabled"}]}), 200
    
    @app.route("/safe", methods=["POST"])
    def safe():
        return jsonify({"message": "Not GraphQL"})
    
    return app

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else FLASK_PORT
    print(f"Starting GraphQL Flask target on http://127.0.0.1:{port}")
    create_app().run(host="127.0.0.1", port=port, use_reloader=False)
```

```python
# L2 テスト
@pytest.mark.integration
def test_graphql_scanner_detects_post_introspection(graphql_server)
def test_graphql_scanner_detects_get_introspection(graphql_server)  # ← GET追加
def test_graphql_scanner_no_false_positive_on_disabled(graphql_server)
```

#### L3 分類テスト（12件）

```python
# tests/core/agents/swarm/injection/test_graphql_classification.py

class TestClassifyUrlGraphQL:
    def test_graphql_candidate_tag_returns_graphql()
    def test_graphql_candidate_beats_competing_category()
    def test_competing_category_unaffected()
    def test_graphql_path_hint_classification()

class TestBuildUnknownHypothesesGraphQL:
    def test_graphql_signal_from_path_hint()  # ← 重要！
    def test_graphql_specialist_selected_from_path()
    def test_graphql_signal_from_param()  # query= mutation=
    def test_graphql_specialist_not_selected_when_not_registered()
    def test_no_graphql_signal_for_unrelated_path()
    def test_graphql_does_not_suppress_other_hypotheses()

class TestGraphQLSpecialistRegistration:
    def test_graphql_specialist_registered_on_init()
    def test_graphql_tool_registered()
    def test_per_url_timeout_has_graphql()
```

#### L4 パイプラインテスト（10件）

```python
# tests/core/agents/swarm/injection/test_graphql_pipeline.py

class TestRunGraphQLHunterStoresFindings:
    async def test_findings_stored_in_current_context()
    async def test_no_findings_when_not_vulnerable()
    async def test_finding_has_correct_fields()
    async def test_result_shape_has_required_keys()
    async def test_current_context_guard_no_keyerror()  # ← A-2発覚

class TestDispatchGraphQLPhase1:
    async def test_dispatch_graphql_candidate_calls_run_graphql_hunter()
    async def test_dispatch_stores_graphql_findings_in_context()
    async def test_unknown_category_triggers_graphql_scan()  # ← _build_unknown_hypotheses

class TestHaddixFormatterGraphQL:
    def test_add_finding_from_dict_accepted()
    def test_graphql_finding_appears_in_markdown()
    def test_graphql_vuln_type_in_markdown()
    def test_graphql_cia_impact_in_markdown()
    def test_graphql_remediation_in_markdown()
    def test_poc_request_in_markdown()
```

---

## 完了チェックリスト（Definition of Done）

| # | 条件 | 確認方法 |
|---|-----|---------|
| 1 | L1〜L4 全テスト GREEN | `.venv/bin/pytest tests/core/agents/swarm/injection/test_smart_graphql.py tests/core/agents/swarm/injection/test_graphql_classification.py tests/core/agents/swarm/injection/test_graphql_pipeline.py -v` |
| 2 | injection スイート回帰なし | `.venv/bin/pytest tests/core/agents/swarm/injection/ -q` |
| 3 | Finding → context["findings"] 格納 | L4 `test_findings_stored_in_current_context` |
| 4 | dispatch経路でspecialist呼ばれる | L4 `test_dispatch_graphql_candidate_calls_run_graphql_hunter` |
| 5 | unknownカテゴリでも検出可能 | L4 `test_unknown_category_triggers_graphql_scan` |
| 6 | Haddixレポートに固有文言出力 | L4 `test_graphql_cia_impact_in_markdown` |
| 7 | GET/POST/Content-Typeバイパスすべて検出 | L2 `test_graphql_scanner_detects_get_introspection` |
| 8 | Evidence/poc_request/poc_response設定 | L1 `test_finding_has_evidence_object` |
| 9 | `__main__`ブロックあり手動起動可 | `python tests/helpers/graphql_flask_target.py` |

---

*計画書バージョン: 2.0（A-2/A-3実装教訓反映・Bug Bounty視点強化）*
