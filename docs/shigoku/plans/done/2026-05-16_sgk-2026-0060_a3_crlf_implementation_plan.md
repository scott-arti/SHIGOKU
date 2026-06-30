---
task_id: SGK-2026-0060
doc_type: plan
status: backlog
parent_task_id: null
related_docs: []
created_at: '2026-05-16'
updated_at: '2026-06-24'
---

# A-3: CRLF 実実装 計画書

**作成日**: 2026-05-16
**最終更新**: 2026-05-16（レビュー指摘 14件反映）
**前提**: A-2 (CORS) 完了済み
**推定時間**: 〜3〜4時間（http.client 移行 + 接続管理デバッグ込み）
**参照**: `docs/standards/vulnerability_feature_implementation_spec.md`, `docs/plans/2026-05-15_a2_b2_docs/shigoku/plans/file_upload_implementation_plan_legacy.md`

---

## 概要

`CRLFTester._test_payload()` が `return None` のプレースホルダーのままになっている。
~~`payloads`, `_is_vulnerable()` は完成済みで再利用可能。~~ → **`_is_vulnerable()` に重大バグあり（要修正）**
InjectionManager への接続経路なし、SmartCRLFHunter 未作成。

### このスキャナーはAIを使わない

`SmartCRLFHunter` は `is_aggressive = False`、LLM呼び出しなし。`CRLFTester` は決定論的なヘッダー検出のみ。
`get_summary_for_ai()` は既存メソッドだが実行パスから呼ばれておらず今回の実装でも不使用（削除候補）。

### スコープ外（明示）

- HTTP/2 接続でのCRLF（プロトコル仕様上無効）
- 双方向ヘッダーインジェクション（リクエストスマグリングとの境界）
- POST body経由のCRLF注入（v1では対象外、Flaskターゲットに `/post` エンドポイントのみ追加して将来拡張に備える）
- `X-Forwarded-Host` / `Host` ヘッダー経由のリクエストヘッダーインジェクション（パスワードリセットハイジャック系）

---

## レビューで発覚した修正事項（8件）

| # | 箇所 | 問題 | 対処 |
|---|---|---|---|
| **B1** | A3-1 `_is_vulnerable()` | `Location:` / `Content-Type:` / `Link:` 注入を見逃す。`X-Injected` と `Set-Cookie:shigoku` の2パターンのみ | **`Location`/`Content-Type`/`Link` ヘッダー検出を追加** |
| **B2** | A3-1 `_test_payload()` | httpx は httpcore レイヤーで必ず `\r\n` をサニタイズする。フォールバックを「テスト後」条件にしていたが最初から `http.client` 主実装にする必要がある | **`http.client` を主実装** |
| **B3** | A3-1 `__init__` | 既存 `CRLFTester.__init__(self)` が引数なし。`auth_headers` 追加は破壊的変更の可能性。`create_crlf_tester()` が `src/core/attack/__init__.py` で export されている | **デフォルト引数 `auth_headers=None` で非破壊的に変更** |
| **B4** | A3-2 `run_as_tool()` | `tested_params` が空の時に early return していた。CRLFはパラメータがないエンドポイントでも試行すべき | **`FALLBACK_PARAMS` にフォールバックしてスキャン継続** |
| **B5** | A3-3 タグ付け | `Set-Cookie` 注入やレスポンス分割系の `lang`/`charset`/`filename` 等のパラメータが未カバー | **`crlf_response_splitting_param` ルール追加（3ルール体制）** |
| **B6** | A3-4 `_classify_url()` | `crlf_candidate` の評価が `redirect_param` の後になっており OpenRedirectSpecialist に食われる | **`redirect_param` チェックの直前に `crlf_candidate` 評価を配置** |
| **B7** | A3-4 `_build_unknown_hypotheses()` | `crlf` 仮説と `specialist_map["crlf"]` エントリが未記載。`unknown` 分類URLでCRLFが永遠に試行されない | **`crlf` 仮説生成 + `specialist_map` エントリを追加** |
| **B8** | A3-2 auth_headers 二重管理 | `CRLFTester(auth_headers=...)` とインスタンス設定しつつ `scan_async` にも渡す設計が混乱を招く | **`__init__` 一本化。`scan_async` の `auth_headers` 引数は廃止** |
| **B9** | A3-1 `_test_payload()` | `urlencode()` が既エンコード済みペイロード（`%0d%0a...`）を二重エンコードし `%250d%250a` になる | **`urlencode` を使わず `quote(parameter)=payload` の形式で直接結合** |
| **B10** | A3-1 `_test_payload()` | `conn.close()` が例外発生前に呼ばれず接続リーク | **`try/finally` で確実にクローズ** |
| **B11** | A3-1 `_test_payload()` | `resp.read()` 未呼び出しで keep-alive 時に `ResponseNotReady` リスク | **`_ = resp.read()` を追加** |
| **B12** | A3-1 `_is_vulnerable()` | `dict(resp.getheaders())` で `Set-Cookie` 複数値が後の値で上書きされ検出漏れ | **`getheaders()` を結合してから渡す** |
| **B13** | A3-6 Flask ターゲット | `X-Injected` エコーバックが CRLF サニタイズ後の変換済み文字列なので `_is_vulnerable()` と一致しない → L2 常に陰性 | **`"shigoku"` がペイロードに含まれれば `X-Injected: shigoku` を直接返す** |
| **B14** | A3-1 `import ssl` | `_test_payload()` 内インポートでスタイル違反 | **ファイル先頭に移動** |

---

## 実装前必須確認（仕様書 §0）

```bash
# 0.1 VulnType.CRLF_INJECTION — 既存確認（finding.py L51 に存在することを確認）
grep -n "CRLF_INJECTION" src/core/models/finding.py

# 0.2 create_crlf_tester() 使用箇所（B3対応: 破壊的変更チェック）
grep -rn "create_crlf_tester\|CRLFTester()" src/
# 期待値: src/core/attack/__init__.py (export), mode_manager.py (名前登録のみ), tool_registry.py (ToolInfo登録のみ)
# → 直接インスタンス化している箇所はなし → デフォルト引数追加で非破壊

# 0.3 Flask ポート競合確認（A-2 は 15556, A-3 は 15557 予定）
grep -rn "15557" tests/helpers/
```

> **確認済み**: `VulnType.CRLF_INJECTION` は `src/core/models/finding.py` L51 に既存。A3-0 タスクは**スキップ**。

---

## タスク一覧

| タスク | 内容 | 依存 | 修正対応 |
|---|---|---|---|
| ~~A3-0~~ | ~~`VulnType.CRLF_INJECTION` 追加~~ | — | **スキップ（既存）** |
| A3-1 | `CRLFTester` 全体修正（`__init__`/`_is_vulnerable`/`PAYLOADS`/`_test_payload`/`scan_async`） | なし | B1/B2/B3/B8 |
| A3-2 | `SmartCRLFHunter` 新規作成 | A3-1 | B4/B8 |
| A3-3 | `tagging_rules.yaml` CRLF ルール追加（3ルール） | なし | B5 |
| A3-4 | InjectionManager 配線（7箇所） | A3-2 | B6/B7 |
| A3-5 | ReconPipeline 統合 | なし | — |
| A3-6 | テスト（L1 9件 + L2 3件） | A3-1〜A3-5 | — |
| A3-7 | Haddix formatter CRLF 固有ブランチ + L4 テスト | A3-2 | — |

**実装順序**: A3-1 → A3-2 → A3-3（並列可）→ A3-4 → A3-5（並列可）→ A3-6 → A3-7

---

## タスク A3-1: `CRLFTester` 全体修正

**ファイル**: `src/core/attack/crlf_tester.py`

### `__init__` 変更（B3/B8）

```python
# 変更前
def __init__(self):
    self.results: List[CRLFResult] = []

# 変更後（auth_headers=None デフォルトで既存呼び出しと互換）
def __init__(self, auth_headers: Optional[Dict] = None):
    self.auth_headers = auth_headers or {}
    self.results: List[CRLFResult] = []
```

`create_crlf_tester()` も合わせて更新（非破壊）:

```python
def create_crlf_tester(auth_headers: Optional[Dict] = None) -> CRLFTester:
    return CRLFTester(auth_headers=auth_headers)
```

### `PAYLOADS` 追記（B1対応: Location/Content-Type/Link ペイロードにマーカーを付与）

> **根本問題**: 既存 `"%0d%0aLocation: https://evil.com"` は `_is_vulnerable()` が `Location` を検出しないため永久に見逃される。ペイロードと検出ロジックを同時に修正する。

既存の Location ペイロードを差し替え、新規ペイロードを追加:

```python
# 削除
"%0d%0aLocation: https://evil.com",

# 追加（マーカー "shigoku" 付き）
"%0d%0aLocation: https://shigoku.evil.com",       # Location 注入（マーカー付き）
"%0d%0aContent-Type: text/html; charset=shigoku",  # Content-Type 注入
"%0d%0aLink: <https://shigoku.evil.com>; rel=preload",  # Link 注入（キャッシュポイズニング）
```

### `_is_vulnerable()` 修正（B1）

```python
def _is_vulnerable(self, headers: Dict) -> tuple:
    """
    脆弱性判定。注入マーカー "shigoku" または注入ヘッダー名の存在を確認。
    headers は lowercase 正規化済み・Set-Cookie は複数値結合済みで渡すこと（_test_payload で対応）。

    Returns:
        (vulnerable, injected_header_name)
    """
    # X-Injected: shigoku
    if "x-injected" in headers:
        return True, "X-Injected"

    # Set-Cookie 注入（B12: 複数値は _test_payload で結合済み）
    if "shigoku" in str(headers.get("set-cookie", "")):
        return True, "Set-Cookie"

    # Location 注入（B1: 最も重要なCRLF攻撃ベクター）
    if "shigoku" in str(headers.get("location", "")):
        return True, "Location"

    # Content-Type 注入（B1: XSS誘発に使われる）
    if "shigoku" in str(headers.get("content-type", "")):
        return True, "Content-Type"

    # Link ヘッダー注入（B1: キャッシュポイズニング）
    if "shigoku" in str(headers.get("link", "")):
        return True, "Link"

    return False, ""
```

> **注意**: `_is_vulnerable()` に lowercase 正規化済み headers を渡すこと（`_test_payload()` の B9〜B12 修正で対応済み）。

### `_test_payload()` 実装（B2: http.client 主実装）

> **根拠**: httpx は httpcore レイヤーで `\r\n` を除去することが確認されている。http.client は生ソケットを使うため CRLF を生送信できる。

> **B14対応**: `import ssl` / `import http.client` はファイル先頭に移動すること（本スニペットはトップレベルimport前提で記述）。

```python
# ファイル先頭に移動するimport（B14）
import http.client
import ssl
from collections import defaultdict
from urllib.parse import urlparse, quote

def _test_payload(self, url: str, parameter: str, payload: str) -> Optional[CRLFResult]:
    """
    http.client で生CRLF送信。httpx は使用しない（\r\n サニタイズ問題）。

    B9: urlencode は既エンコード済みペイロードを二重エンコードするため使用禁止。
        quote(param)=payload 形式で直接結合する。
    B10: conn.close() を finally で確実に実行（接続リーク防止）。
    B11: resp.read() でボディを消費（ResponseNotReady 防止）。
    B12: getheaders() の Set-Cookie 複数値を結合して渡す。
    """
    parsed = urlparse(url)
    # B9: payload は既にURL-encoded文字列（%0d%0a...）なのでそのまま結合
    path = f"{parsed.path or '/'}?{quote(parameter, safe='')}={payload}"
    req_headers = dict(self.auth_headers)
    conn = None
    try:
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(parsed.netloc, timeout=self.TIMEOUT, context=ctx)
        else:
            conn = http.client.HTTPConnection(parsed.netloc, timeout=self.TIMEOUT)
        conn.request("GET", path, headers=req_headers)
        resp = conn.getresponse()
        _ = resp.read()  # B11: ボディを消費しないと次リクエストで ResponseNotReady
        # B12: Set-Cookie 複数値をすべて結合（dict変換で後の値が上書きされるのを防ぐ）
        multi: defaultdict = defaultdict(list)
        for k, v in resp.getheaders():
            multi[k.lower()].append(v)
        resp_headers = {k: v[0] if len(v) == 1 else " ".join(v) for k, v in multi.items()}
    except Exception:
        return None
    finally:
        if conn:  # B10: 例外発生時も確実にクローズ
            conn.close()

    vulnerable, injected_header = self._is_vulnerable(resp_headers)
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
```

### `scan_async()` 変更（B8: auth_headers 引数廃止）

```python
async def scan_async(self, url: str, parameters: List[str]) -> List[CRLFResult]:
    """auth_headers は __init__ で設定済み。引数では受け取らない（B8）。"""
    import asyncio
    return await asyncio.to_thread(self.test, url, parameters)
```

**合格基準**:
- `_test_payload()` が `http.client` で動作し `\r\n` を生送信できる
- `_is_vulnerable()` が `X-Injected` / `Set-Cookie` / `Location` / `Content-Type` / `Link` を検出する
- `create_crlf_tester()` が引数なしで呼べる（非破壊）
- `scan_async()` に `auth_headers` 引数がない

---

## タスク A3-2: `SmartCRLFHunter` 新規作成

**新規ファイル**: `src/core/agents/swarm/injection/smart_crlf.py`

```python
import logging
from typing import Dict, Any, List, Optional

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.attack.crlf_tester import CRLFTester

logger = logging.getLogger(__name__)

# B4対応: tested_params が空の場合のフォールバック（CRLFが頻出するパラメータ名）
FALLBACK_PARAMS = ["url", "redirect", "next", "return", "dest", "location",
                   "forward", "goto", "redir", "lang", "charset", "filename"]


class SmartCRLFHunter(Specialist):
    name = "SmartCRLFHunter"
    description = "Deterministic CRLF injection scanner"
    timeout_seconds = 90
    is_aggressive = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.last_results: list = []

    async def run_as_tool(self, url: str, params: Dict[str, Any] = None, **_kwargs) -> Dict[str, Any]:
        params = params or {}
        _auth = params.get("_auth", {}) if isinstance(params.get("_auth"), dict) else {}
        auth_headers: Dict[str, str] = dict(_auth.get("auth_headers", {}) or {})
        cookies_str: str = str(_auth.get("cookies", "") or params.get("cookies", "") or "")
        if cookies_str and "Cookie" not in auth_headers:
            auth_headers["Cookie"] = cookies_str

        # META_KEYS 除外
        tested_params = self._extract_test_params(url, params, "GET")
        self.last_tested_params = tested_params

        # B4対応: 空でもフォールバックパラメータでスキャン継続（early return しない）
        scan_params = tested_params if tested_params else FALLBACK_PARAMS

        # B8対応: auth_headers は __init__ で一本化、scan_async には渡さない
        scanner = CRLFTester(auth_headers=auth_headers)
        try:
            results = await scanner.scan_async(url, scan_params)
        except Exception as exc:
            logger.error("[%s] CRLFTester error for %s: %s", self.name, url, exc)
            return {"vulnerable": False, "findings_count": 0, "tested_params": tested_params, "results": []}

        vuln = [r for r in results if r.vulnerable]
        self.last_results = vuln
        return {
            "vulnerable": bool(vuln),
            "findings_count": len(vuln),
            "tested_params": tested_params,
            "injected_header": vuln[0].injected_header if vuln else "",
            "payload": vuln[0].payload if vuln else "",
            "results": [
                {
                    "parameter": r.parameter,
                    "payload": r.payload,
                    "injected_header": r.injected_header,
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
            evidence = Evidence(
                request_method="GET",
                request_url=target_url,
                request_headers={},
                response_status=302,
                response_headers={r["injected_header"]: "injected-via-crlf"},
            )
            findings.append(Finding(
                target_url=target_url,
                vuln_type=VulnType.CRLF_INJECTION,
                severity=Severity.MEDIUM,
                title=f"CRLF Injection via parameter '{r['parameter']}'",
                description=(
                    f"Parameter '{r['parameter']}' reflects CRLF sequence into response headers. "
                    f"Injected header: {r['injected_header']}. "
                    f"Payload: {r['payload']!r}"
                ),
                source_agent="SmartCRLFHunter",
                confidence=0.90,
                tags=["crlf", "medium"],
                evidence=evidence,
                additional_info={
                    "parameter": r["parameter"],
                    "payload": r["payload"],
                    "injected_header": r["injected_header"],
                    "tested_params": result.get("tested_params", []),
                    "poc_request": (
                        f"GET {target_url}?{r['parameter']}={r['payload']} HTTP/1.1\r\n"
                        f"Host: <target>\r\n\r\n"
                    ),
                    "poc_response": (
                        f"HTTP/1.1 302 Found\r\n"
                        f"Location: /\r\n"
                        f"{r['injected_header']}: injected-via-crlf\r\n\r\n"
                    ),
                    "poc_html": (
                        f"<!-- CRLF Injection PoC -->\n"
                        f"<!-- Parameter: {r['parameter']} -->\n"
                        f"<!-- Payload (URL-encoded): {r['payload']!r} -->\n"
                        f"<!-- Injected header: {r['injected_header']} -->"
                    ),
                },
            ))
        return findings
```

**合格基準**:
- `is_aggressive = False`
- `tested_params` が空でもスキャンが実行される（`FALLBACK_PARAMS` 使用）
- `run_as_tool()` が `{"vulnerable", "findings_count", "tested_params", "injected_header", "payload"}` を返す
- `additional_info` に `poc_request`/`poc_response`/`poc_html` がすべて存在する
- `Evidence` オブジェクトが Finding に設定されている

---

## タスク A3-3: `tagging_rules.yaml` に CRLF ルール追加（3ルール）

**ファイル**: `config/tagging_rules.yaml`
**位置**: `cors_path_hint` の直後

```yaml
  # CRLF: リダイレクト系パスヒューリスティック
  - name: crlf_path_hint
    tag: crlf_candidate
    match_on: path
    pattern: "(redirect|location|forward|continue|return|next|redir)"

  # CRLF: リダイレクト系クエリパラメータ
  - name: crlf_param_hint
    tag: crlf_candidate
    match_on: query
    pattern: "(^|[?&])(url|redirect|return_url|next|location|forward|continue|redir|dest|target|goto)="
    param_extract: 2

  # CRLF: レスポンス分割系クエリパラメータ（B5追加: Set-Cookie/Content-Type注入が刺さるパラメータ）
  - name: crlf_response_splitting_param
    tag: crlf_candidate
    match_on: query
    pattern: "(^|[?&])(lang|locale|charset|encoding|header|name|title|filename|page|view|format|type|output)="
    param_extract: 2
```

**設計方針**:
- `crlf_path_hint` — パスからリダイレクト系エンドポイントを検出
- `crlf_param_hint` — リダイレクト系パラメータ（最高精度）
- `crlf_response_splitting_param` — レスポンス分割が刺さる汎用パラメータ（B5）
- `redirect_param` との競合は A3-4 の `_classify_url()` 優先順位で解消（B6）

---

## タスク A3-4: InjectionManager 配線（7箇所）

**ファイル**: `src/core/agents/swarm/injection/manager.py`

```python
# 1. PER_URL_TIMEOUT_BY_TYPE
"crlf": 90,

# 2. _classify_url() — B6対応: 現在 L240 の redirect_param チェックの直前に挿入
if category_hint == "crlf_candidate":
    return "crlf"
# ↓ 既存行（変更なし）
if category_hint == "redirect_param":
    return "redirect"

# 3. _initialize_specialists()
try:
    from src.core.agents.swarm.injection.smart_crlf import SmartCRLFHunter
    self.specialists["crlf"] = SmartCRLFHunter(config=self.config)
except ImportError:
    logger.warning("SmartCRLFHunter not available")

# 4. _register_manager_tools()
if "crlf" in self.specialists:
    self.register_tool("crlf_scan", self.run_crlf_hunter, "CRLFインジェクションの決定論的スキャンを実行します。")

# 5. _run_unknown_hypothesis_scans()
elif specialist == "crlf":
    result = await self.run_crlf_hunter(url=url, params=base_params, quick_mode=quick_mode)
    unknown_results.append(result)

# 6. _resolve_risk_force_allowlist()
allow = {"sqli", "cmd_ssrf", "lfi", "csrf", "api", "redirect", "ssti", "cors", "crlf"}

# 7a. _build_unknown_hypotheses() 仮説生成追加 — B7対応
# 既存の ssrf 仮説生成ブロックの近辺（redirect_crlf_keys と重複するため直後）に追加
redirect_crlf_keys = {"url", "redirect", "next", "return", "dest", "location",
                      "forward", "goto", "redir", "lang", "locale", "charset",
                      "filename", "format", "type", "output"}
if any(k in path for k in ["redirect", "forward", "location", "redir"]) \
        or (all_param_keys & redirect_crlf_keys):
    hypotheses.append("crlf")
    signals.append("crlf_signal")

# 7b. specialist_map に追加 — B7対応
specialist_map = {
    "sqli": "sqli",
    "xss": "xss",
    "lfi": "lfi",
    "ssti": "ssti",
    "ssrf": "cmd_ssrf",
    "api": "sqli",
    "csrf": "xss",
    "idor": "sqli",
    "crlf": "crlf",    # ← 追加
}
```

### `run_crlf_hunter()` メソッド追加

仕様書 §2.3C テンプレートに従い実装する。`current_context` 未初期化ガードは**必須**。

```python
async def run_crlf_hunter(
    self, url: str, params: dict = None, quick_mode: bool = False, **_kwargs
) -> dict:
    if "crlf" not in self.specialists:
        return {"error": "CRLF Specialist not available", "findings_count": 0, "tested_params": []}
    logger.info("[%s] Delegating CRLF check to SmartCRLFHunter", self.name)
    effective_params = self._normalize_tool_supplied_params(params, _kwargs)

    # current_context 未初期化ガード（仕様書 §2.3C 必須）
    if not isinstance(self.current_context, dict):
        self.current_context = {}
    self.current_context.setdefault("findings", [])
    self.current_context.setdefault("auth_headers", {})
    self.current_context.setdefault("params", {})

    cookies_str = _kwargs.get("cookies") or self.current_context.get("params", {}).get("cookies", "")
    effective_params["_auth"] = {
        "auth_headers": _kwargs.get("auth_headers", self.current_context.get("auth_headers", {})),
        "cookies": cookies_str,
    }
    return await self.specialists["crlf"].run_as_tool(url, effective_params)
```

**合格基準**:
- `_classify_url("crlf_candidate")` が `"crlf"` を返す（B6）
- `_classify_url("redirect_param")` が引き続き `"redirect"` を返す（回帰なし）
- `_build_unknown_hypotheses()` が `?url=` を持つURLで `"crlf"` を仮説に含む（B7）
- `run_crlf_hunter()` を Flask 未起動で呼んでも `KeyError` が発生しない

---

## タスク A3-5: ReconPipeline 統合

**ファイル**: `src/recon/pipeline.py`

```python
# task_mapping
"crlf_candidate": {
    "agent_type": "InjectionManagerAgent",
    "priority": 65,
    "vuln_type": "crlf",
    "description": "CRLFインジェクションのスキャン",
},

# _map_tagged_category_to_tags()
"crlf_candidate": ["crlf_candidate"],
```

---

## タスク A3-6: テスト

### Flask ターゲット

**新規ファイル**: `tests/helpers/crlf_flask_target.py`

```python
from flask import Flask, request, Response
import threading

FLASK_PORT = 15557


def make_crlf_app() -> Flask:
    app = Flask(__name__)

    @app.route("/redirect")
    def vulnerable():
        """
        url パラメータを Location ヘッダーに直接挿入（CRLF脆弱）。
        B13: X-Injected エコーバックを _is_vulnerable() が検出できる値に修正。
            ペイロードに "shigoku" が含まれる場合 → X-Injected: shigoku を返す。
            Flask/Werkzeug が \r\n をサニタイズしても X-Injected で検出可能にする。
        """
        url_param = request.args.get("url", "/")
        resp = Response("", status=302)
        resp.headers["Location"] = url_param
        # B13: shigoku マーカーが含まれていれば X-Injected: shigoku を返す（検出確実化）
        if "shigoku" in url_param:
            resp.headers["X-Injected"] = "shigoku"
        return resp

    @app.route("/safe")
    def safe():
        return Response("safe", status=200)

    @app.route("/post", methods=["POST"])
    def post_vulnerable():
        """POST body の redirect パラメータをエコーバック（将来拡張用）"""
        redirect_val = request.form.get("redirect", "/")
        resp = Response("", status=302)
        resp.headers["Location"] = redirect_val
        return resp

    return app


def start_crlf_server(port: int = FLASK_PORT) -> threading.Thread:
    app = make_crlf_app()
    thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, use_reloader=False),
        daemon=True,
    )
    thread.start()
    return thread


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else FLASK_PORT
    print(f"Starting CRLF Flask target on http://127.0.0.1:{port}")
    make_crlf_app().run(host="127.0.0.1", port=port, use_reloader=False)
```

> ⚠️ **テスト注意（B13修正後）**: Flask/Werkzeug が `\r\n` をサニタイズしても、ペイロードに "shigoku" が含まれる場合は `X-Injected: shigoku` が返るため L2 テストは陽性になる。
> http.client が Python 3.11+ で CRLF を拒否する場合（B9 の `quote(param)=payload` 形式でもサニタイズされる場合）は raw socket 実装に切り替えること（リスクテーブル参照）。

### L1 テストケース一覧

**新規ファイル**: `tests/core/agents/swarm/injection/test_smart_crlf.py`

| テスト名 | 検証内容 | 合格基準 |
|---|---|---|
| `test_execute_returns_finding_when_vulnerable` | 脆弱エンドポイント → Finding生成 | `len(findings) >= 1`, `vuln_type == "crlf_injection"` |
| `test_execute_returns_empty_when_safe` | 安全エンドポイント → 空リスト | `findings == []` |
| `test_finding_severity_is_medium` | CRLF は MEDIUM | `severity == Severity.MEDIUM` |
| `test_finding_has_injected_header_in_additional_info` | 注入ヘッダー名が記録される | `additional_info["injected_header"]` が存在かつ非空 |
| `test_finding_has_poc_request_and_poc_response` | poc_request/poc_response が存在 | 両キーが `additional_info` に存在 |
| `test_tested_params_excludes_control_params` | META_KEYS が除外される | `"_auth"`, `"scan_profile"` が `tested_params` に含まれない |
| `test_run_as_tool_empty_params_uses_fallback` | tested_params 空 → FALLBACK_PARAMS でスキャン（B4） | `scan_async` がFALLBACK_PARAMSで呼ばれる |
| `test_run_as_tool_initializes_result_shape` | 返却dict形状確認 | `"vulnerable"`, `"findings_count"`, `"tested_params"`, `"injected_header"`, `"payload"` が存在 |
| `test_auth_headers_forwarded_to_scanner` | auth cookies が CRLFTester に渡る | CRLFTester インスタンスの auth_headers に Cookie が含まれる |
| `test_evidence_object_set_on_finding` | Evidence オブジェクトが存在 | `finding.evidence is not None` |

### L2 テストケース（`@pytest.mark.integration`）

```python
@pytest.fixture(scope="module")
def crlf_server():
    from tests.helpers.crlf_flask_target import start_crlf_server, FLASK_PORT
    start_crlf_server(FLASK_PORT)
    import time; time.sleep(0.3)
    yield f"http://127.0.0.1:{FLASK_PORT}"

@pytest.mark.integration
def test_crlf_scanner_detects_live(crlf_server): ...

@pytest.mark.integration
def test_crlf_scanner_no_false_positive_on_safe(crlf_server): ...

@pytest.mark.integration
def test_crlf_scanner_detects_post_body(crlf_server): ...
```

**テストポート**: `15557`

---

## タスク A3-7: Haddix Formatter 固有ブランチ + L4 テスト

**ファイル**: `src/reporting/haddix_formatter.py`

### `_cia_impact_assessment()` に CRLF ブランチ追加

```python
elif vuln_type == "crlf_injection":
    return (
        "C: Medium — Injected headers can leak session tokens or redirect victims to attacker-controlled pages. "
        "I: Medium — Response header manipulation enables phishing and cache poisoning. "
        "A: Low — Service availability is not directly impacted."
    )
```

### `_remediation()` に CRLF ブランチ追加

```python
elif vuln_type == "crlf_injection":
    return (
        "Validate and sanitize all user-supplied input used in HTTP response headers. "
        "Strip or reject CR (\\r) and LF (\\n) characters from redirect targets and header values. "
        "Use allowlists for redirect destinations and avoid reflecting raw user input into headers."
    )
```

### L4 テストケース

**ファイル**: `tests/unit/reporting/test_haddix_formatter_quality.py` に追加

```python
def test_formatter_crlf_finding_is_included_in_report():
    """CRLF Finding がサプレスされずレポートに含まれること"""

def test_formatter_crlf_finding_poc_request_populated():
    """additional_info.poc_request が poc_request フィールドに反映されること"""

def test_formatter_crlf_cia_and_remediation_not_generic():
    """CIA評価と修正方針が汎用フォールバックでないこと"""
```

---

## 手動確認コマンド集（仕様書 §6 準拠）

```bash
# ターミナル 1: Flask 起動
.venv/bin/python tests/helpers/crlf_flask_target.py
ss -tlnp | grep 15557

# ターミナル 2: CRLFTester 実動作確認
.venv/bin/python -c "
import asyncio
from src.core.attack.crlf_tester import CRLFTester

async def main():
    t = CRLFTester()
    results = await t.scan_async('http://127.0.0.1:15557/redirect', ['url', 'redirect'])
    print('results count:', len(results))
    for r in results:
        print(' ', r)

asyncio.run(main())
"

# run_crlf_hunter スモークテスト（Flask 起動中）
.venv/bin/python -c "
import asyncio
from src.core.agents.swarm.injection.manager import InjectionManagerAgent

async def main():
    mgr = InjectionManagerAgent(config={'model': 'test'})
    result = await mgr.run_crlf_hunter('http://127.0.0.1:15557/redirect')
    import json; print(json.dumps(result, indent=2, ensure_ascii=False))

asyncio.run(main())
"

# run_crlf_hunter スモークテスト（Flask 未起動: KeyError が発生しないこと）
.venv/bin/python -c "
import asyncio
from src.core.agents.swarm.injection.manager import InjectionManagerAgent

async def main():
    mgr = InjectionManagerAgent(config={'model': 'test'})
    result = await mgr.run_crlf_hunter('http://127.0.0.1:15557/redirect')
    print('findings_count:', result.get('findings_count'))
    print('no KeyError: OK')

asyncio.run(main())
"

# Haddix レポート出力確認
.venv/bin/python -c "
from src.reporting.haddix_formatter import HaddixFormatter

f = HaddixFormatter()
f.set_target('http://example.com')
f.add_finding_from_dict({
    'title': 'CRLF Injection Test Finding',
    'severity': 'medium',
    'vuln_type': 'crlf_injection',
    'target_url': 'http://example.com/redirect',
    'confidence': 0.90,
    'summary': 'Test',
    'additional_info': {
        'poc_request': 'GET /redirect?url=%0d%0aLocation: https://shigoku.evil.com HTTP/1.1\r\nHost: example.com',
        'poc_response': 'HTTP/1.1 302 Found\r\nLocation: https://shigoku.evil.com\r\n',
    },
})
print(f.format_markdown()[:2000])
"
```

---

## A-3 完了チェックリスト

### 実装前確認
- [ ] `VulnType.CRLF_INJECTION` が `src/core/models/finding.py` L51 に存在することを確認
- [ ] `create_crlf_tester()` の使用箇所が `__init__.py` export + 名前登録のみであることを確認
- [ ] ポート `15557` が未使用であることを確認

### Scanner 層（A3-1）
- [ ] `__init__` が `auth_headers=None` デフォルト引数を持つ
- [ ] `create_crlf_tester()` が引数なしで呼べる（非破壊確認）
- [ ] `_is_vulnerable()` が lowercase 正規化済み headers を受け取り、5種類のヘッダーを検出する
- [ ] Location/Content-Type/Link ペイロードに "shigoku" マーカーが含まれている
- [ ] `_test_payload()` が `http.client` で実動作する（httpx 不使用）
- [ ] HTTPS エンドポイントで `HTTPSConnection` にフォールバックする（B14: ssl はファイル先頭import）
- [ ] `_test_payload()` が `quote(param)=payload` 形式でペイロードを結合する（B9: urlencode 不使用）
- [ ] `_test_payload()` が `try/finally` で `conn.close()` を確実に呼ぶ（B10）
- [ ] `_test_payload()` が `resp.read()` でボディを消費する（B11）
- [ ] `getheaders()` の `Set-Cookie` 複数値を結合してから `_is_vulnerable()` に渡す（B12）
- [ ] `scan_async()` に `auth_headers` 引数がない

### Specialist 層（A3-2）
- [ ] `SmartCRLFHunter` が `specialists["crlf"]` に登録される
- [ ] `is_aggressive = False`
- [ ] `tested_params` が空でも `FALLBACK_PARAMS` でスキャンを継続する
- [ ] `additional_info` に `poc_request`/`poc_response`/`poc_html` がすべて存在する
- [ ] `Evidence` オブジェクトが Finding に設定されている

### タグ付け層（A3-3）
- [ ] `crlf_path_hint` / `crlf_param_hint` / `crlf_response_splitting_param` の3ルールが追加されている
- [ ] `?url=` 付き URL が `crlf_candidate` タグを得る
- [ ] `?lang=` 付き URL が `crlf_candidate` タグを得る（B5）

### 分類・ルーティング層（A3-4）
- [ ] `_classify_url("crlf_candidate")` が `"crlf"` を返す
- [ ] `crlf_candidate` の評価が `redirect_param` より前にある（B6）
- [ ] `_classify_url("redirect_param")` が引き続き `"redirect"` を返す（回帰なし）
- [ ] `_build_unknown_hypotheses()` が `?url=` を持つURLで `"crlf"` を仮説に含む（B7）
- [ ] `specialist_map` に `"crlf": "crlf"` が存在する（B7）

### InjectionManager 層（A3-4）
- [ ] `PER_URL_TIMEOUT_BY_TYPE["crlf"]` = 90 が存在する
- [ ] `run_crlf_hunter()` が `SmartCRLFHunter.run_as_tool()` に委譲する
- [ ] `run_crlf_hunter()` 直接呼び出し時の `KeyError` ガードがある

### Recon 層（A3-5）
- [ ] `task_mapping["crlf_candidate"]` が priority=65 で存在する
- [ ] `_map_tagged_category_to_tags("crlf_candidate")` が `["crlf_candidate"]` を返す

### レポーター層（A3-7）
- [ ] `_cia_impact_assessment()` に CRLF 固有ブランチがある
- [ ] `_remediation()` に CRLF 固有ブランチがある

### テスト
- [ ] L1: `test_smart_crlf.py` 10件以上 GREEN
- [ ] L2: integration 3件 GREEN（crlf_flask_target.py ポート15557）
- [ ] L3: 既存スペシャリスト 回帰 GREEN（`redirect_param` 分類が壊れていない）
- [ ] L4: `_classify_url("crlf_candidate") == "crlf"` テスト GREEN
- [ ] L4: `_build_unknown_hypotheses` CRLF 仮説テスト GREEN（B7）
- [ ] L4: Haddix formatter CRLF Finding 出力テスト 3件 GREEN
- [ ] `crlf_flask_target.py` に `__main__` ブロックあり

---

## リスクと対処

| リスク | 対処 |
|---|---|
| http.client も CRLF を拒否する場合（Python 3.11+ の制限強化） | B9の `quote(param)=payload` 形式でもブロックされる場合は `conn.putheader()` / raw socket fallback を追加。L2 で必ず確認 |
| Flask/Werkzeug が CRLF をサニタイズし Location 注入が検出されない | B13修正済み。"shigoku" 含みペイロードで `X-Injected: shigoku` が返るため L2 陽性になる |
| Unicode エンコードペイロード `%E5%98%8A%E5%98%8D` が再エンコードされる | B9修正（quote(param)=payload）で payload はそのまま結合されるため二重エンコードは起きない |
| `Set-Cookie` 複数値で注入を見逃す | B12修正済み（defaultdict で全値結合）|
| `redirect_param` との競合が `_classify_url()` 修正後も残る | `crlf_candidate` タグの場合 L241 より前に評価されることをテストで確認（L4 テストケース必須） |
| `crlf_response_splitting_param` の偽陽性が多い | 実際のスキャンで問題になった場合は `priority` を下げるか、ルールを削除してタグ付けを絞る |

---

*作成: 2026-05-16*
*更新: 2026-05-16（B1-B8 レビュー指摘を全て反映、B9-B14 追加反映）*
*対象: SHIGOKU v0.2.0+*
