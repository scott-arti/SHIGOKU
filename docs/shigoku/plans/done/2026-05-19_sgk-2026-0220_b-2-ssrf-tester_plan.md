---
task_id: SGK-2026-0220
doc_type: plan
status: done
parent_task_id: null
related_docs:
- docs/shigoku/plans/2026-05-15_sgk-2026-0059_a2_b2_implementation_plan.md
- docs/shigoku/specs/standards/vulnerability_feature_implementation_spec.md
title: 'B-2: SSRF 単体 Tester 実実装'
created_at: '2026-05-19'
updated_at: '2026-06-24'
tags:
- shigoku
target: src/core/attack/ssrf_tester.py, src/core/agents/swarm/injection/smart_ssrf.py,
  src/core/agents/swarm/injection/manager.py
---

# B-2: SSRF 単体 Tester 実実装 計画書

**作成日**: 2026-05-19  
**前提**: A-2 (CORS) ✅, A-3 (CRLF) ✅, B-1 (GraphQL) ✅ 完了済み  
**参照**: `docs/shigoku/plans/2026-05-15_sgk-2026-0059_a2_b2_implementation_plan.md` §B-2  
**標準仕様**: `docs/shigoku/specs/standards/vulnerability_feature_implementation_spec.md`

---

## 概要

`SSRFTester._test_payload()` が `return None` のプレースホルダー。  
`_analyze_response()`, `SAFE_PAYLOADS`, `VULN_INDICATORS` は実装済み・再利用可能。  
`SmartCmdSSRFHunter`（`specialists["cmd_ssrf"]`）は別系統（LLM+OOB）として稼働中。  
今回は **httpx 応答ベースの決定論的 SSRF 検出** として独立エントリポイント `"ssrf"` を新設する。

---

## スコープ

### スコープ内
- `SSRFTester._test_payload()` の httpx 実装
- `SSRFTester.scan_async()` 非同期ラッパー追加
- `SmartSSRFHunter` 新規作成（`specialists["ssrf"]`）
- InjectionManager 配線（6箇所）
- `tagging_rules.yaml` SSRF ルール追加
- ReconPipeline 統合
- テスト L1〜L4 + Flask ターゲット

### スコープ外
- OOB（DNS/HTTP コールバック）検出 — LocalOOBListener 連携は将来フェーズ
- クラウドメタデータへの実際のアクセス（スキャン対象環境外への送信）
- file:// プロトコルの実送信

---

## 0. 実装前事前確認（仕様書 §0 準拠）

### 0.1 VulnType 確認結果
```
$ grep -n "SSRF\|ssrf" src/core/models/finding.py
47:    SSRF = "ssrf"
```
→ `VulnType.SSRF = "ssrf"` **既存定義済み**。追加不要。

### 0.2 既存 VulnType 競合確認
`SmartCmdSSRFHunter` は `VulnType.CMD_INJECTION` 等を使用（確認要）。  
`VulnType.SSRF` を `SmartSSRFHunter` 専用に使う。競合なし。

### 0.3 Flask ポート確認結果
| フェーズ | ファイル | ポート |
|---|---|---|
| A-1 | ssti_flask_target.py | 15555 |
| A-2 | cors_flask_target.py | 15556 |
| A-3 | crlf_flask_target.py | 15557 |
| B-1 | graphql_flask_target.py | 15558 |
| **B-2** | **ssrf_flask_target.py** | **15559** |

→ `15559` 未使用。計画通り使用可。

### 0.4 HTTPクライアント選択
SSRF は通常の GET リクエストのため `httpx.Client` で可（仕様書 §0.4 表より）。

### 0.5 Import パス確認結果
```
$ grep -rn "class Specialist" src/core/agents/swarm/
src/core/agents/swarm/base.py:34:class Specialist(ABC):
```
→ `from src.core.agents.swarm.base import Specialist`

### 0.6 manager.py 既存 ssrf 状態
- `specialist_map` に `"ssrf": "cmd_ssrf"` が存在（L644）→ **B-2実装後に `"ssrf": "ssrf"` へ変更必要**
- `_classify_url()` L311 のパスヒューリスティックが `"cmd_ssrf"` を返す → `"ssrf_candidate"` tag を先に評価すること
- `_resolve_risk_force_allowlist()` の allowlist に `"ssrf"` なし → 追加要
- `PER_URL_TIMEOUT_BY_TYPE` に `"ssrf"` なし → 追加要

---

## 実装タスク一覧

| # | タスク | ファイル | 優先 |
|---|---|---|---|
| B2-1 | `SSRFTester` 強化 | `src/core/attack/ssrf_tester.py` | 1 |
| B2-2 | `SmartSSRFHunter` 新規作成 | `src/core/agents/swarm/injection/smart_ssrf.py` | 2 |
| B2-3 | tagging_rules SSRF ルール追加 | `config/tagging_rules.yaml` | 3 |
| B2-4 | InjectionManager 配線（6箇所） | `src/core/agents/swarm/injection/manager.py` | 4 |
| B2-5 | ReconPipeline 統合 | `src/recon/pipeline.py` | 5 |
| B2-6 | テスト全層 | `tests/` 複数ファイル | 6 |

---

## タスク B2-1: `SSRFTester` 強化

**ファイル**: `src/core/attack/ssrf_tester.py`

### 変更内容

1. `import httpx` 追加
2. `__init__` に `auth_headers: Optional[Dict] = None` パラメータ追加
3. `_test_payload()` に httpx 実装（プレースホルダー置換）
4. `scan_async()` メソッド追加

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

> **注意**: クラウドメタデータ URL（169.254.169.254等）への実リクエストは、
> 実際のクラウド環境上で動作しているターゲットにのみ有効。
> 内部環境での誤検知を防ぐため、レスポンスボディの `VULN_INDICATORS` マッチを必須とする。

**合格基準**:
- `_test_payload()` が httpx で実動作（`return None` でない）
- タイムアウト時に `SSRFResult(vulnerable=False, evidence="timeout")` を返す
- `scan_async()` が非同期で呼べる

---

## タスク B2-2: `SmartSSRFHunter` 新規作成

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

### Finding 仕様
- `VulnType.SSRF`（`"ssrf"`）
- `Severity.HIGH`
- `additional_info` 必須フィールド（仕様書 §2.4）:
  - `tested_params`: List[str]
  - `poc_request`: str（生HTTPリクエスト）
  - `poc_response`: str（生HTTPレスポンス）
  - `poc_html`: str（ブラウザ実行用 HTML）
  - `payload_type`: str
  - `payload`: str
  - `evidence`: str
- `Evidence` オブジェクト設定必須

### SmartCmdSSRFHunter との関係
`specialists["ssrf"]`（今回）と `specialists["cmd_ssrf"]`（既存）は完全独立。
型キーが異なるため競合なし。

---

## タスク B2-3: tagging_rules.yaml SSRF ルール追加

**ファイル**: `config/tagging_rules.yaml`  
**位置**: 既存ルールの末尾 or ssrf関連セクション

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

## タスク B2-4: InjectionManager 配線（6箇所）

**ファイル**: `src/core/agents/swarm/injection/manager.py`

```python
# 1. PER_URL_TIMEOUT_BY_TYPE
"ssrf": 180,

# 2. _classify_url() — ssrf_candidate を cmd_ssrf パスヒューリスティックより前に評価
if category_hint == "ssrf_candidate":
    return "ssrf"

# 3. _initialize_specialists()
try:
    from src.core.agents.swarm.injection.smart_ssrf import SmartSSRFHunter
    self.specialists["ssrf"] = SmartSSRFHunter(config=self.config)
except ImportError:
    logger.warning("SmartSSRFHunter not available")

# 4. _register_manager_tools()
if "ssrf" in self.specialists:
    self.register_tool("ssrf_scan", self.run_ssrf_hunter, "SSRF脆弱性の応答ベーススキャンを実行します。")

# 5. _build_unknown_hypotheses() — "ssrf": "cmd_ssrf" → "ssrf": "ssrf" に変更
ssrf_keys = {"url", "uri", "endpoint", "host", "target", "dest", "src", "fetch", "webhook"}
if any(kw in path for kw in ["fetch", "proxy", "redirect"]) \
    or (all_param_keys & ssrf_keys):
    hypotheses.append("ssrf")
    signals.append("ssrf_signal")
# specialist_map["ssrf"] = "ssrf"  ← "cmd_ssrf" から変更

# 6. _run_unknown_hypothesis_scans() に ssrf 分岐追加
elif specialist == "ssrf":
    result = await self.run_ssrf_hunter(url=url, params=base_params, quick_mode=quick_mode)
    unknown_results.append(result)

# 7. _resolve_risk_force_allowlist()
allow = {..., "ssrf"}  # 追加
```

`run_ssrf_hunter()` メソッド追加（仕様書 §2.3C パターン準拠、`current_context` ガード必須）

---

## タスク B2-5: ReconPipeline 統合

**ファイル**: `src/recon/pipeline.py`

```python
"ssrf_candidate": {
    "agent_type": "InjectionManagerAgent",
    "priority": 80,
    "vuln_type": "ssrf",
    "description": "SSRF脆弱性の応答ベーススキャン",
},

# _map_tagged_category_to_tags()
"ssrf_candidate": ["ssrf_candidate"],
```

---

## タスク B2-6: テスト

### 新規ファイル一覧
| ファイル | 層 | 件数目標 |
|---|---|---|
| `tests/helpers/ssrf_flask_target.py` | Flask ターゲット | — |
| `tests/core/agents/swarm/injection/test_smart_ssrf.py` | L1+L2 | 9件以上+3件 |
| `tests/core/agents/swarm/injection/test_ssrf_classification.py` | L3 | 10件以上 |
| `tests/core/agents/swarm/injection/test_ssrf_pipeline.py` | L4 | 10件以上 |

### Flask ターゲット設計（ポート: 15559）

```python
# tests/helpers/ssrf_flask_target.py
FLASK_PORT = 15559

def make_ssrf_app() -> Flask:
    @app.route("/fetch")
    def vulnerable():
        target = request.args.get("url", "")
        # VULN_INDICATORS マッチ用レスポンスをシミュレート
        if target:
            return f"ami-id: i-1234567890abcdef0\nFetched from: {target}", 200
        return "no url", 400

    @app.route("/safe")
    def safe():
        return "safe", 200

    @app.route("/post", methods=["POST"])
    def post_vulnerable():
        target = request.form.get("url", "")
        if target:
            return f"ami-id: i-1234567890abcdef0\nFetched from: {target}", 200
        return "no url", 400
```

> **設計方針**: 実際の外部URLフェッチは行わず、`VULN_INDICATORS` に含まれる文字列を  
> レスポンスにエコーバックして検出ロジックの動作を確認する。

### L1 ユニットテストケース

| テスト名 | 検証内容 |
|---|---|
| `test_execute_returns_finding_when_vulnerable` | VULN_INDICATORS マッチ → Finding生成 |
| `test_execute_returns_empty_when_safe` | マッチなし → 空リスト |
| `test_finding_severity_is_high` | SSRF は HIGH |
| `test_finding_has_payload_type_in_additional_info` | payload_type が記録される |
| `test_finding_has_poc_request_in_additional_info` | poc_request が記録される |
| `test_finding_has_poc_response_in_additional_info` | poc_response が記録される |
| `test_tested_params_excludes_control_params` | META_KEYS 除外 |
| `test_run_as_tool_initializes_result_shape` | 返却 dict 形状確認 |
| `test_auth_headers_forwarded_to_tester` | auth cookies が渡る |

### L2 統合テストケース（`pytest.mark.integration`）

```python
def test_ssrf_scanner_detects_cloud_metadata_indicator(ssrf_server)
def test_ssrf_scanner_no_false_positive_on_safe(ssrf_server)
def test_ssrf_scanner_detects_post_body(ssrf_server)
```

### L3 分類テストケース（`test_ssrf_classification.py`）

```
class TestClassifyUrlSsrf:
  test_ssrf_candidate_tag_returns_ssrf
  test_ssrf_candidate_beats_cmd_ssrf_path_heuristic
  test_cmd_ssrf_category_unaffected
  test_unknown_category_with_ssrf_path_no_direct_return

class TestBuildUnknownHypothesesSsrf:
  test_ssrf_signal_from_fetch_path_hint
  test_ssrf_specialist_selected_from_fetch_path
  test_ssrf_signal_from_url_param
  test_ssrf_signal_from_webhook_param
  test_ssrf_specialist_not_selected_when_not_registered
  test_no_ssrf_signal_for_unrelated_path
  test_ssrf_does_not_suppress_other_hypotheses

class TestSsrfSpecialistRegistration:
  test_ssrf_specialist_registered_on_init
  test_ssrf_tool_registered
  test_per_url_timeout_has_ssrf
```

### L4 パイプラインテストケース（`test_ssrf_pipeline.py`）

```
class TestRunSsrfHunterStoresFindings:
  test_findings_stored_in_current_context
  test_no_findings_when_not_vulnerable
  test_finding_has_correct_fields
  test_result_shape_has_required_keys

class TestDispatchSsrfPhase1:
  test_dispatch_ssrf_candidate_calls_run_ssrf_hunter
  test_dispatch_stores_ssrf_findings_in_context

class TestHaddixFormatterSsrf:
  test_add_finding_from_dict_accepted
  test_ssrf_finding_appears_in_markdown
  test_ssrf_vuln_type_in_markdown
  test_ssrf_cia_impact_in_markdown
  test_ssrf_remediation_in_markdown
  test_low_confidence_ssrf_suppressed
  test_poc_request_in_markdown
```

---

## ファイル変更一覧

| ファイル | 変更種別 |
|---|---|
| `src/core/attack/ssrf_tester.py` | 修正（_test_payload実装、scan_async追加、auth_headers対応） |
| `src/core/agents/swarm/injection/smart_ssrf.py` | **新規** |
| `config/tagging_rules.yaml` | 修正（ssrf_param_hint, ssrf_body_hint 追加） |
| `src/core/agents/swarm/injection/manager.py` | 修正（6箇所配線、run_ssrf_hunter追加、specialist_map修正） |
| `src/recon/pipeline.py` | 修正（ssrf_candidate タスクマッピング追加） |
| `tests/helpers/ssrf_flask_target.py` | **新規** |
| `tests/core/agents/swarm/injection/test_smart_ssrf.py` | **新規** |
| `tests/core/agents/swarm/injection/test_ssrf_classification.py` | **新規** |
| `tests/core/agents/swarm/injection/test_ssrf_pipeline.py` | **新規** |
| `src/reporting/haddix_formatter.py` | 修正（SSRF固有CIA評価・修正方針ブランチ追加） |

---

## 既知のリスクと注意点

| リスク | 対処方針 |
|---|---|
| `specialist_map["ssrf"] = "cmd_ssrf"` が既存 → L3テストで競合 | B2-4 で `"ssrf": "ssrf"` に変更し、`cmd_ssrf` は別キーで保持 |
| SSRF の実検出が内部環境でほぼ機能しない | L2は VULN_INDICATORS エコーバックで代替、実クラウドは L5 スコープ |
| `_classify_url()` L311 パスヒューリスティックが `cmd_ssrf` を返す | `ssrf_candidate` tag チェックを先に評価すること |
| `SmartCmdSSRFHunter` への回帰 | 回帰テストで `specialists["cmd_ssrf"]` が影響を受けないことを確認 |

---

## 完了チェックリスト（仕様書 §7 準拠）

**スキャナー層**
- [ ] `SSRFTester._test_payload()` が httpx で実動作する（`return None` でない）
- [ ] タイムアウト時に `SSRFResult(vulnerable=False, evidence="timeout")` を返す
- [ ] `SSRFTester.scan_async()` が非同期で呼べる
- [ ] `auth_headers` が httpx リクエストの Cookie ヘッダーに含まれる

**統合層**
- [ ] `VulnType.SSRF = "ssrf"` が存在する（確認済み）
- [ ] `SmartSSRFHunter` が `specialists["ssrf"]` に登録される
- [ ] `run_ssrf_hunter()` が `SmartSSRFHunter` に委譲する
- [ ] `run_ssrf_hunter()` 直接呼び出し時に `KeyError` が発生しない
- [ ] `specialist_map["ssrf"] = "ssrf"` に変更済み（`"cmd_ssrf"` から変更）
- [ ] `PER_URL_TIMEOUT_BY_TYPE["ssrf"] = 180` が設定されている
- [ ] `_resolve_risk_force_allowlist()` の allowlist に `"ssrf"` が追加されている
- [ ] `Finding.additional_info` に `poc_request`/`poc_response` が存在する
- [ ] `Evidence` オブジェクトが Finding に設定されている
- [ ] `Specialist.is_aggressive = False` が設定されている

**レポーター層**
- [ ] `haddix_formatter._cia_impact_assessment()` に SSRF 固有ブランチがある
- [ ] `haddix_formatter._remediation()` に SSRF 固有ブランチがある

**テスト**
- [ ] L1: `test_smart_ssrf.py` 9件以上 GREEN
- [ ] L2: integration 3件 GREEN（ssrf_flask_target.py ポート15559）
- [ ] L3: `test_ssrf_classification.py` 10件以上 GREEN
- [ ] L4: `test_ssrf_pipeline.py` 10件以上 GREEN
- [ ] 回帰: injection スイート全体 GREEN（`SmartCmdSSRFHunter` 影響なし）
- [ ] `ssrf_flask_target.py` に `__main__` ブロックあり

---

## 実装順序

```
Step 1: B2-1 SSRFTester 強化
Step 2: B2-2 SmartSSRFHunter 新規作成（Step 1 依存）
Step 3: B2-3 tagging_rules SSRF ルール追加（独立）
Step 4: B2-4 InjectionManager 配線（Step 1-3 完了後）
Step 5: B2-5 ReconPipeline 統合（独立）
Step 6: B2-6 テスト L1〜L4 + Flask ターゲット
Step 7: haddix_formatter SSRF ブランチ追加
Step 8: 回帰テスト確認
```

---

## 回帰テストコマンド（完了時）

```bash
# B-2 全テスト
.venv/bin/pytest \
  tests/core/agents/swarm/injection/test_smart_ssrf.py \
  tests/core/agents/swarm/injection/test_ssrf_classification.py \
  tests/core/agents/swarm/injection/test_ssrf_pipeline.py -v

# 回帰テスト（injection スイート）
.venv/bin/pytest tests/core/agents/swarm/injection/ -q

# SmartCmdSSRFHunter 回帰確認
.venv/bin/pytest tests/core/agents/swarm/test_smart_cmd_ssrf.py -v
```

---

## 多視点レビュー 累積問題点サマリ（Rev.1〜Rev.3 + 専門家視点）

> 全レビューラウンドで発見した問題点の要点のみ。詳細は末尾「実装引き継ぎサマリ」参照。

### バグハンター視点：バイパス可能性（上位問題のみ）

| # | バイパス種別 | 対処 | 優先 |
|---|---|---|---|
| 1 | IP 表記バリエーション（16進/10進/IPv6-mapped） | `BYPASS_VARIANTS` 定数追加 | P0 |
| 2 | `redirect_params` が `url` を先取りして SSRF スキップ | `redirect_params` から `"url"` 削除 | P0 |
| 3 | `status==200+size>0` が FP 大量生成 | ベースライン差分判定に変更 | P0 |
| 4 | AWS IMDSv2 の `401` 応答を見逃す | `status==401` + エラー本文を VULN_INDICATORS に追加 | P1 |
| 5 | 多段 Redirect バイパス（1段のみ検出） | `_check_final_destination()` 追加 | P1 |
| 6 | パラメータ値が URL 形式の未検出 | `_build_unknown_hypotheses()` に値ベース URL 検出追加 | P1 |
| 7 | VULN_INDICATORS の JSON 形式・gzip 圧縮未対応 | JSON キー形式追加 + gzip デコード処理 | P1 |
| 8 | WAF バイパス（URLエンコードバリエーション） | `raw_mode` オプション追加 | P2 |
| 9 | HEADER_INJECTION 応答差分判定が不確実 | ステータスコード差分判定に変更 | P2 |
| 10 | gopher/dict スキームによる内部サービス攻撃 | スコープ外（Future） | Future |

### SRE 視点：致命的ネットワーク・スケーラビリティ問題

| # | 問題 | 影響 | 対処 |
|---|---|---|---|
| SRE1 | ペイロード爆発（40件×10パラメータ×10秒） | 4.6日/100URL → 実運用不能 | `quick_mode=True` デフォルト化、1URL30リクエスト以内 |
| SRE2 | `asyncio.to_thread` + `AsyncClient` 混在 | `RuntimeError` 確定クラッシュ | `scan_async()` を純粋 async に統一、`to_thread` 廃止 |
| SRE3 | `self.results` 非スレッドセーフ | Finding 欠落・混入（silent fail） | `run_as_tool()` ごとに `SSRFTester` 新規生成 |
| SRE4 | 接続プール枯渇でハング | `InjectionManager` 全体ハング | `asyncio.Semaphore` でコルーチン数制御 |
| SRE5 | タイミング差分方式がクラウド環境で崩壊 | ポートスキャン検出率ゼロ | エラー種別差分（`RemoteProtocolError` vs `ConnectError`）に変更 |

### アーキテクト視点：致命的設計問題

| # | 問題 | 致命的影響 | 対処 |
|---|---|---|---|
| A1 | `SSRFTester` 責務過多（ペイロード定義・判定・HTTP送信を全包含） | OOB/LLM 拡張で連鎖変更 | 純粋 HTTP プローブクライアントに縮小 |
| A2 | `specialist_map["ssrf"]` 変更の全参照箇所未確認 | SSRF タスクがサイレントスキップ | `manager.py` 全参照フロー追跡（grep 必須） |
| A3 | `run_as_tool()` dict が `haddix_formatter` と無検証結合 | 新規キー欠如で `KeyError` クラッシュ | `SSRFToolOutput(TypedDict, total=False)` を `ssrf_types.py` に定義 |
| A4 | `_classify_url()` 挿入が依存順序を永続固定 | 将来拡張で優先順が壊れても検出不可 | `CATEGORY_PRIORITY` テーブル駆動化（Phase B-2b） |
| A5 | `SSRFPayloadType` が Scanner Core に束縛 | 全レイヤー波及・スキャナー差し替え不可 | `ssrf_types.py` に分離（**最初に作成する**） |

### QA 視点：致命的 FP/FN・テスト容易性問題

| # | 問題 | 致命的影響 | 対処 |
|---|---|---|---|
| Q1 | Flask テストが実装の正しさを保証しない | L2 全通過でも実アプリ検出を保証しない | L2a（Flask）/ L2b（実環境スモーク）に分離 |
| Q2 | `status==200+size>0` が FP 大量生成 | レポート信頼性ゼロ | ベースライン差分判定に変更 |
| Q3 | `httpx.Client.get` モックが実装詳細に依存 | 非同期化で L1 全15件が一斉破損 | `respx` + `probe()` レベルモックに変更 |
| Q4 | FP 1件で URL 全体が `vulnerable=True` に | FP が Finding→レポートまで連鎖伝播 | `CONFIDENCE_WEIGHTS` 確信度スコア判定 |
| Q5 | `conftest.py` スコープ未定義 | 既存テストへの mock 干渉でデグレ検出不能 | `injection/` 配下 `scope="function"` に限定 |

### CTO 視点：Recon SSRF アタックサーフェス発見の問題

| # | 問題 | 見逃す攻撃面 | 対処 |
|---|---|---|---|
| R1 | 認証後エンドポイントがクロール対象外 | 最高価値 SSRF 全欠落 | 認証済みクロールモード追加 |
| R2 | JS 動的生成 URL が未発見 | SPA の 80% が未カバー | katana `-js-crawl` または JS 静的解析 |
| R3 | `match_on: body` の TaggingFilter 実装が未確認 | POST ボディ SSRF 全見逃し | §0 事前確認に `grep` 追加（実装前必須） |
| R4 | API スペック（OpenAPI/GraphQL）未解析 | 明示エンドポイント見逃し | `openapi_spec_discoverer` 追加（将来） |
| R5 | パラメータ名ベースのみ・値ベース検出なし | 汎用パラメータ名 SSRF 全体 | `ssrf_value_hint`（`match_on: param_value`）追加 |
| R6 | `ssrf_path_hint` 部分一致 FP | Recon ノイズ増大 | パスセグメント境界アンカー追加 |
| R7 | GET のみプローブで POST SSRF が全 FN | Webhook/インポート系エンドポイント | `methods=["GET","POST"]` デフォルト化 |
| R8 | タグ付き/なしパスで二重処理が発生 | `SmartSSRFHunter` が同一 URL に 2 回実行 | `completed_urls` が両パスをカバーすることを B2-4 に明記 |

> **CTO 総評**: 現 Recon は全 SSRF 攻撃面の **20〜30% しかカバーできない**。R1/R2/R3/R5 が最優先。

### CTO 実現性・難易度・適合性 総合評価（後述 §実装引き継ぎサマリ参照）

---

### 更新後の実装順序（Rev.3 確定版）

```
Step 1:  §0.7 SmartCmdSSRFHunter VulnType 確認（grep）
Step 2:  §0.8 specialist_map 変更影響確認（manager.py 全参照フロー追跡）
Step 3:  §0.9 completed_urls 型確認（grep manager.py）
Step 4:  §0.10 match_on: body 実装確認（grep TaggingFilter）
Step 5:  §0.11 respx 追加確認（requirements.txt）
Step 6:  ssrf_types.py 新規作成（SSRFPayloadType/SSRFResult/SSRFToolOutput）← 最初に実施
Step 7:  settings.py に ssrf_* キー追加
Step 8:  B2-1 SSRFTester 純粋プローブクライアントに縮小
           - SSRFPayloadType: FILE_PROTOCOL 削除、LOCALHOST_PORT_SCAN/HEADER_INJECTION 追加
           - _test_payload() → probe() に改名・httpx 実装（後方互換維持）
           - _detect_by_timing_diff() エラー種別差分方式（RemoteProtocolError vs ConnectError）
           - ベースライン差分判定（http://127.0.0.1/nonexistent_ssrf_check_404）
           - SSRFResult.injected_header フィールド追加（Optional[str] = None）
           - timeout 時 None 返却、timeout_count 別カウント
           - request_delay/jitter（settings 連動）
Step 9:  B2-2 SmartSSRFHunter 新規作成
           - AsyncClient 遅延初期化（_get_client()）、外部注入対応（async_client=None）
           - asyncio.Semaphore(max_concurrency) でコルーチン数制御
           - CONFIDENCE_WEIGHTS 確信度スコア判定（閾値 0.6）
           - quick_mode=True デフォルト（LOCALHOST_PORT_SCAN を quick_mode 時無効化）
           - run_as_tool() ごとに SSRFTester 新規生成（非スレッドセーフ対策）
           - run_as_tool() に timeout_count / dns_rebinding_skipped / injected_header 含める
Step 10: B2-3 tagging_rules 追加
           - ssrf_param_hint / ssrf_body_hint（body 実装確認後）/ ssrf_path_hint（境界アンカー）
           - ssrf_value_hint（match_on: param_value, pattern: "^https?://"）← 新規追加
Step 11: B2-4 InjectionManager 最小配線
           - ssrf_candidate チェックを redirect_params チェックより前に挿入
           - redirect_params から "url" を削除
           - specialist_map["ssrf"] = "ssrf" に変更（全参照確認後）
           - PER_URL_TIMEOUT_BY_TYPE["ssrf"] = 300
           - run_ssrf_hunter() スケルトン（methods=["GET","POST"]、quick_mode=True デフォルト）
Step 12: B2-5 ReconPipeline 統合
Step 13: tests/helpers/ に ssrf_port_helper.py 追加
Step 14: tests/core/agents/swarm/injection/conftest.py に mock_ssrf_client fixture 追加（respx, scope="function"）
Step 15: B2-6 テスト（L1: 15件 respx使用, L2: 4件+bypass, L3: 11件以上, L4: CIA 期待値含む）
Step 16: haddix_formatter（SSRF CIA: C:High/I:Low, detection_method 分岐、SSRFToolOutput.get() 使用）
Step 17: 回帰テスト確認（SmartCmdSSRFHunter 影響なし確認含む）
```

---

## CTO 総合評価サマリ

| タスク | 実現性 | 難易度 | 適合性 | 致命的リスク |
|---|---|---|---|---|
| B2-1 SSRFTester 強化 | 中 | 中〜高 | 高 | ポートスキャン方式が環境依存で動かない（SRE5） |
| B2-2 SmartSSRFHunter | 中〜低 | 高 | 高 | 非同期デッドロック + 責務逆転（SRE2, A1） |
| B2-3 tagging_rules | 高 | 低 | 高 | body マッチ未実装の可能性（R3） |
| B2-4 InjectionManager | 低〜中 | 最高 | 中 | 既存 SQLi/XSS 検出への副作用（A2） |
| B2-5 ReconPipeline | 中 | 低〜中 | 高 | Recon の根本的発見能力不足（R1〜R8） |
| B2-6 テスト | 中 | 中 | 高 | テストが実装詳細依存で全壊リスク（Q3） |

### 推奨：Phase B-2a / B-2b の2フェーズ分割

**Phase B-2a（確実に動く最小実装）**
```
ssrf_types.py 新規作成 → SSRFTester 縮小 → SmartSSRFHunter（CLOUD_METADATA+LOCALHOST のみ）
→ ベースライン差分判定 → CONFIDENCE_WEIGHTS → tagging_rules → InjectionManager 最小配線
→ respx L1 テスト10件
```

**Phase B-2b（拡張実装）**
```
LOCALHOST_PORT_SCAN（エラー種別差分） → HEADER_INJECTION → L2a/L2b/L3/L4 テスト
→ CATEGORY_PRIORITY テーブル駆動化 → Recon R1/R2/R5 対処
```

---

## 実装引き継ぎサマリ（次のチャットで実装を開始する人へ）

> このセクションは本チャット（レビュー専用）で発見した問題点・リスク・判断経緯の全量を、初めて読む人が計画書全体を読まずに把握できる形で要約したもの。

---

### 1. 計画書の位置づけと現状

- **タスクID**: SGK-2026-0220、計画書: `docs/shigoku/plans/2026-05-19_sgk-2026-0220_b-2-ssrf-tester_plan.md`
- **目的**: 既存のプレースホルダー `SSRFTester` を実際に動く SSRF 検出器に仕上げ、`SmartSSRFHunter` Specialist として `InjectionManager` に統合する
- **関連ファイル**:
  - `src/core/attack/ssrf_tester.py` — コア（現在プレースホルダー）
  - `src/core/agents/swarm/injection/manager.py` — 配線先（3,800行超の巨大ファイル）
  - `src/core/agents/swarm/injection/smart_ssrf.py` — 新規作成する Specialist
  - `config/tagging_rules.yaml` — SSRF タグルール追加
  - `src/core/config/settings.py` — 新規キー追加必要（計画書当初未記載）
- **この計画書は Rev.3 まで4回の多視点レビューを経ており、実装前に必ず本サマリを読むこと**

---

### 2. 実装前に必ず実施する事前確認（§0 拡張版）

```bash
# 1. VulnType.SSRF の定義確認
grep -n 'SSRF' src/core/models/vulnerability.py

# 2. specialist_map の "ssrf" 全参照確認（変更前に全箇所を把握）
grep -n '"ssrf"' src/core/agents/swarm/injection/manager.py
grep -n 'specialist_map\|resolve_specialist' src/core/agents/swarm/injection/manager.py

# 3. completed_urls の型（set/list）確認（SmartSSRFHunter の実装に合わせる）
grep -n 'completed_urls' src/core/agents/swarm/injection/manager.py

# 4. match_on: body が TaggingFilter に実装済みか確認（未実装なら ssrf_body_hint は追加不可）
grep -rn 'match_on.*body\|body.*match_on' src/core/agents/swarm/

# 5. respx が requirements に含まれるか確認（L1テスト用）
grep 'respx' requirements*.txt pyproject.toml 2>/dev/null || echo "要追加"
```

---

### 3. 最優先で解決すべき致命的問題（実装開始前に設計確定が必要）

**【P0-CRITICAL】実装の根底を変える問題 — これを解決せずに実装すると後で全書き直し**

- **Arch A1（責務逆転）**: `SSRFTester` がペイロード定義・判定・HTTP送信を全包含している。他の Specialist（SQLi/XSS）は「Scanner Core = 純粋HTTP」「Specialist = 判定」に分離している。この逆転を放置すると将来の OOB/LLM 拡張時に連鎖変更が発生する。→ **`ssrf_types.py` を先に作成し、`SSRFPayloadType`/`SSRFResult`/`SSRFToolOutput(TypedDict)` をそこに定義してから他ファイルを実装する**
- **Arch A5（Enum 束縛）**: `SSRFPayloadType` が `ssrf_tester.py` に定義されているとすべてのレイヤーが Scanner Core に依存する。→ **`src/core/attack/ssrf_types.py`（新規）を最初に作成する**
- **SRE #2（デッドロック）**: `asyncio.to_thread()` 内から `async def _detect_by_timing_diff()` を呼ぶと `RuntimeError` 確定。→ **`scan_async()` を純粋 async に統一し `to_thread` を廃止。同期 `test()` は `asyncio.run(scan_async())` で実装**
- **Arch A3（formatter クラッシュ）**: `run_as_tool()` 返却 dict の新規キー（`dns_rebinding_skipped`, `injected_header`）が `quick_mode=True` 時や非 HEADER_INJECTION 時に存在しないと `haddix_formatter` が `KeyError` クラッシュ。→ **`SSRFToolOutput(TypedDict, total=False)` で全フィールドをオプショナル化し `.get()` でアクセス**

**【P0-DETECTION】これを解決しないと検出器として機能しない**

- **QA Q2（FP 爆発）**: `status==200 + size>0` の判定では `127.0.0.1:8080` が正規転送しているだけで全リクエストが FP になる。→ **`http://127.0.0.1/nonexistent_ssrf_check_404` をベースラインとして先行取得し、実ペイロードとの差分（status または size 差 >50B）を判定基準にする**
- **SRE #5（ポートスキャン崩壊）**: `http://127.0.0.1:99999/` はポート不正（最大65535）で httpx がソケット生成前にエラー → タイミング差分がゼロ。クラウド環境では全ポートが即時 ECONNREFUSED。→ **タイミング差分を廃止し、`httpx.RemoteProtocolError`（サービス存在 = SSH/Redis が HTTP と異なるプロトコルで応答）vs `httpx.ConnectError`（拒否）のエラー種別差分方式に変更**
- **QA Q4（FP 連鎖）**: `any(r.vulnerable for r in results)` では40ペイロード中1件の FP で URL全体が `vulnerable=True` になりレポートに伝播。→ **`CONFIDENCE_WEIGHTS = {CLOUD_METADATA: 1.0, LOCALHOST: 0.6, INTERNAL_IP: 0.4, HEADER_INJECTION: 0.7}` で重み付けし最高スコア ≥ 0.6 の場合のみ Finding 生成**

---

### 4. 実装時の重要な注意事項

**非同期設計**
- `SmartSSRFHunter` インスタンスは `run_as_tool()` ごとに新規生成すること（`self.results` の非スレッドセーフ問題、SRE#3）
- `AsyncClient` は `_get_client()` async メソッドで遅延初期化（`__init__` での生成禁止）
- `asyncio.gather()` に渡す前に `asyncio.Semaphore(max_concurrency)` でコルーチン数を制限（接続プール枯渇防止、SRE#4）
- `PER_URL_TIMEOUT_BY_TYPE["ssrf"] = 300`（ポートスキャン分を考慮、`manager.py` で設定）

**`InjectionManager` 変更の注意**
- `specialist_map["ssrf"] = "ssrf"` 変更前に `grep -n '"ssrf"' manager.py` で全参照箇所を確認すること
- `SmartCmdSSRFHunter`（`specialists["cmd_ssrf"]`）は独立しており競合しないが、変更後の回帰テストで確認必須
- `_classify_url()` への `ssrf_candidate` チェック挿入は `redirect_params` チェック（L275付近）より前に挿入
- `CATEGORY_PRIORITY` テーブル駆動化は Phase B-2b に延期推奨（B2-4 の工数過重を防ぐ）

**テスト設計**
- `unittest.mock.patch("httpx.Client.get")` は使わない（非同期化後に全壊するため）→ `respx` ライブラリを使うか `probe()` メソッド自体をモック
- `conftest.py` は `tests/core/agents/swarm/injection/conftest.py` に配置（ルートに置くと既存テストへの干渉が発生）
- fixture は `scope="function"` を明示

**Recon の根本的限界（Phase B-2b 以降の課題）**
- 現 Recon が `ssrf_candidate` を発見できるのは全 SSRF 攻撃面の約20〜30%のみ
- 最優先改善4点: ①認証済みクロールモード、②katana `-js-crawl`、③`match_on: body` 実装確認、④`ssrf_value_hint`（値ベース検出）
- `ssrf_value_hint`（`match_on: param_value`, `pattern: "^https?://"`）は Phase B-2a で追加可能かつ効果大

---

### 5. SSRFPayloadType 確定版（実装時の参照用）

```python
class SSRFPayloadType(str, Enum):
    CLOUD_METADATA      = "cloud_metadata"
    LOCALHOST           = "localhost"
    LOCALHOST_PORT_SCAN = "localhost_port_scan"  # quick_mode=True 時は無効
    INTERNAL_IP         = "internal_ip"
    HEADER_INJECTION    = "header_injection"
    DNS_REBINDING       = "dns_rebinding"        # settings.ssrf_dns_rebinding_domain 設定時のみ
    # FILE_PROTOCOL は削除（httpx 非対応）
```

---

### 6. 新規作成ファイル一覧（計画書本文から追加されたもの）

| ファイル | 目的 | 優先 |
|---|---|---|
| `src/core/attack/ssrf_types.py` | `SSRFPayloadType`/`SSRFResult`/`SSRFToolOutput` の定義元 | P0 |
| `src/core/agents/swarm/injection/smart_ssrf.py` | `SmartSSRFHunter` Specialist | P0 |
| `tests/core/agents/swarm/injection/test_smart_ssrf.py` | L1 テスト（respx 使用） | P0 |
| `tests/core/agents/swarm/injection/conftest.py` | `mock_ssrf_client` fixture（injection スコープ限定） | P0 |
| `tests/helpers/ssrf_port_helper.py` | `socketserver.TCPServer` でポート開放/閉鎖制御 | P1 |

---

### 7. 変更ファイル一覧（当初計画書から追加されたもの含む）

| ファイル | 主な変更 |
|---|---|
| `src/core/attack/ssrf_tester.py` | `FILE_PROTOCOL` 削除、`LOCALHOST_PORT_SCAN`/`HEADER_INJECTION` 追加、`_detect_by_timing_diff()` エラー種別差分方式、ベースライン差分判定、`CONFIDENCE_WEIGHTS` |
| `src/core/agents/swarm/injection/manager.py` | `ssrf_candidate` チェック挿入、`specialist_map["ssrf"]` 変更、`PER_URL_TIMEOUT_BY_TYPE["ssrf"]=300` |
| `config/tagging_rules.yaml` | `ssrf_param_hint`/`ssrf_body_hint`/`ssrf_path_hint`/`ssrf_value_hint` 追加 |
| `src/core/config/settings.py` | `ssrf_max_concurrency`, `ssrf_request_delay`, `ssrf_jitter`, `ssrf_dns_rebinding_domain`, `ssrf_crawl_depth` 追加 |
