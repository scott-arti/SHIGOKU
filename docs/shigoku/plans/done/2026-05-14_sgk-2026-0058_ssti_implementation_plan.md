---
task_id: SGK-2026-0058
doc_type: plan
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/subtasks/done/2026-05-19_sgk-2026-0171_phase1_tasks.md
- docs/shigoku/reports/REPORT_OUTPUTS.md
- docs/shigoku/worklogs/2026-05-14_log_codex_chat_summary.md
created_at: '2026-05-14'
updated_at: '2026-07-02'
---

# SSTI Detection Implementation Plan
**作成日**: 2026-05-14  
**対象バージョン**: Ver.1 追加機能（SCN01-07精度・安定性工場に影響しない範囲）  
**優先度**: Phase A-1（最優先 Quick Win）

---

## 1. 背景・動機

### 現状の問題

SSTIはBug Bountyでのインパクトが高い（Critical級）にもかかわらず、SHIGOKUでは**実行経路がゼロ**。

| チェックポイント | 現状 |
|---|---|
| `tagging_rules.yaml` にSSTIパターン | ❌ なし |
| `_classify_url()` が `"ssti"` を返すケース | ❌ なし |
| `_build_unknown_hypotheses()` が `ssti` 仮説を生成 | ❌ なし |
| `specialist_map` に `"ssti"` キー | ❌ なし |
| `specialists` dict に SSTI ハンター | ❌ なし |
| `_run_unknown_hypothesis_scans()` に ssti 分岐 | ❌ なし |

`SSTIScanner`（`src/core/attack/ssti_scanner.py`）は HTTP リクエスト送信まで実装済みだが、
`InjectionManager` から呼ばれる経路が一切なく、かつ `asyncio` 非対応・auth 渡し未対応という問題もある。

また `template` パラメータは現状 `lfi` として**誤分類**される（`lfi_keys` に含まれる）。

### 実装後に期待できること

- Flask/Jinja2, Ruby/ERB, Java/Thymeleaf/FreeMarker, PHP/Twig/Smarty, Python/Mako などの SSTI を自動検出
- Recon のタグ付けから InjectionManager → SmartSSTIHunter まで実行経路が繋がる
- 検出結果が `VulnType.SSTI` の `Finding` として Haddix レポートに記録される

---

## 2. 実装しないこと（スコープ外）

- ブラインドSSTI（time-based / OOB）— 現時点はスコープ外。OOB連携は将来フェーズ
- SSTI to RCE Exploitation — 非破壊方針を維持、算術演算確認のみ
- WebSocket 経由の SSTI — WebSocketTester 実装前提のため後回し
- SCN01-07 既存スペシャリスト（SQLi/XSS/LFI/Cmd/Redirect）の変更 — 本実装は追加のみ

---

## 3. 実装タスク詳細

### タスク A1-1: `SSTIScanner` 安全化・強化
**ファイル**: `src/core/attack/ssti_scanner.py`

#### 変更内容
1. **Velocity RCEペイロード削除・置換**  
   `"$class.inspect('java.lang.Math').type.pow(7,2)"` は事実上のRCEペイロードで非破壊原則違反。  
   → `"#set($x=7*7)$x"` のみに絞る

2. **`_send_request()` に auth headers 引数追加**  
   ```python
   def _send_request(self, url, parameter, payload, method,
                     auth_headers: dict | None = None) -> Optional[httpx.Response]
   ```
   `httpx.Client` のデフォルトヘッダーに `Cookie` / `Authorization` を注入する

3. **`scan()` / `scan_with_fingerprint()` に `auth_headers` 引数追加**  
   呼び出し元から認証情報を受け取れるようにする

4. **`scan_async()` メソッド追加**  
   ```python
   async def scan_async(self, url, parameters, method="GET",
                        engines=None, auth_headers=None) -> List[SSTIResult]:
       return await asyncio.to_thread(
           self.scan, url, parameters, method, engines, False, auth_headers
       )
   ```
   InjectionManager（非同期）から呼べるようにする

5. **JSON ボディ対応**  
   `_send_request()` の `method` が `"JSON"` の場合、`client.post(url, json={parameter: payload})` を使用

#### 合格基準
- `test_ssti_scanner.py` の既存テストがすべて GREEN のまま
- `scan()` に `auth_headers={"Cookie": "session=test"}` を渡すと `httpx.Client` のリクエストヘッダーに Cookie が含まれること（モックで確認）
- Velocity ペイロードセットに `$class.inspect` が含まれないこと

---

### タスク A1-2: `tagging_rules.yaml` に SSTI ルール追加
**ファイル**: `config/tagging_rules.yaml`

#### 追加ルール
```yaml
  - name: ssti_path_hint
    tag: ssti_candidate
    match_on: path
    pattern: "(tpl|render|template_engine|jinja|freemarker|thymeleaf|velocity|smarty|mako|blade)"

  - name: ssti_param_hint
    tag: ssti_candidate
    match_on: query
    pattern: "(^|[?&])(template|tpl|view_name|layout|theme|engine)="
    param_extract: 2

  - name: ssti_body_hint
    tag: ssti_candidate
    match_on: body
    pattern: "(^|&)(template|tpl|view_name|layout|theme|engine)="
    param_extract: 2
```

#### 注意点
- `file_param_query` ルールは `template` パラメータにもマッチするため、
  `ssti_candidate` と `file_param` の二重タグが付く場合がある。
  `_classify_url()` で `ssti_candidate` を `lfi` より先に評価することで対処（A1-3参照）

#### 合格基準
- `/render/page` というパスのURLに `ssti_candidate` タグが付く
- `?template=foo` クエリパラメータに `ssti_candidate` タグが付く
- 既存の `sqli_path_hint` / `xss_path_hint` の動作が変わらない

---

### タスク A1-3: `_classify_url()` に ssti 分類追加
**ファイル**: `src/core/agents/swarm/injection/manager.py`

#### 変更箇所: `_classify_url()` メソッド（約 L194-L247）

```python
# category_hint チェックを既存の lfi より前に追加
if category_hint == "ssti_candidate":
    return "ssti"

# パス名ヒューリスティック（lfi 判定より前に配置）
if any(kw in path for kw in ["render", "tpl", "/template/", "jinja", "thymeleaf", "freemarker"]):
    return "ssti"
```

#### 重要: 配置順序
`lfi` ヒューリスティック（`"template"` がパスに含まれると `lfi` になる）より**前**に SSTI 判定を置くこと。

#### 合格基準
- `_classify_url("http://example.com/render?name=x", "ssti_candidate")` → `"ssti"`
- `_classify_url("http://example.com/tpl/page", "")` → `"ssti"`
- `_classify_url("http://example.com/file?path=../etc/passwd", "file_param")` → `"lfi"`（既存動作維持）

---

### タスク A1-4: `_build_unknown_hypotheses()` に ssti 仮説追加
**ファイル**: `src/core/agents/swarm/injection/manager.py`

#### 変更箇所: `_build_unknown_hypotheses()` メソッド（約 L476-L549）

1. `ssti_keys` セット定義を追加:
   ```python
   ssti_keys = {"template", "tpl", "view", "layout", "theme", "engine"}
   ```

2. 仮説生成ロジック追加（LFI 判定の**前**）:
   ```python
   if any(kw in path for kw in ["render", "/tpl", "/template/", "jinja", "thymeleaf"]) \
       or (all_param_keys & ssti_keys):
       hypotheses.append("ssti")
       signals.append("ssti_signal")
   ```

3. `specialist_map` に追加:
   ```python
   specialist_map = {
       "sqli": "sqli",
       "xss": "xss",
       "lfi": "lfi",
       "ssti": "ssti",      # ← 追加
       "ssrf": "cmd_ssrf",
       "api": "sqli",
       "csrf": "xss",
       "idor": "sqli",
   }
   ```

#### 合格基準
- `?template=foo` を含む URL で `"ssti"` 仮説が生成される
- `specialist_map` で `"ssti"` が `"ssti"` にマッピングされる
- `"ssti"` specialist が `specialists` dict にない場合、フィルタで除外されてエラーにならない

---

### タスク A1-5: `SmartSSTIHunter` 新規作成
**新規ファイル**: `src/core/agents/swarm/injection/smart_ssti.py`

#### 設計方針
- `SmartCmdSSRFHunter` / `SmartLFIHunter` と同じ構造パターンに従う
- LLM は使用しない（SSTIScanner が決定論的）
- `SSTIResult` → `Finding(VulnType.SSTI)` 変換を担当
- Fingerprinter の tech_stack 情報を受け取り `scan_with_fingerprint()` を使用

#### クラス構造（概略）

```python
class SmartSSTIHunter(Specialist):
    name = "SmartSSTIHunter"
    description = "Deterministic SSTI scanner using arithmetic confirmation pairs"
    timeout_seconds = 150
    is_aggressive = False

    def __init__(self, config=None):
        super().__init__(config)
        self.last_tested_params: List[str] = []

    async def run_as_tool(self, url: str, params: dict = None, **kwargs) -> dict:
        """InjectionManager から呼ばれるエントリポイント"""
        # auth_headers 抽出
        # tech_stack 抽出（Recon 結果から）
        # SSTIScanner.scan_async() 呼び出し
        # last_tested_params 更新
        # 結果を dict で返す

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        """Specialist インターフェース"""
        result = await self.run_as_tool(task.target, task.params)
        return self._convert_to_findings(result, task.target)

    def _convert_to_findings(self, result: dict, target_url: str) -> List[Finding]:
        """SSTIResult → Finding 変換"""
        # VulnType.SSTI, Severity.CRITICAL
        # additional_info: engine, payload, confidence, tested_params
```

#### `run_as_tool` の返却形式

```python
{
    "vulnerable": bool,
    "findings_count": int,
    "tested_params": List[str],
    "engine": str,           # TemplateEngine.value
    "payload": str,
    "confidence": float,
    "evidence": str,
}
```

#### 合格基準
- `run_as_tool` が `vulnerable=True` を返すとき、`execute()` が `VulnType.SSTI` の `Finding` を返す
- `run_as_tool` が `vulnerable=False` を返すとき、`execute()` が空リストを返す
- `last_tested_params` が更新される
- `additional_info["tested_params"]` に内部制御パラメータ（`scan_profile`, `_auth` 等）が含まれない

---

### タスク A1-6: `InjectionManager` 配線（5 箇所）
**ファイル**: `src/core/agents/swarm/injection/manager.py`

#### 変更 1: `_initialize_specialists()` — SmartSSTIHunter 登録

```python
# SmartSSTIHunter
try:
    from src.core.agents.swarm.injection.smart_ssti import SmartSSTIHunter
    self.specialists["ssti"] = SmartSSTIHunter(config=self.config)
except ImportError:
    logger.warning("SmartSSTIHunter not available")
```

#### 変更 2: `_register_manager_tools()` — ツール登録

```python
if "ssti" in self.specialists:
    self.register_tool(
        "ssti_scan",
        self.run_ssti_hunter,
        "SSTI (Server-Side Template Injection) 脆弱性の決定論的スキャンを実行します。"
    )
```

#### 変更 3: `PER_URL_TIMEOUT_BY_TYPE` — タイムアウト設定

```python
PER_URL_TIMEOUT_BY_TYPE: Dict[str, int] = {
    "sqli": 180,
    "xss": 210,
    "lfi": 120,
    "ssti": 150,      # ← 追加（確認ペアテスト2回分を考慮）
    "redirect": 90,
    "cmd_ssrf": 180,
    "unknown": 120,
}
```

#### 変更 4: `run_ssti_hunter()` メソッド追加

```python
async def run_ssti_hunter(self, url: str, params: dict = None,
                          quick_mode: bool = False, **_kwargs) -> dict:
    if "ssti" not in self.specialists:
        return {"error": "SSTI Specialist not available"}
    logger.info("[%s] Delegating SSTI check to SmartSSTIHunter", self.name)
    effective_params = self._normalize_tool_supplied_params(params, _kwargs)
    result = await self.specialists["ssti"].run_as_tool(url, effective_params)
    findings_count = result.get("findings_count", 0)
    if findings_count > 0:
        for f in self.current_context.get("findings", [])[-findings_count:]:
            pass  # Finding は SmartSSTIHunter.execute() 経由で登録される
    return result
```

#### 変更 5: `_run_unknown_hypothesis_scans()` — ssti 分岐追加

```python
elif specialist == "ssti":
    ssti_result = await self.run_ssti_hunter(
        url=url, params=base_params, quick_mode=quick_mode
    )
    unknown_results.append(ssti_result)
```

#### 変更 6: `_resolve_risk_force_allowlist()` — ssti 追加

```python
allow = {"sqli", "cmd_ssrf", "lfi", "csrf", "api", "redirect", "ssti"}
```

#### 合格基準
- `InjectionManagerAgent()` のインスタンス化時に `SmartSSTIHunter` が `specialists["ssti"]` に登録される
- `run_ssti_hunter()` が `SmartSSTIHunter.run_as_tool()` に委譲する
- `_run_unknown_hypothesis_scans()` で `"ssti"` specialist が選ばれたとき `run_ssti_hunter` が呼ばれる

---

### タスク A1-7: テスト
**新規ファイル**: `tests/core/agents/swarm/injection/test_smart_ssti.py`

---

### タスク A1-8: Recon ルーティング確認
**確認ファイル**: `src/recon/pipeline.py` / `src/core/engine/swarm_dispatcher.py`

`ssti_candidate` タグが `InjectionManagerAgent` タスクとして正しく生成されるかを追跡し、
必要なら `SwarmDispatcher` のタグ→エージェントマッピングを補完する。

---

## 4. テスト方針・合格基準（詳細）

### 4.1 テストレベル

```
L1: ユニットテスト（モック使用、依存なし）
L2: 統合テスト（SSTIScanner実HTTP、最小Flaskターゲット使用）
L3: 回帰テスト（既存スペシャリストへの影響なし確認）
L4: E2Eスモーク（InjectionManager→SmartSSTIHunter経路確認）
```

### 4.2 L1: ユニットテスト（`tests/core/agents/swarm/injection/test_smart_ssti.py`）

#### テストケース一覧

| テスト名 | 検証内容 | 合格基準 |
|---|---|---|
| `test_execute_returns_finding_when_vulnerable` | `run_as_tool` が `vulnerable=True` → Finding生成 | `len(findings) == 1`, `findings[0].vuln_type.value == "ssti"` |
| `test_execute_returns_empty_when_safe` | `run_as_tool` が `vulnerable=False` → 空リスト | `findings == []` |
| `test_finding_severity_is_critical` | SSTIはCritical | `findings[0].severity == Severity.CRITICAL` |
| `test_finding_has_engine_in_additional_info` | エンジン情報が記録される | `findings[0].additional_info["engine"] == "jinja2"` |
| `test_tested_params_excludes_control_params` | 内部制御パラメータが除外される | `"scan_profile"` and `"_auth"` not in `additional_info["tested_params"]` |
| `test_last_tested_params_updated_after_run` | `last_tested_params` が更新される | `hunter.last_tested_params == ["name"]` |
| `test_run_as_tool_initializes_result_shape` | 返却dictの形が正しい | `"vulnerable"`, `"findings_count"`, `"tested_params"`, `"engine"` が全てキーとして存在 |
| `test_auth_headers_forwarded_to_scanner` | auth cookiesがSSTIScannerに渡る | `SSTIScanner.scan_async` のcall_argsに `auth_headers={"Cookie": "..."}` が含まれる |
| `test_tech_stack_triggers_targeted_engines` | tech_stack → scan_with_fingerprint使用 | Django tech_stackで `engines=["jinja2"]` が渡される |

#### テストパターン（`test_smart_cmd_ssrf.py` 準拠）

```python
@pytest.mark.asyncio
async def test_execute_returns_finding_when_vulnerable():
    hunter = SmartSSTIHunter(config={"model": "test-model"})
    hunter.run_as_tool = AsyncMock(return_value={
        "vulnerable": True,
        "findings_count": 1,
        "param": "name",
        "engine": "jinja2",
        "payload": "{{7*7}}abc123",
        "confidence": 0.95,
        "evidence": "Result: 49abc123",
        "tested_params": ["name"],
    })
    task = Task(
        id="ssti-vuln",
        name="ssti",
        target="http://example.com/greet?name=world",
        params={"name": "world"},
    )
    findings = await hunter.execute(task)

    assert len(findings) == 1
    assert findings[0].vuln_type.value == "ssti"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].additional_info.get("engine") == "jinja2"
    assert findings[0].additional_info.get("tested_params") == ["name"]
```

### 4.3 L1: `_classify_url()` 単体テスト（`test_injection_manager.py` 追記）

| テスト名 | 入力 | 期待出力 |
|---|---|---|
| `test_classify_url_ssti_candidate_category` | url=`/greet`, category=`"ssti_candidate"` | `"ssti"` |
| `test_classify_url_render_path` | url=`/render/page`, category=`""` | `"ssti"` |
| `test_classify_url_tpl_path` | url=`/tpl/view`, category=`""` | `"ssti"` |
| `test_classify_url_template_param_not_lfi` | url=`/page?template=foo`, category=`"ssti_candidate"` | `"ssti"` （lfi でない） |
| `test_classify_url_file_param_still_lfi` | url=`/view?file=doc.pdf`, category=`"file_param"` | `"lfi"` （既存動作維持） |

### 4.4 L1: `_build_unknown_hypotheses()` 単体テスト

| テスト名 | 入力 | 期待出力 |
|---|---|---|
| `test_hypotheses_ssti_signal_from_template_param` | query_keys=`{"template"}` | `"ssti"` が hypotheses に含まれる |
| `test_hypotheses_ssti_signal_from_render_path` | path=`/render` | `"ssti"` が hypotheses に含まれる |
| `test_specialist_map_ssti_maps_to_ssti` | hypotheses=`["ssti"]` | `selected_specialists == ["ssti"]` |

### 4.5 L1: `SSTIScanner` 安全化テスト（`tests/test_ssti_scanner.py` 追記）

| テスト名 | 検証内容 | 合格基準 |
|---|---|---|
| `test_velocity_payload_no_rce` | Velocity ペイロードにRCE命令がない | `"$class.inspect"` が Velocity ペイロードに含まれない |
| `test_scan_with_auth_headers_forwarded` | auth_headers が httpx リクエストに含まれる | `mock_send` の call_args headers に Cookie が含まれる |
| `test_scan_async_returns_list` | `scan_async()` が `List[SSTIResult]` を返す | `isinstance(result, list)` かつ `asyncio` で実行可能 |

### 4.6 L2: 統合テスト（最小 Flask SSTI ターゲット）

#### テストターゲット設計

```python
# tests/helpers/ssti_flask_target.py
from flask import Flask, request
from jinja2 import Environment

app = Flask(__name__)

@app.route("/greet")
def greet():
    """Jinja2 SSTI 脆弱エンドポイント（テスト用）"""
    name = request.args.get("name", "World")
    env = Environment()
    template = env.from_string(f"Hello {name}!")
    return template.render()

@app.route("/safe")
def safe():
    """安全なエンドポイント（SSTI なし）"""
    name = request.args.get("name", "World")
    return f"Hello {name}!"

if __name__ == "__main__":
    app.run(port=15555, debug=False)
```

#### 統合テストケース（`@pytest.mark.integration` マーカー）

| テスト名 | 内容 | 合格基準 |
|---|---|---|
| `test_ssti_scanner_detects_jinja2_live` | Flaskターゲットの `/greet?name={{7*7}}` を検出 | `result.vulnerable == True`, `result.engine == TemplateEngine.JINJA2` |
| `test_ssti_scanner_no_false_positive_on_safe` | `/safe` エンドポイントで陰性 | `scanner.get_vulnerable_count() == 0` |
| `test_ssti_confirmation_pair_prevents_false_positive` | `49` がレスポンスに含まれるが SSTI でないケース | ユニークマーカー方式により false positive にならない |

#### 実行方法

```bash
# Flask ターゲット起動（テスト前）
python tests/helpers/ssti_flask_target.py &

# 統合テストのみ実行
.venv/bin/pytest tests/core/agents/swarm/injection/test_smart_ssti.py \
  -m integration -v

# 終了後 kill
kill %1
```

### 4.7 L3: 回帰テスト（既存スペシャリストへの影響なし）

以下のテストが既存のまま全 GREEN であること：

```bash
.venv/bin/pytest tests/test_ssti_scanner.py -v
.venv/bin/pytest tests/core/agents/swarm/test_injection_manager.py -v
.venv/bin/pytest tests/core/agents/swarm/injection/test_smart_lfi.py -v
.venv/bin/pytest tests/core/agents/swarm/test_smart_cmd_ssrf.py -v
.venv/bin/pytest tests/core/agents/swarm/test_smart_xss.py -v
```

確認ポイント：
- `template` パラメータを持つ URL が `"lfi"` と `"ssti"` に二重処理されない
- `SmartLFIHunter` が `ssti_candidate` タグの URL でも呼ばれない
- `PER_URL_TIMEOUT_BY_TYPE` に `ssti` を追加しても既存タイプのタイムアウトが変わらない

### 4.8 L4: E2E スモーク（InjectionManager 経由の実行経路）

#### スモークテストケース

```python
@pytest.mark.asyncio
async def test_injection_manager_routes_ssti_candidate_to_ssti_hunter():
    manager = InjectionManagerAgent(config={"model": "test-model"})
    manager.current_context = {"findings": []}
    manager.run_ssti_hunter = AsyncMock(return_value={
        "findings_count": 1,
        "tested_params": ["name"],
        "vulnerable": True,
        "engine": "jinja2",
    })

    result = await manager._process_single_url(
        url="http://example.com/render?name=test",
        vuln_type="ssti",
        base_params={"_auth": {"auth_headers": {}, "cookies": ""}},
        quick_mode=False,
    )

    manager.run_ssti_hunter.assert_called_once()
    assert result["findings_count"] == 1
```

---

## 5. 合格基準まとめ（チェックリスト形式）

### 機能合格基準

- [ ] `SSTIScanner.PAYLOADS["velocity"]` に `$class.inspect` が含まれない
- [ ] `SSTIScanner.scan()` が `auth_headers` 引数を受け取り httpx リクエストに適用する
- [ ] `SSTIScanner.scan_async()` が asyncio で正常動作する
- [ ] `tagging_rules.yaml` で `/render/` パスに `ssti_candidate` タグが付く
- [ ] `_classify_url()` で `"ssti_candidate"` category が `"ssti"` を返す
- [ ] `_classify_url()` で `/render` パスが `"ssti"` を返す（`lfi` より優先）
- [ ] `_build_unknown_hypotheses()` で `template` パラメータが `ssti` 仮説を生成する
- [ ] `SmartSSTIHunter` が `InjectionManager.specialists["ssti"]` に登録される
- [ ] `run_ssti_hunter()` が `SmartSSTIHunter.run_as_tool()` に委譲する
- [ ] SSTI Finding の `vuln_type` が `VulnType.SSTI` である
- [ ] SSTI Finding の `severity` が `Severity.CRITICAL` である
- [ ] SSTI Finding の `additional_info["tested_params"]` に `scan_profile`, `_auth` が含まれない
- [ ] `last_tested_params` が `SmartSSTIHunter` に実装されている

### テスト合格基準

- [ ] `tests/core/agents/swarm/injection/test_smart_ssti.py` の L1 テスト 9 件が全 GREEN
- [ ] `tests/test_ssti_scanner.py` の既存テスト + 追加 3 件が全 GREEN
- [ ] `test_injection_manager.py` の SSTI 分類テスト 5 件が全 GREEN
- [ ] `test_injection_manager.py` の `_build_unknown_hypotheses` SSTI テスト 3 件が全 GREEN
- [ ] L4 スモーク（`test_injection_manager_routes_ssti_candidate_to_ssti_hunter`）が GREEN
- [ ] 回帰テスト 5 ファイルが全 GREEN（既存スペシャリストへの影響なし）

### 非機能合格基準

- [ ] `ssti` タイムアウトが 150 秒（確認ペア2回 × ネットワーク往復を許容）
- [ ] `ssti_candidate` タグが付いた URL の処理が既存 `lfi` / `xss` タスクと競合しない
- [ ] `SmartSSTIHunter` の `is_aggressive = False`（非破壊宣言）

---

## 6. 実装順序と依存関係

```
A1-1 (SSTIScanner 強化)
    ↓
A1-5 (SmartSSTIHunter 新規作成)  ←── A1-1 に依存
    │
    ├── A1-2 (tagging_rules.yaml)  ←── 独立、並列実施可
    ├── A1-3 (_classify_url)        ←── 独立、並列実施可
    └── A1-4 (_build_unknown_hypotheses) ←── 独立、並列実施可
    ↓
A1-6 (InjectionManager 配線)  ←── A1-2〜A1-5 全て完了後
    ↓
A1-7 (テスト実装・実行)
    ↓
A1-8 (ReconPipeline ルーティング確認)
```

---

## 7. 次フェーズ候補（今回スコープ外）

本実装完了後、以下を検討：

| 候補 | 条件 |
|---|---|
| ブラインドSSTI（time-based） | SmartSQLiHunterのtime-based実装が安定してから |
| GraphQL Introspection 実実装 | A-1完了後、次のQuick Win |
| CORS 実実装 | A-1完了後 |
| CRLF 実実装 | A-1完了後 |

---

## 8. ファイル変更一覧

| ファイル | 変更種別 | タスク |
|---|---|---|
| `src/core/attack/ssti_scanner.py` | 修正 | A1-1 |
| `config/tagging_rules.yaml` | 修正 | A1-2 |
| `src/core/agents/swarm/injection/manager.py` | 修正 | A1-3, A1-4, A1-6 |
| `src/core/agents/swarm/injection/smart_ssti.py` | **新規作成** | A1-5 |
| `tests/core/agents/swarm/injection/test_smart_ssti.py` | **新規作成** | A1-7 |
| `tests/helpers/ssti_flask_target.py` | **新規作成** | A1-7 (L2統合テスト用) |
| `tests/test_ssti_scanner.py` | 追記 | A1-7 |
| `tests/core/agents/swarm/test_injection_manager.py` | 追記 | A1-7 |

---

## 9. 実装結果記録（2026-05-14 完了）

### 9.1 全タスク完了状況

| タスク | 状態 | 備考 |
|---|---|---|
| A1-1 SSTIScanner 安全化・強化 | ✅ 完了 | |
| A1-2 tagging_rules.yaml SSTI ルール追加 | ✅ 完了 | |
| A1-3 `_classify_url()` ssti 分類追加 | ✅ 完了 | |
| A1-4 `_build_unknown_hypotheses()` ssti 仮説追加 | ✅ 完了 | |
| A1-5 SmartSSTIHunter 新規作成 | ✅ 完了 | |
| A1-6 InjectionManager 配線 6箇所 | ✅ 完了 | `run_ssti_hunter()` 含む |
| A1-7 テスト実装 | ✅ 完了 | L1 9件 + L2 3件 + L3回帰 + L4 E2E |
| A1-8 ReconPipeline ルーティング確認・補完 | ✅ 完了 | `task_mapping` / `_map_tagged_category_to_tags` に `ssti_candidate` 追加 |

### 9.2 テスト最終結果

```
tests/core/agents/swarm/injection/test_smart_ssti.py   12 passed (L1 9件 + L2 3件)
tests/test_ssti_scanner.py                              36 passed (既存 32件 + 追加 4件)
tests/core/agents/swarm/test_injection_manager.py       29 passed, 1 skipped (追加 9件含む)
回帰テスト (LFI/Cmd/SQLi スペシャリスト)               全 GREEN
合計: 77 passed, 1 skipped
```

### 9.3 事後発見・修正した不具合

#### バグ1: `tagging_rules.yaml` — `template` パラメータの誤分類
- **発見**: 実動作確認時。`?template=foo` が `ssti_candidate` にならず `file_param` になっていた
- **原因**: `file_param_query` の pattern に `template` が混入していた
- **修正**: `file_param_query` pattern から `template` を削除。`ssti_param_hint` / `ssti_body_hint` に `template` を追加

#### バグ2: `SSTIScanner.PAYLOADS["mako"]` — 無効ペイロード
- **発見**: ペイロード充足性レビュー時
- **原因**: `<% 7*7 %>` は Mako では評価されない（出力なし）→ 確認ペアで必ず陰性
- **修正**: `<% 7*7 %>` → `${str(7*7)}`

#### バグ3: `SSTIScanner.PAYLOADS["handlebars"]` / `["mustache"]` — 確認ペア不成立
- **発見**: ペイロード充足性レビュー時
- **原因**: `{{#with 7}}{{this}}{{/with}}` は `7` を返すが演算ではない。確認ペア（8*6=48）が一致しないため必ず陰性になる
- **修正**: `{{7*7}}` に統一。Handlebars/Mustache は算術演算不可のため `universal` スキャン（`{{7*7}}`）と同一ペイロードで検出を試みる設計に変更

#### 改善: `use_encoding` / `tech_stack` の接続
- **発見**: 設計レビュー時。WAF 回避エンコードが InjectionManager から有効化できていなかった
- **修正**:
  - `SSTIScanner.scan_async()` に `use_encoding` 引数を追加
  - `SmartSSTIHunter.run_as_tool()` で `params["use_encoding"]` を読み取り転送
  - `run_ssti_hunter()` で `use_encoding` / `tech_stack` / `_context` を `effective_params` に組み立て、Recon fingerprint 結果をエンドツーエンドで接続

---

## 10. 未実装事項と判断基準

以下は本実装のスコープ外として意図的に除外した。将来実装する場合の判断基準を記録する。

### 10.1 ブラインドSSTI（time-based / OOB）

| 項目 | 内容 |
|---|---|
| **なぜ除外したか** | レスポンス出力がない環境での検出が必要だが、time-based は遅延計測の不安定性が高く誤検知リスクが大きい。OOB はコールバックインフラ（Caido IO / Burp Collaborator相当）が必要 |
| **実装条件** | OOB インフラが SHIGOKU に統合された後。SmartSQLiHunter の time-based 実装が安定して実績が出た後 |
| **実装時の注意** | delay=1.5〜3秒のペイロード（`{{range(1,10000000)|list}}`等）を使う。誤検知削減のため3回以上計測し中央値で判定する |

### 10.2 WAF 回避エンコードの自動有効化

| 項目 | 内容 |
|---|---|
| **現状** | `use_encoding=True` を渡せば有効化できる実装は完了済み。ただし InjectionManager はデフォルト `False` で呼ぶ |
| **なぜデフォルト False か** | エンコードバリアントを追加することでリクエスト数が 2〜3 倍になる。通常スキャンで不要なリクエストを増やしたくない |
| **有効化条件** | WAF 検出シグナル（429 / 403 応答パターン）を受けたとき、または `scan_profile="ctf"` / `scan_profile="aggressive"` 指定時に自動有効化するのが望ましい |

### 10.3 JSON body パラメータへの SSTI

| 項目 | 内容 |
|---|---|
| **現状** | `SSTIScanner._send_request()` は `method="JSON"` で `client.post(url, json={parameter: payload})` を実装済み |
| **問題** | `SmartSSTIHunter._extract_test_params()` が `method="JSON"` のときに body パラメータキーを抽出しない。URL クエリに頼っている |
| **実装条件** | InjectionManager が JSON body のパラメータキーを `params` に渡す仕組みができたとき（他スペシャリストと共通化が望ましい） |

### 10.4 ヘッダーインジェクション型 SSTI

| 項目 | 内容 |
|---|---|
| **現状** | 未対応。`User-Agent`, `X-Forwarded-Host`, `Referer` 等へのインジェクションは不可 |
| **実装条件** | ヘッダーベースのインジェクションを扱う共通レイヤーが InjectionManager に追加されたとき。他の脆弱性（SSRF のヘッダーインジェクション等）と同時に実装するのが効率的 |

### 10.5 Jinja2 Sandbox 回避検出

| 項目 | 内容 |
|---|---|
| **現状** | 未対応 |
| **なぜ除外したか** | Sandbox 回避は RCE に直結する破壊的アクション。非破壊方針（`is_aggressive=False`）に違反する |
| **実装条件** | 明示的に `is_aggressive=True` が設定された場合のみ実行するサブモジュールとして実装する。本番環境では原則無効 |

### 10.6 Handlebars / Mustache の算術確認

| 項目 | 内容 |
|---|---|
| **現状** | `{{7*7}}` ペイロードを使うが、これらのエンジンは算術演算を行わないため確認ペアで陰性になる（=**検出不可**） |
| **理由** | Handlebars/Mustache は Logic-less テンプレートエンジンで、数値計算式を評価しない設計。SSTI の影響度も Jinja2 等と比べて限定的 |
| **将来の対応案** | プロトタイプ汚染（`constructor.prototype`）を使った挙動の異常検出など、算術以外の確認方式が必要。別途専用ペイロード方式を設計する
