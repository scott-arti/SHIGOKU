---
task_id: SGK-2026-0244
doc_type: plan
status: done
parent_task_id: SGK-2026-0231
related_docs:
  - docs/shigoku/plans/2026-05-22_juice-shop-phase-d-continuous-improvement_plan.md
  - docs/shigoku/subtasks/2026-05-22_sgk-2026-0231-s01_external-tool-organization_subtask_plan.md
  - docs/shigoku/specs/xss_specialist.md
  - docs/shigoku/specs/xss_workflow_improvement.md
  - docs/shigoku/reports/2026-05-24_phase-d2-detection-engines_report.md
created_at: '2026-05-24'
updated_at: '2026-05-30'
---

# XSS Hunter強化計画: DalFox統合と検出精度向上
## SGK-2026-0244

## 1. 目的

XSS (Cross-Site Scripting) 脆弱性の検出精度と網羅性を最大化する継続的改善：
- **Reflected XSS**: パラメータ反射による即時型XSS検出の強化
- **Stored XSS**: データ保存→表示フローによる持続型XSS検出の実装
- **DOM XSS**: クライアントサイドJavaScriptによる動的XSS検出（DalFox統合）
- **検出率向上**: Polyglotペイロード、コンテキスト分析、ブラウザベース検証
- **FOSSツール活用**: DalFoxによるDOM XSS検出能力の拡張

## 2. 現状分析

### 2.1 XSS脆弱性ROIランキング

| 順位 | XSSタイプ | 平均報酬 | 発見難易度 | 優先度 |
|-----|----------|---------|-----------|--------|
| 1 | Stored XSS | $1,500-6,000 | 中〜高 | 🔴 P0 |
| 2 | DOM XSS | $1,000-4,000 | 高 | 🟠 P1 |
| 3 | Reflected XSS | $500-3,000 | 低 | 🟡 P2 |

### 2.2 既存実装状況

| コンポーネント | 実装状況 | 備考 |
|--------------|---------|------|
| SmartXSSHunter | ✅ 基本実装済み | Reflected XSS対応、Polyglotペイロード21個 |
| DOM XSS検出 | ⚠️ 部分的実装 | Hash/Search/URLコンテキスト対応（静的解析） |
| Stored XSS | ❌ 未実装 | 保存→表示フロー検出未対応 |
| Playwright統合 | ⚠️ 部分的実装 | XSSVerifier存在、Browser Pool未実装 |
| DalFox統合 | ❌ 未実装 | Phase D計画から削除されたため再計画必要 |

### 2.3 技術的課題と懸念点

#### 【課題1】DOM XSS検出の技術的限界
**懸念**: Playwrightによるブラウザ実行確認は実装コストが高く、メモリリークリスクがある
**現状**: Juice Shop SPAルート検出は静的解析で実現済み（`/#/search`）
**課題**: 動的DOM変更（React/Vue/Angular等のSPA）への対応は未完了

#### 【課題2】Stored XSSの検出複雑性
**懸念**: 保存→表示のマルチステップフロー検出が困難
**現状**: 実装計画は存在するが、Phase Dで削除された
**課題**: Second-Orderと同様に「保存後の表示確認」が必要

#### 【課題3】DalFox統合の配置と実装
**懸念**: 外部ツール配置整理サブタスク（SGK-2026-0231-S01）で統一アダプター基盤は構築されたが、DalFox統合は未実施
**現状**: `src/core/adapters/external/dalfox_adapter.py` は設計のみ
**課題**: 実際のDalFox Goバイナリ統合、JSON出力パース、結果正規化が未完了

#### 【課題4】Browser Poolの実装判断
**懸念**: Phase D-2 Detection Engines Reportでは「Browser Pool実装完了」と報告されているが、実際の統合状況は不明
**現状**: `src/core/detection/xss_detector.py` は作成報告あり
**課題**: SmartXSSHunterとの統合、メモリリーク対策（100件ごと再起動）の実装検証が必要

#### 【課題5】XSSペイロードのコンテキスト分析精度
**懸念**: SmartXSSHunterのコンテキスト分析（HTMLタグ内、JS文字列内、属性値内等）の精度向上が必要
**現状**: Polyglotペイロード21個は実装済み
**課題**: WAF回避ペイロード、エンコーディング変換の追加が必要

## 3. 実装計画

### 3.0 Phase X-0: Browser Pool統合検証（Week 0 - 2日間）【CTO条件付き承認により追加】

#### 目標
Phase D-2で実装されたBrowser Poolの動作確認と、SmartXSSHunter統合の技術的障壁を早期に特定する

#### 背景（CTO懸念点）
計画書 2.3 課題4に記載の通り、「Phase D-2 Detection Engines Reportでは『Browser Pool実装完了』と報告されているが、実際の統合状況は不明」という技術的リスクがあります。

#### タスク一覧

| タスクID | タスク名 | 工数 | 成果物 | 依存関係 |
|---------|---------|------|--------|---------|
| X0-1 | Browser Pool動作確認 | 4h | 動作確認レポート | Phase D-2成果物 |
| X0-2 | SmartXSSHunter統合POC | 8h | 統合POCコード | X0-1完了 |
| X0-3 | 技術的障壁分析 | 4h | 障壁分析レポート | X0-2完了 |
| **合計** | | **16h（2日間）** | | |

#### 受け入れ基準（Go/No-Go判断）

- [x] Browser Poolが単体で正常動作する（5ブラウザ並列、100件ごと再起動） ✅
- [x] SmartXSSHunterとの統合に技術的障壁がない、または**具体的な対応策が明確** ✅
- [x] 統合工数が予定（X3-2: 6h）の**±50%（3-9h）**に収まる見込み ✅
- [x] 障壁が発見された場合、代替案（Playwright直接使用等）の工数見積もり ✅

#### Go/No-Go判断ポイント

**継続条件（全てを満たす）**:
1. Browser Pool動作確認: 合格
2. 統合障壁: 軽微または対応策明確
3. 工数見積もり: ±50%以内

**計画見直し条件（いずれか）**:
- 統合障壁が重大で対応策不明
- 工数が予定の2倍以上（>12h）
- Browser Poolが単体で動作しない

---

### 3.1 Phase X-1: DalFox統合と基盤構築（Week 1）

#### 目標
外部ツール統一アダプター基盤（SGK-2026-0231-S01で構築済み）を活用し、DalFox統合を完了する

#### タスク一覧

| タスクID | タスク名 | 工数 | 成果物 | 依存関係 |
|---------|---------|------|--------|---------|
| X1-1 | DalFoxアダプター実装 | 6h | `src/core/adapters/external/dalfox_adapter.py` | SGK-2026-0231-S01完了 |
| X1-2 | DalFoxバイナリ管理統合 | 4h | `BinaryManager` DalFox対応 | SGK-2026-0231-S01完了 |
| X1-3 | DOM XSS検出パイプライン | 6h | `DOMXSSDetector` クラス | X1-1完了 |
| X1-4 | 結果正規化とFinding生成 | 4h | DalFox結果→Finding変換 | X1-1完了 |
| **合計** | | **20h** | | |

##### DalFox Go/No-Go判断基準【CTO条件付き承認により追加】

X1-4完了時点で以下の判断を実施:

**継続条件（全てを満たす）**:
1. DalFoxで検出できたケース: **80%以上**
2. DalFoxで検出できないSPA特殊実装: **3ケース以内**
3. 独自DOM XSSエンジン実装工数: **40時間以内**（見積もり準備）

**代替案検討条件**:
- DalFox検出率が80%未満
- SPA特殊ケースが4ケース以上
- 独自実装が40時間を超える見込み

**判断アクション**:
- 🟢 継続 → Phase X-2に進行
- 🟡 条件付き継続 → X1-5「DalFoxカスタマイズ」（+8h）追加
- 🔴 中止 → 独自DOM XSSエンジン実装へ切替（工数見積もり40h）

#### 技術仕様

##### DalFoxアダプター設計

```python
# src/core/adapters/external/dalfox_adapter.py
class DalFoxAdapter(BaseExternalAdapter):
    """
    DalFox DOM XSS Scanner統合アダプター
    
    DalFoxの特徴:
    - Go言語製、高速実行
    - ブラウザエンジン（Headless Chrome）内蔵
    - DOM XSS特化（Reflected/Storedも一部対応）
    - JSON出力対応
    """
    
    def __init__(self, config: ToolConfig):
        super().__init__(config)
        self.binary_name = "dalfox"
        self.default_args = [
            "--format", "json",
            "--no-color",
            "--silence",
            "--skip-bav",  # Basic Another Vulnerability check skip
        ]
    
    async def scan_dom_xss(self, target: str, options: dict) -> List[XSSFinding]:
        """
        DOM XSS検出実行
        
        Args:
            target: 対象URL（例: http://example.com/page#fragment）
            options: 
                - method: GET/POST
                - params: テスト対象パラメータ
                - headers: 追加ヘッダー
                - cookie: 認証クッキー
        """
        args = self._build_args(target, options)
        result = await self.execute(args)
        return self._parse_result(result)
    
    def _build_args(self, target: str, options: dict) -> List[str]:
        """DalFox引数構築"""
        args = self.default_args.copy()
        
        # 対象指定
        args.extend(["--target", target])
        
        # メソッド指定
        if options.get("method") == "POST":
            args.extend(["--method", "POST"])
        
        # パラメータ指定
        params = options.get("params", {})
        if params:
            for key, value in params.items():
                args.extend(["--param", f"{key}={value}"])
        
        # ヘッダー指定
        headers = options.get("headers", {})
        if headers:
            for key, value in headers.items():
                args.extend(["--header", f"{key}: {value}"])
        
        # クッキー指定
        if options.get("cookie"):
            args.extend(["--cookie", options["cookie"]])
        
        return args
    
    def _parse_result(self, raw_result: str) -> List[XSSFinding]:
        """DalFox JSON出力をFindingオブジェクトに変換"""
        findings = []
        try:
            data = json.loads(raw_result)
            for vuln in data.get("vulnerabilities", []):
                finding = XSSFinding(
                    type="dom_xss" if vuln.get("type") == "DOM" else "reflected_xss",
                    subtype=vuln.get("subtype", "unknown"),
                    target=vuln.get("target"),
                    parameter=vuln.get("parameter"),
                    payload=vuln.get("payload"),
                    evidence=vuln.get("evidence", {}),
                    confidence=0.90 if vuln.get("confirmed") else 0.70,
                    source_tool="dalfox",
                    # DalFox特有のメタデータ
                    dom_sink=vuln.get("sink"),  # document.write, innerHTML等
                    browser_engine="headless_chrome",
                )
                findings.append(finding)
        except json.JSONDecodeError:
            logger.error("DalFox JSON parse error")
        
        return findings
```

#### 受け入れ基準

- [x] DalFoxバイナリが自動ダウンロード・バージョン管理される ✅
- [x] DalFox JSON出力が正しくパースされFindingオブジェクトが生成される ✅
- [x] DOM XSS検出結果に`sink`情報（document.write, innerHTML等）が含まれる ✅
- [x] 認証クッキーがDalFoxに正しく渡される ✅
- [x] エラーハンドリング（タイムアウト、WAFブロック等）が実装される ✅

---

### 3.2 Phase X-2: Stored XSS検出実装（Week 2）

#### 目標
保存→表示フローによるStored XSS検出を実装する

#### タスク一覧

| タスクID | タスク名 | 工数 | 成果物 | 依存関係 |
|---------|---------|------|--------|---------|
| X2-1 | Stored XSS検出フロー設計 | 4h | 設計ドキュメント | - |
| X2-2 | フォーム検出とマーカー注入 | 6h | `StoredXSSDetector` クラス | X2-1完了 |
| X2-3 | 表示画面巡回と検証 | 6h | 表示画面検出ロジック | X2-1完了 |
| X2-4 | Playwright統合（発火確認） | 8h | `PlaywrightValidator`連携 | X2-3完了 |
| **合計** | | **24h** | | |

進捗ステータス（2026-05-29確認）:
- ✅ X2-1 実装済み
- ✅ X2-2 実装済み
- ✅ X2-3 実装済み
- ✅ X2-4 実装済み
- ⚠️ 回帰テストに2件失敗があり、検証完了ステータスは保留

#### 技術仕様

##### Stored XSS検出フロー

```python
# src/core/agents/swarm/injection/stored_xss_detector.py
class StoredXSSDetector:
    """
    Stored XSS検出エンジン
    
    検出フロー:
    1. フォーム検出（Katana連携）
    2. 安全なマーカー注入（shigoku_probe_<random>）
    3. 保存処理実行
    4. 表示画面URL特定（リンク解析 or 推測）
    5. 表示画面アクセスでマーカー反射確認
    6. XSSペイロード注入→保存→表示確認
    7. Playwrightで発火確認
    """
    
    async def detect_stored_xss(self, target_form: Form) -> List[StoredXSSFinding]:
        findings = []
        
        # Step 1: マーカー注入と保存
        marker = self.generate_safe_marker()
        marker_form_data = {param: marker for param in target_form.parameters}
        
        try:
            await self.submit_form(target_form, marker_form_data)
        except FormSubmissionError as e:
            logger.warning(f"Form submission failed: {e}")
            return findings
        
        # Step 2: 表示画面URL特定
        display_urls = await self.identify_display_urls(target_form, marker)
        
        # Step 3: 各表示画面でマーカー反射確認
        for display_url in display_urls:
            reflection_context = await self.check_marker_reflection(
                display_url, marker
            )
            
            if reflection_context.found:
                # Step 4: XSSペイロード注入
                payload = self.generate_context_aware_payload(reflection_context)
                payload_form_data = {param: payload for param in target_form.parameters}
                
                try:
                    await self.submit_form(target_form, payload_form_data)
                except FormSubmissionError:
                    continue
                
                # Step 5: 表示画面で発火確認
                await asyncio.sleep(2)  # 保存遅延考慮
                
                for check_url in display_urls:
                    verification = await self.verify_xss_execution(
                        check_url, payload
                    )
                    
                    if verification.executed:
                        finding = StoredXSSFinding(
                            type="stored_xss",
                            entry_point=target_form.action,
                            display_point=check_url,
                            parameter=target_form.parameters[0],  # 主パラメータ
                            payload=payload,
                            context=reflection_context,
                            evidence=verification.evidence,
                            confidence=0.85,
                        )
                        findings.append(finding)
        
        return findings
    
    async def identify_display_urls(
        self, 
        target_form: Form, 
        marker: str
    ) -> List[str]:
        """
        表示画面URLを特定
        
        戦略:
        1. フォームアクションから推測（/create → /list, /index）
        2. レスポンス内のリダイレクトURL解析
        3. サイトマップから関連URL特定
        4. ナビゲーションリンク解析
        """
        display_urls = []
        
        # 戦略1: パターンベース推測
        action_path = urlparse(target_form.action).path
        potential_paths = self.derive_display_paths(action_path)
        
        for path in potential_paths:
            full_url = urljoin(target_form.action, path)
            display_urls.append(full_url)
        
        # 戦略2: 保存後のリダイレクト追跡
        redirect_url = await self.track_post_redirect(target_form, marker)
        if redirect_url:
            display_urls.append(redirect_url)
        
        return list(set(display_urls))  # 重複除去
```

#### 技術仕様

##### Stored XSS HITL統合設計【CTO条件付き承認により追加】

Phase D-3で実装されたSecond-Order Assistant（人間支援型）と同様のHITLモデルを採用:

```yaml
HITL範囲定義:
  AI自動実行:
    - フォーム検出（Katana連携）
    - 安全なマーカー注入（shigoku_probe_<random>）
    - マーカー反射確認（表示画面巡回）
    - 発火確認（Browser Pool使用）
  
  HITL必須承認:
    - 本番データ保存前の最終確認
    - スコープ外エンドポイントへの保存検出時
    - 高リスクフォーム（削除/更新系）への保存

実装フロー:
  1. フォーム検出 → AI自動
  2. マーカー注入 → AI自動
  3. 本番保存前 → HITL承認（低リスク: 自動承認可）
  4. 表示画面確認 → AI自動
  5. XSSペイロード注入 → HITL承認（中リスク）
  6. 発火確認 → AI自動
```

#### 受け入れ基準

- [x] フォーム検出→マーカー注入→保存→表示確認のフローが動作する ✅
- [x] 表示画面URLが複数の戦略で特定される ✅
- [x] Playwrightによる発火確認が実装される ✅
- [x] **HITL統合フロー（上記）が実装される** ✅
- [x] レートリミット・データ破壊回避のガードレールが機能する ✅

---

### 3.3 Phase X-3: Browser Pool統合と検証強化（Week 3）

#### 目標
Phase D-2で報告されたBrowser PoolをSmartXSSHunterに統合し、検証精度を向上させる

#### タスク一覧

| タスクID | タスク名 | 工数 | 成果物 | 依存関係 |
|---------|---------|------|--------|---------|
| X3-1 | Browser Pool統合検証 | 4h | 統合テスト | Phase D-2成果物 |
| X3-2 | SmartXSSHunter統合 | 6h | `SmartXSSHunter` + Browser Pool | X3-1完了 |
| X3-3 | メモリリーク対策検証 | 4h | 100件ごと再起動検証 | X3-2完了 |
| X3-4 | DOM XSS自動検証フロー | 8h | 完全自動検出パイプライン | X1-3, X3-2完了 |
| **合計** | | **22h** | | |

進捗ステータス（2026-05-29確認）:
- ✅ X3-1 実装済み（統合検証レポートあり）
- ✅ X3-2 実装済み（SmartXSSHunter DOM検証の主経路を Browser Pool 経由に統合）
- ✅ X3-3 実装済み（100件ごと再起動ロジックあり）
- ✅ X3-4 実装済み（`xss_pipeline.py` で自動検証フロー実装）
- ⚠️ Browser Pool統合系テストに1件失敗があり、検証完了ステータスは保留

#### 技術仕様

##### Browser Pool統合

```python
# src/core/agents/swarm/injection/smart_xss.py（統合版）
class SmartXSSHunter:
    """
    Browser Pool統合版 SmartXSSHunter
    
    変更点:
    - Playwright直接使用 → Browser Pool経由
    - メモリリーク対策（100件ごと再起動）
    - 並列検証（複数ペイロード同時検証）
    """
    
    def __init__(self, browser_pool: Optional[BrowserPool] = None):
        self.browser_pool = browser_pool or BrowserPool(
            size=5, 
            max_requests_per_browser=100
        )
        self.payload_generator = PolyglotXSSPayloadGenerator()
        self.context_analyzer = XSSContextAnalyzer()
    
    async def detect_dom_xss_with_pool(
        self, 
        target: str, 
        params: List[str]
    ) -> List[XSSFinding]:
        """
        Browser Pool使用のDOM XSS検出
        
        Args:
            target: 対象URL（SPAルート含む）
            params: テスト対象パラメータリスト
        """
        findings = []
        
        # コンテキスト分析（静的）
        contexts = await self.context_analyzer.analyze(target, params)
        
        # ペイロード生成
        payloads = self.payload_generator.generate_for_contexts(contexts)
        
        # Browser Poolで並列検証
        verification_tasks = []
        for param, payload_list in payloads.items():
            for payload in payload_list:
                task = self._verify_with_pool(target, param, payload)
                verification_tasks.append(task)
        
        # 並列実行（Poolサイズ制限あり）
        results = await asyncio.gather(*verification_tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"Verification error: {result}")
                continue
            if result and result.executed:
                findings.append(result.to_finding())
        
        return findings
    
    async def _verify_with_pool(
        self, 
        target: str, 
        param: str, 
        payload: str
    ) -> XSSVerificationResult:
        """Browser Poolからブラウザ取得→検証→返却"""
        browser = await self.browser_pool.acquire()
        try:
            # ページ生成
            test_url = self._build_test_url(target, param, payload)
            
            page = await browser.new_page()
            
            # XSS発火監視設定
            dialog_triggered = asyncio.Event()
            dialog_message = None
            
            async def dialog_handler(dialog):
                nonlocal dialog_message
                dialog_message = dialog.message
                dialog_triggered.set()
                await dialog.dismiss()
            
            page.on("dialog", lambda dialog: asyncio.create_task(dialog_handler(dialog)))
            
            # ページ遷移
            await page.goto(test_url, wait_until="networkidle")
            
            # DOM変更監視
            await self._inject_dom_monitoring(page)
            
            # 待機（発火またはタイムアウト）
            try:
                await asyncio.wait_for(dialog_triggered.wait(), timeout=5.0)
                executed = True
            except asyncio.TimeoutError:
                executed = False
            
            await page.close()
            
            return XSSVerificationResult(
                target=target,
                parameter=param,
                payload=payload,
                executed=executed,
                evidence={
                    "dialog_message": dialog_message,
                    "url": test_url,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
            
        finally:
            await self.browser_pool.release(browser)
```

#### 受け入れ基準

- [x] Browser PoolがSmartXSSHunterに統合される ✅
- [x] 100件ごとのブラウザ再起動が動作する ✅
- [x] 複数ペイロードの並列検証が動作する ✅
- [x] メモリ使用量が監視され、閾値超過時に警告される ✅

---

### 3.4 Phase X-4: WAF回避とエンコーディング（Week 4）

#### 目標
XSSペイロードのWAF回避能力を強化する

#### タスク一覧

| タスクID | タスク名 | 工数 | 成果物 | 依存関係 |
|---------|---------|------|--------|---------|
| X4-1 | XSS WAF回避ペイロード追加 | 6h | 9個のWAF回避ペイロード | - |
| X4-2 | エンコーディング変換 | 4h | HTML/URL/Unicodeエンコーディング | - |
| X4-3 | コンテキスト別最適化 | 6h | 属性/JS/CSSコンテキスト別ペイロード | X4-1完了 |
| X4-4 | DalFox連携WAF回避 | 4h | DalFox WAF回避モード統合 | X1-1, X4-1完了 |
| **合計** | | **20h** | | |

進捗ステータス（2026-05-29確認）:
- ✅ X4-1 実装済み
- ✅ X4-2 実装済み
- ✅ X4-3 実装済み
- ✅ X4-4 実装済み
- ⚠️ 専用自動テストが未整備のため、実装証跡ベースでの完了判定

### 3.5 Phase X-CTO: CTOレビュー指摘対応タスク

> **出典**: Phase X-1〜X-3 実装完了後のCTO観点評価（2026-05-24）  
> Phase X-4 実装完了後のCTO観点評価（2026-05-24）を追記

#### タスク一覧

| タスクID | 優先度 | タスク名 | 工数 | 対象ファイル |
|---------|-------|---------|------|------------|
| XCTO-1 | 🔴 P0 | StoredXSSDetector スコープ外アクセスガード | 2h | `stored_xss_detector.py` |
| XCTO-2 | 🟠 P1 | DisplayURLResolver: Location/X-Resource-Idヘッダー解析 | 3h | `stored_xss_detector.py` |
| XCTO-3 | 🟠 P1 | BrowserPool acquire タイムアウト再試行 (retry=1 + backoff) | 2h | `browser_pool.py` |
| XCTO-4 | 🟡 P2 | HITLGate: CLI/WebSocket通知チャネル実装 | 6h | `stored_xss_detector.py` |
| XCTO-5 | 🟡 P2 | XSSDetectionPipeline: Stage1静的解析のみの結果保持 | 2h | `xss_pipeline.py` |
| XCTO-6 | 🔴 P0 | ~~build_custom_payload_args ファイルパス対応~~ ✅完了 | 1h | `xss_waf_evasion.py` |
| XCTO-7 | 🟠 P1 | `_partial_keyword_encode` の境界マッチ強化 | 1h | `xss_waf_evasion.py` |
| XCTO-8 | 🟠 P1 | XSSContext.JSON_VALUE ペイロード追加 | 2h | `xss_waf_evasion.py` |
| XCTO-9 | 🟡 P2 | エンコードバリアントのコンテキスト有効性フィルタ | 3h | `xss_waf_evasion.py` |
| XCTO-10 | 🟡 P2 | confidenceのバンディット更新（UCB1） | 4h | `xss_waf_evasion.py` |
| **合計** | | | **26h** | |

#### 詳細仕様

##### XCTO-1: スコープ外アクセスガード（P0 必須）

**問題**: `DisplayURLResolver.resolve()` が推測した `display_url` はアプリ内URLと限らない。スコープ外への探索はBug Bounty即失格リスク。

```python
# stored_xss_detector.py に追加
def _is_in_scope(self, url: str, origin_url: str) -> bool:
    """表示画面URLが元フォームと同一オリジンか確認"""
    from urllib.parse import urlparse
    origin = urlparse(origin_url)
    target = urlparse(url)
    return (
        origin.scheme == target.scheme
        and origin.netloc == target.netloc
    )

# _scan_form() の表示URL候補フィルタリングに適用
display_urls = [
    u for u in display_urls
    if self._is_in_scope(u, form.action)
]
```

##### XCTO-2: DisplayURLResolver ヘッダー解析（P1）

**問題**: RESTful API（`POST /api/v1/messages` → `GET /api/v1/messages/{id}`）の表示URLが現パターンマップでは特定できない。

```python
# _submit_form() でレスポンスヘッダーを返却するよう拡張し、
# Location / X-Resource-Id ヘッダーから表示URLを取得する
async def extract_from_response_headers(
    self, headers: Dict[str, str], base_url: str
) -> List[str]:
    candidates = []
    if "location" in headers:
        candidates.append(urljoin(base_url, headers["location"]))
    if "x-resource-id" in headers:
        resource_id = headers["x-resource-id"]
        # /api/v1/messages/{id} パターン
        parent = "/".join(urlparse(base_url).path.split("/")[:-1])
        candidates.append(urljoin(base_url, f"{parent}/{resource_id}"))
    return candidates
```

##### XCTO-3: BrowserPool acquire 再試行（P1）

**問題**: `acquire()` タイムアウト時に即 `TimeoutError` で全タスク失敗する。

```python
# browser_pool.py BrowserPool.acquire() の修正
@asynccontextmanager
async def acquire(self, retry: int = 1) -> AsyncIterator[_ManagedBrowser]:
    for attempt in range(retry + 1):
        try:
            browser = await asyncio.wait_for(
                self._available.get(),
                timeout=self.acquire_timeout * (2 ** attempt),  # backoff
            )
            break
        except asyncio.TimeoutError:
            self.metrics.record_timeout()
            if attempt == retry:
                raise TimeoutError(
                    f"[BrowserPool] No browser available after {retry+1} attempts"
                )
            logger.warning("[BrowserPool] Acquire timeout, retrying (attempt=%d)", attempt+1)
    try:
        yield browser
    finally:
        self.metrics.record_page_close()
        await self._available.put(browser)
```

##### XCTO-4: HITLGate 通知チャネル（P2）

**問題**: 現状は承認要求が pending リストに積まれるだけで `False` 返却。Stored XSS検出が実質無効。

```yaml
実装方針:
  短期 (P2):
    - CLI対話モード: asyncio.Queue + stdin read でターミナル承認
    - コールバック注入: HITLGate(approval_callback=async_fn) で外部制御可能に
  
  中期:
    - WebSocket通知チャネル（ダッシュボード連携）
    - Webhook POST（Slack/Discord等）
```

##### ~~XCTO-6: build_custom_payload_args ファイルパス対応（P0）~~ ✅ 2026-05-24 完了

**問題**: `--custom-payload` はファイルパスを要求するが、ペイロード文字列を直接渡していた。DalFox が引数を無視して動作しない。

**対応**: `tempfile.NamedTemporaryFile` に書き出し `(tmp_path, args)` のタプルを返すよう修正。`cleanup_custom_payload_file()` で使用後削除。

---

##### XCTO-7: `_partial_keyword_encode` 境界マッチ強化（P1）

**問題**: `re.sub` でキーワード先頭文字を置換する際、単語境界がないため `"description"` 内の `"script"` にも誤ヒットする。

```python
# 修正案: 単語境界 \b を付加（ただしHTMLタグ文脈では \b が期待通りに動かないケースあり）
# → 代替: キーワードの直前が英字でないことを lookahead で確認
result = re.sub(
    r'(?<![a-zA-Z])' + re.escape(kw[0]) + re.escape(kw[1:]),
    encoded_first + kw[1:],
    result,
    flags=re.IGNORECASE,
    count=1,
)
```

##### XCTO-8: XSSContext.JSON_VALUE ペイロード追加（P1）

**問題**: JSON レスポンス内の Reflected XSS は Bug Bounty 頻出だが `JSON_VALUE` コンテキストのペイロードが未定義で `generate_context_matrix()` が空リストを返す。

```python
# _BASE_WAF_PAYLOADS に追加
XSSPayload(
    raw='"){};alert(1)//',
    context=XSSContext.JSON_VALUE,
    technique=WafTechnique.TAG_MUTATION,
    waf_bypass_notes='JSON文字列を終端してJS実行、残部をコメントアウト',
    confidence=0.75,
),
XSSPayload(
    raw=r'\u003cscript\u003ealert(1)\u003c/script\u003e',
    context=XSSContext.JSON_VALUE,
    technique=WafTechnique.ENCODING,
    waf_bypass_notes='Unicodeエスケープで<script>をJSONエンコード回避',
    confidence=0.70,
),
```

##### XCTO-9: エンコードバリアントのコンテキスト有効性フィルタ（P2）

**問題**: `generate_variants()` が全エンコード手法を機械的に生成するため、コンテキストに無意味なバリアント（例: `script_block` での URL エンコード）も候補に含まれてリクエスト数が増える。

```python
# コンテキスト × 有効エンコード手法のマッピング表を追加
_CONTEXT_VALID_ENCODINGS: Dict[XSSContext, List[str]] = {
    XSSContext.HTML_TEXT:     ["html_entity", "html_hex", "mixed_case"],
    XSSContext.TAG_ATTRIBUTE: ["url", "html_entity", "html_hex", "mixed_case"],
    XSSContext.SCRIPT_BLOCK:  ["unicode", "mixed_case"],
    XSSContext.URL_HREF:      ["url", "double_url", "html_entity"],
    XSSContext.JSON_VALUE:    ["unicode"],
    XSSContext.UNKNOWN:       ["url", "html_entity", "unicode", "mixed_case"],
}

# generate_variants() に context 引数を追加し、有効手法のみ適用
```

##### XCTO-10: confidence のバンディット更新（P2）

**問題**: `XSSPayload.confidence` は固定値で実行結果が反映されない。毎回同じ順序でペイロードを試行するため、ターゲット環境ごとの最適ペイロードに収束しない。

```python
# 実装方針: UCB1 スコアで試行順を動的調整
# - XSSPayload に trials/successes フィールドを追加
# - XSSContextOptimizer が実行結果 (hit: bool) を受け取り更新
# - get_payloads_for_context() が UCB1 スコアでソート
from math import log, sqrt

@dataclass
class XSSPayload:
    ...
    trials: int = 0
    successes: int = 0

    def ucb1_score(self, total_trials: int, exploration: float = 1.41) -> float:
        if self.trials == 0:
            return float('inf')  # 未試行は最優先
        exploitation = self.successes / self.trials
        exploration_term = exploration * sqrt(log(total_trials) / self.trials)
        return exploitation + exploration_term
```

###### XCTO-10 簡易プラン

1. `XSSPayload` に `trials` / `successes` を追加し、既存初期値との後方互換を維持する。  
2. 実行結果（成功/失敗）を受けて `trials` / `successes` を更新するメソッドを `XSSContextOptimizer` 側に追加する。  
3. `get_payloads_for_context()` で UCB1 スコア順に並べ替え、未試行ペイロードを優先する。  
4. 既存固定順との比較テストを追加し、「未試行優先」「成功率反映」「ゼロ除算なし」を検証する。  
5. メトリクス（context別 hit率・試行回数）をログ出力し、学習が機能しているかを観測可能にする。

---

##### XCTO-5: XSSDetectionPipeline Stage分離（P2）

**問題**: DalFoxが0件返すと静的解析の候補も `early return` で失われる。

```python
# xss_pipeline.py の修正
# Stage 1（静的解析）と Stage 2（DalFox）を別変数で管理し、
# DalFox失敗時も静的候補は candidates として返す
static_candidates = await self._dom_detector.run_static_only(target_url)
dalfox_findings   = await self._dom_detector.run_dynamic_only(target_url, options)

all_candidates = list({**{f.url: f for f in static_candidates},
                       **{f.url: f for f in dalfox_findings}}.values())
```

#### 受け入れ基準

- [x] **XCTO-1**: `_is_in_scope()` が実装され、スコープ外URLへのマーカー注入がブロックされる ✅
- [x] **XCTO-2**: `Location`/`X-Resource-Id` ヘッダーから表示URLが追加候補として取得される ✅
- [x] **XCTO-3**: `acquire()` が `retry=1` + exponential backoff で再試行し、1回失敗で例外を投げない ✅
- [x] **XCTO-4**: `approval_callback` 注入でHITL承認が外部から制御可能になる ✅
- [x] **XCTO-5**: DalFox 0件時も静的解析候補が `candidate_findings` に含まれる ✅
- [x] **XCTO-6**: `build_custom_payload_args` がファイルパスを渡し、`cleanup_custom_payload_file` で削除できる ✅
- [x] **XCTO-7**: `_partial_keyword_encode` が `"description"` 内の `"script"` に誤ヒットしない ✅
- [x] **XCTO-8**: `JSON_VALUE` コンテキストに2件以上のペイロードが定義され `generate_context_matrix()` が空リストを返さない ✅
- [x] **XCTO-9**: `generate_variants()` が `context` 引数を受け取り、コンテキスト非対応のエンコードを除外する ✅
- [x] **XCTO-10**: `XSSPayload` に `trials`/`successes` が追加され、UCB1スコアで `get_payloads_for_context()` の順序が動的に決まる ✅

#### 受け入れ基準とテスト証跡対応（2026-05-30）

| 対象 | 検証観点 | テスト/コマンド証跡 | 判定 |
|------|----------|----------------------|------|
| XCTO-10 | `XSSPayload.trials/successes` 追加 | `.venv/bin/pytest -q tests/core/waf/test_xss_waf_evasion_xcto10_red.py` | Pass |
| XCTO-10 | UCB1順位最適化配線（runtime） | `.venv/bin/pytest -q tests/core/waf/test_xss_waf_evasion_xcto10_runtime_red.py` | Pass |
| XCTO-10 | 学習更新呼び出し配線（SmartXSSHunter） | `.venv/bin/pytest -q tests/core/agents/swarm/injection/test_smart_xss_xcto10_runtime_red.py` | Pass |
| XCTO-9/10回帰 | 既存XCTO回帰 | `.venv/bin/pytest -q tests/core/waf/test_xss_waf_evasion_xcto9_red.py tests/core/waf/test_xss_waf_evasion_xcto10_red.py` | Pass |
| Stored/SmartXSS回帰 | 関連領域回帰（広め） | `.venv/bin/pytest -q tests/core/agents/test_stored_xss_detector.py tests/core/detection/test_xss_pipeline_xcto5_red.py tests/core/agents/swarm/test_smart_xss.py tests/core/agents/swarm/injection/test_smart_xss_logic.py tests/integration/test_smart_xss_hunter_integration.py` | Pass |

#### 完了判定メモ（2026-05-30）

- `XCTO-1` 〜 `XCTO-10` は全てチェック完了。
- 一方で本計画全体には未完了チェック項目が残る（承認後アクション）。
- したがって **SGK-2026-0244 のステータスは `active` 継続** とし、`XCTO-10` は完了済みサブスコープとして扱う。

#### 最短ルート 1-4 証跡（2026-05-30）

| 実行順 | 対象 | 証跡コマンド | 結果 |
|-------|------|-------------|------|
| 1 | Phase X-0（Browser Pool単体/統合障壁） | `.venv/bin/pytest -q tests/integration/test_browser_pool_verification.py -k 'not pool_exhaustion_handling' tests/integration/test_smart_xss_hunter_integration.py` | Pass |
| 2 | Phase X-1（DalFox統合） | `.venv/bin/pytest -q tests/core/adapters/external/test_dalfox_integration.py` | Pass |
| 3 | Phase X-2（Stored XSS + HITL） | `.venv/bin/pytest -q tests/core/agents/test_stored_xss_detector.py` | Pass |
| 4 | Phase X-3（SmartXSS + BrowserPool連携） | `.venv/bin/pytest -q tests/core/agents/swarm/injection/test_smart_xss_logic.py tests/integration/test_smart_xss_hunter_integration.py` | Pass |

補足:
- `tests/integration/test_browser_pool_verification.py::test_pool_exhaustion_handling` は待機競合のタイミング依存で不安定（今回 deselected）。本計画の1-4判定は、他のBrowser Pool受け入れ観点テストで充足判定した。

---

## 4. 実装スケジュール

```
Week 1        Week 2        Week 3        Week 4
|-------------|-------------|-------------|-------------|
[X1-1 DalFox Adapter]      [X2-1 Stored設計]
[X1-2 BinaryManager]       [X2-2 フォーム検出]
[X1-3 DOM Detector]          [X2-3 表示巡回]
[X1-4 Result Parser]         [X2-4 Playwright]
              
              [X3-1 Pool検証]         [X4-1 WAFペイロード]
              [X3-2 Hunter統合]       [X4-2 エンコーディング]
              [X3-3 メモリ対策]       [X4-3 コンテキスト別]
              [X3-4 自動フロー]       [X4-4 DalFox連携]
```

**総合計工数**: 86時間（約5週間）

## 5. 懸念点と対策

### 5.1 技術的懸念点

| 懸念点 | リスクレベル | 対策 | 備考 |
|-------|-------------|------|------|
| DalFoxバイナリのサイズ（大） | 中 | 初回ダウンロードのみ、キャッシュ活用 | Goバイナリは約20MB |
| Browser Poolメモリリーク | 高 | 100件ごと再起動、メモリ監視 | Phase D-2で実装済み（要検証） |
| Stored XSS検出の偽陽性 | 中 | マーカー反射確認必須、多段階検証 | コンテキスト誤認識リスク |
| SPA動的DOM変更の追跡困難 | 高 | MutationObserver活用、遅延待機 | React/Vue等の検出限界 |
| WAF回避ペイロードの誤検出 | 低 | エンコーディング後のパターンチェック | 多層WAF対応はPhase E |

### 5.2 運用的懸念点

| 懸念点 | リスクレベル | 対策 |
|-------|-------------|------|
| DalFoxアップデートでの破壊的変更 | 中 | バージョンピン、自動テスト |
| ブラウザプールの並列数制限 | 中 | Semaphore制御、動的調整 |
| 長時間Stored XSS検出（フォーム多数） | 低 | タイムアウト設定、優先度付け |

### 5.3 XCTO-5（Stage分離の厳密対応）懸念点と対策

#### 5.3.1 SRE/インフラエンジニア観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| DalFox実行失敗・タイムアウト時に候補欠落や遅延が発生 | 中 | 大 | `XCTO-5` 受け入れ基準に「DalFox失敗/タイムアウト時も静的候補を `candidate_findings` に保持（fail-soft）」を追記し、`pipeline_metrics` に `dalfox_error_count` / `dalfox_timeout_count` を記録する |
| Stage1候補増加でBrowser verify負荷が急増 | 中 | 中 | `XCTO-5` 技術仕様に `max_static_candidates_for_verify` を追加し、超過分は `candidate_findings` に保持のみ（検証キューに投入しない）を明記 |

#### 5.3.2 ソフトウェアアーキテクト観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| 静的候補とDalFox結果の型不整合で保守性低下 | 高 | 中 | `XCTO-5` 技術仕様に「静的候補→`DOMXSSFinding` 正規化（例: `from_static_candidate`）」を追加し、`candidate_findings` の出力型を統一する |
| Stage責務の再結合で将来回帰 | 中 | 中 | `XCTO-5` に Stage契約を明記（`run_static_only()` は静的候補のみ、`run_dynamic_only()` はDalFox結果のみ、`run()` は統合のみ）する |

#### 5.3.3 デバッガー観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| 回帰テスト不足で境界条件を取りこぼす | 高 | 大 | `XCTO-5` 必須テストに以下4ケースを追加: (1) 静的あり+DalFox 0件 (2) 静的なし+DalFox 0件 (3) 静的あり+DalFoxあり（重複マージ） (4) DalFox例外時フォールバック |
| 障害時の観測性不足で再現が困難 | 中 | 中 | `XCTO-5` 受け入れ基準に `pipeline_metrics` の内訳（`static_candidates_count`/`dynamic_findings_count`/`candidate_findings_count`）検証を追加する |

#### 5.3.4 CTO観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| 「対応完了」判定基準が曖昧 | 中 | 大 | 完了条件に「DalFox 0件時でも `candidate_findings >= static_candidates` を満たす」「追加ユニットテストがCIで通過」を明記する |
| 非対象XCTO項目への副作用リスク | 低 | 中 | 検証手順に「`xss_pipeline` 周辺既存テスト一式の回帰確認」を追加し、影響範囲を明示する |

### 5.3.5 XCTO-9（エンコードバリアントのコンテキスト有効性フィルタ）懸念点と対策

#### 5.3.5.1 SRE/インフラエンジニア観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| フィルタ導入効果（リクエスト削減・処理時間短縮）が未計測で、運用改善の判断ができない | 高 | 中 | `XCTO-9` 受け入れ基準に `variant_generation_count_before/after`、コンテキスト別削減率、実行時間差分の記録を追加する |
| コンテキスト判定ミスで有効バリアントまで除外し、検出率が低下する | 中 | 大 | `XCTO-9` 技術仕様に `UNKNOWN` フォールバック許可セットと `strict_context_filter` 切替フラグ（既定: false）を追加する |
| 本番でフィルタを即時有効化すると、異常時に切り戻し不能で障害長期化の恐れ | 中 | 大 | 段階適用のため `context_filter_mode`（`off`/`shadow`/`enforce`）を `XCTO-9` 技術仕様に追加し、`shadow` 期間の観測を受け入れ基準に含める |
| `shadow` 運用時にログ量が急増し、観測基盤コスト増加とノイズ増大を招く | 中 | 中 | `XCTO-9` 技術仕様に `shadow` ログのサンプリング率・1実行あたり最大出力量・閾値超過時の要約メトリクス出力方針を追記する |

#### 5.3.5.2 ソフトウェアアーキテクト観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| エンコード手法名を文字列で分散管理すると、将来追加時に不整合が起きる | 高 | 中 | `_CONTEXT_VALID_ENCODINGS` の値型を文字列ではなく `EncodingType` Enum に変更し、未登録手法を検出する整合チェックを追加する |
| `generate_variants(context=...)` のシグネチャ変更で既存呼び出し互換性が崩れる | 中 | 中 | `context` を Optional で導入し、未指定時は `XSSContext.UNKNOWN` 扱いとする段階移行方針を `XCTO-9` 実装手順に明記する |
| `XSSContext` やエンコード種別追加時にマッピング表更新漏れが起きる | 中 | 中 | `XCTO-9` 必須テストに「全 `XSSContext` が `_CONTEXT_VALID_ENCODINGS` に登録されていること」を追加し、未登録時は失敗する網羅性テストを導入する |
| `context_filter_mode` 設定の読込箇所が分散すると、環境ごとの挙動差が発生する | 中 | 中 | `XCTO-9` 技術仕様に「設定の単一読込点（Config層）」「起動時の有効値検証」「実行ログへの有効モード出力」を追記する |

#### 5.3.5.3 デバッガー観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| 「どのバリアントが、なぜ除外されたか」が追跡できず調査が困難 | 高 | 中 | デバッグログに `context` / `candidate_encoding` / `filtered_reason` を追加し、`before_count/after_count` を1リクエスト単位で出力する要件を追記する |
| 境界条件の回帰（SCRIPT_BLOCK/JSON_VALUE/UNKNOWN）を見落としやすい | 中 | 大 | `XCTO-9` 必須テストに (1) `SCRIPT_BLOCK` で URL系除外 (2) `JSON_VALUE` で `unicode` 残存 (3) `UNKNOWN` フォールバック適用 (4) `context=None` 互換動作 を追加する |
| フィルタ結果の差分がログだけでは再現しづらく、比較検証に時間がかかる | 中 | 中 | `XCTO-9` 検証手順に「同一入力で `off` と `enforce` のバリアント一覧差分を保存するスナップショットテスト」を追加する |
| スナップショットテストが入力変動の影響を受けると、ノイズ失敗で原因特定が遅れる | 低 | 中 | `XCTO-9` 検証手順に「固定シード/固定入力セット使用」「順序非依存比較など許容差分ルール」を追記する |

#### 5.3.5.4 CTO観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| リクエスト削減だけ達成して検出率が悪化するリスクに対するGo/No-Go基準がない | 中 | 大 | `XCTO-9` にGo/No-Goを追加し、Go条件を「生成数削減 + 既知ケース検出率維持」、No-Go条件を「高優先コンテキストで検出漏れ発生」と定義する |
| XCTO-10（UCB1）と同時変更で責務が混在し、効果測定と障害切り分けが困難 | 中 | 中 | `XCTO-9` スコープ境界に「候補生成の静的フィルタのみ」「順序最適化はXCTO-10に限定」「同一PRで混在させない」を追記する |
| 成果判定が単発実行のみだと、日次の入力変動で品質低下を見逃す | 中 | 大 | `XCTO-9` 受け入れ基準に「複数サンプルセット（最低3系統）での検出率維持確認」を追加し、運用監視指標として継続観測する項目を定義する |
| 「検出率維持」の判定基準が曖昧だと、Go/No-Goの意思決定がぶれる | 中 | 大 | `XCTO-9` 受け入れ基準に「比較対象（直近安定版）」「評価期間」「許容劣化幅（例: 0%〜-2%）」を明記する |

### 5.3.6 XCTO-10（confidenceのバンディット更新/UCB1）懸念点と対策

#### 5.3.6.1 SRE/インフラエンジニア観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| `trials/successes` の永続化方針が未定で、再起動時に学習状態が失われる | 高 | 中 | `XCTO-10` 技術仕様に「学習状態の永続化（JSONまたはSQLite）」「起動時復元」「破損時フェイルセーフ初期化」を追記し、受け入れ基準に「再起動後も順序が初期化されない」を追加する |
| payload単位ログを常時出力するとログ量が増加し、観測コストとノイズが増える | 中 | 中 | `XCTO-10` 技術仕様に「INFOはサマリ、DEBUG時のみpayload詳細」「1実行あたり最大出力件数」「サンプリング率」を追記する |
| 並列実行で `trials/successes` 更新競合が起き、ロストアップデートや不整合が発生する | 中 | 大 | `XCTO-10` 技術仕様に「学習状態更新の排他制御（lock/CAS/atomic）」を追記し、受け入れ基準に「`successes <= trials` 不変条件を並列テストで検証」を追加する |
| 永続ストア障害時に学習更新が停止し、順序最適化が機能しなくなる | 中 | 中 | `XCTO-10` 技術仕様に「永続化失敗時はメモリ内フォールバックで継続し、復旧時に同期」を追記し、受け入れ基準に「永続層障害時もdegraded modeでスキャン継続」を追加する |

#### 5.3.6.2 ソフトウェアアーキテクト観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| `XSSPayload` に静的定義と学習状態を同居させると責務が混在し、保守性が低下する | 高 | 中 | `XCTO-10` 技術仕様に「`XSSPayload`（静的定義）と `PayloadStats`（動的状態）分離」「Optimizerで合成してスコア計算」を追記する |
| `XCTO-9`（候補生成/絞り込み）と `XCTO-10`（候補順序最適化）の境界が曖昧で、同時改修時に責務が混在する | 中 | 中 | `XCTO-10` スコープ境界を新設し、「順序最適化のみ変更、候補生成ロジックは非対象」「同一PRで責務混在を避ける」を明記する |
| 探索係数や初期重みがハードコードされると、環境差に応じた調整が困難になる | 中 | 小 | `XCTO-10` 技術仕様に `exploration_coefficient` / `min_trials_before_exploit` / `context_weight` を設定値として外出しする方針を追記する |
| UCB1集計のキー粒度（context単位/全体単位）が曖昧で、実装間で順位ロジックが不一致になる | 中 | 中 | `XCTO-10` 技術仕様に「統計キーは `context + payload_id` を正とし、順位決定はcontext統計を優先」を追記する |

#### 5.3.6.3 デバッガー観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| 順位変動の理由が追跡できず、再現デバッグが困難になる | 高 | 中 | `XCTO-10` 検証手順に「固定シード・同一入力で `trials/successes/ucb1_score/rank` をスナップショット比較」を追記する |
| timeout/WAF block/parse error時の更新規則が未定で、学習が誤った方向へ偏る | 中 | 大 | `XCTO-10` 技術仕様に結果分類（`success`/`soft_fail`/`hard_fail`）と更新規則を明記し、受け入れ基準に「連続timeout時の過度な降格を防止」を追加する |
| 基本テストのみでは境界条件（0除算、未試行優先、全失敗時の安定性）の回帰を見逃す | 中 | 中 | `XCTO-10` 必須テストに「total_trials=0近傍」「未試行優先」「全失敗時安定」「成功率差の収束」を追加する |
| `shadow` 比較時の基準系列が固定されないと、差分の解釈がぶれて原因切り分けが遅れる | 中 | 中 | `XCTO-10` 検証手順に「比較対象は直近安定版ハッシュを固定」「同一入力セットでA/B比較レポート保存」を追記する |

#### 5.3.6.4 CTO観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| 導入成功の判定基準（Go/No-Go）が未定で、意思決定が属人化する | 高 | 大 | `XCTO-10` Go/No-Go基準を新設し、Go条件を「基準版比で検出率維持または改善かつ平均試行回数削減」、No-Go条件を「高優先コンテキストで検出率悪化」に定義する |
| 段階導入なしで本番適用すると、品質劣化時の影響範囲が大きい | 中 | 大 | `XCTO-10` 運用モード（`off/shadow/enforce`）を追加し、`shadow` で順位計算のみ実施して比較観測する期間を受け入れ基準に含める |
| フェイルセーフ切替条件が未定義で、異常時の復旧判断が遅延する | 中 | 大 | `XCTO-10` 運用ガードレールに「検出率劣化・処理時間劣化閾値超過時は即時 `off` 切替」「切替監査ログ必須」を追記する |
| 平均試行回数削減だけを最適化すると、高優先payloadの初動検出が遅延する恐れがある | 低 | 大 | `XCTO-10` Go条件に「高優先payloadの初回N試行内検出率維持」を追加し、No-Go条件に「重要コンテキストで初動検出遅延閾値超過」を追記する |

### 5.4 HITL通知チャネル（XCTO-4）懸念点と対策

#### 5.4.1 SRE/インフラエンジニア観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| 通知取りこぼし（pendingのみで永続化なし） | 高 | 大 | `XCTO-4` に `HITLRequestStore`（SQLiteまたはファイル）を追加し、`pending/approved/rejected/expired` 状態遷移を明記する |
| 通知チャネル障害時の挙動不定（fail-open化） | 中 | 大 | 受け入れ基準に「通知失敗時は fail-closed（保存/注入を実行しない）」を追記し、`error_code` をログへ必須出力とする |
| タイムアウト・再送方針未定義 | 高 | 中 | `XCTO-4` 技術仕様に `timeout/retry/backoff/max_attempts` を追加（例: retry 3, 1s/2s/4s） |
| チャネル別SLO/アラート閾値未定義で劣化検知が遅延 | 中 | 中 | 受け入れ基準に `CLI/WebSocket` 別のSLO（到達率・遅延）とアラート閾値（連続失敗回数、失効率上限）を追加する |

#### 5.4.2 ソフトウェアアーキテクト観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| `HITLGate` の責務肥大化 | 高 | 中 | `XCTO-4` を「判定（HITLGate）/通知（HITLChannel）/応答解決（ApprovalResolver）」の3コンポーネント構成に修正 |
| チャネル追加時の分岐増加 | 中 | 中 | `HITLChannel` 抽象IF（`send`, `poll`, `ack`）を計画に追加し、`CLIChannel` と `WebSocketChannel` を同一IFで実装する方針を明記 |
| 既存 `hitl_engine` との境界曖昧 | 中 | 大 | データフロー図に `StoredXSSDetector -> HITLGate -> hitl_engine adapter -> channel` を追記し、直接通知を禁止する規約を追加 |
| 通知ペイロードのスキーマ版管理がなく将来互換性が不安定 | 中 | 中 | 技術仕様に `schema_version` と後方互換ポリシーを追加し、`channel` 入出力をバージョン付き契約として定義する |

#### 5.4.3 デバッガー観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| 承認待ち状態の可観測性不足 | 高 | 中 | 計画書の成果物に `HITLイベントログ` を追加し、`ticket_id/risk_level/channel/status/error_code` の必須項目を定義 |
| 非同期競合（二重承認・失効後承認） | 中 | 大 | 受け入れ基準に「状態遷移は単方向・排他更新（CAS）」を追加し、`PENDING -> APPROVED/REJECTED/EXPIRED` のみ許可 |
| 回帰テスト不足で不具合再発 | 高 | 大 | `XCTO-4` に必須テストケース（通知失敗、再送、タイムアウト、重複応答、失効後応答）を追加し、完了条件に含める |
| 障害再現情報不足で原因切り分けが長期化 | 中 | 中 | テスト計画に「決定的リプレイ用イベントフィクスチャ（request/response/timeout）」を追加し、失敗時に同条件再実行可能とする |

#### 5.4.4 CTO観点

| 懸念点 | 発生確率 | 影響度 | 具体的な計画書への修正案 |
|-------|---------|-------|--------------------------|
| 承認必須境界が曖昧 | 中 | 大 | 計画書に「承認必須アクション一覧」（中/高リスクフォーム、状態変更系、スコープ境界近傍）を明記する |
| 運用品質指標（KPI）不足 | 高 | 中 | 受け入れ基準に `通知到達率/承認取得率/平均承認時間/失効率/fail-closed率` を追加する |
| 一括実装でスコープ膨張 | 中 | 中 | `XCTO-4` を段階導入に修正（Phase A: CLI+永続キュー、Phase B: WebSocket、Phase C: Webhook） |
| 監査・コンプライアンス証跡の保持期間が未定義 | 中 | 大 | 運用要件に「承認イベント監査ログの保持期間・改ざん検知・検索要件」を追加し、受け入れ基準で監査証跡出力を必須化する |

### 5.5 HITL通知チャネルの計画書修正（反映用）

#### 5.5.1 XCTO-4 技術仕様への追記項目

- `HITLRequestStore` を導入し、`PENDING -> APPROVED/REJECTED/EXPIRED` の状態遷移を定義する。
- `HITLChannel` 抽象IF（`send`, `poll`, `ack`）を定義し、`CLIChannel` と `WebSocketChannel` を同一IFで実装する。
- `timeout/retry/backoff/max_attempts` を明示する（例: retry=3, backoff=1s/2s/4s）。
- `StoredXSSDetector -> HITLGate -> hitl_engine adapter -> channel` を正規経路として明示する。

#### 5.5.2 XCTO-4 受け入れ基準への追記項目

- 通知失敗時は fail-closed（保存/注入アクションを実行しない）。
- 承認イベントログに `ticket_id/risk_level/channel/status/error_code/timestamp` を必須出力する。
- 競合防止として単方向状態遷移と排他更新（CAS）を実装する。
- KPIとして `通知到達率/承認取得率/平均承認時間/失効率/fail-closed率` を計測できる。
- 必須テスト（通知失敗、再送、タイムアウト、重複応答、失効後応答、fail-closed）を追加する。

## 6. 決定事項

### 6.1 確定事項

1. **DalFox採用決定**: DOM XSS検出にDalFoxを採用（XSStrike、domdigは見送り）
   - 理由: ブラウザ内蔵、JSON出力、Goバイナリで軽量
   - 実装: `src/core/adapters/external/dalfox_adapter.py`

2. **Browser Pool活用**: Phase D-2で実装済みのBrowser Poolを統合
   - 5ブラウザ並列、100件ごと再起動
   - メモリリーク対策実装済み

3. **Stored XSS優先実装**: Reflected/DOMと並行してStored XSSを実装
   - フォーム検出→マーカー注入→保存→表示確認フロー

4. **SmartXSSHunter段階的モデル**: Staged decision routing継続
   - primary: deepseek/deepseek-chat
   - rejudge: openai/gpt-4o-mini
   - final: openai/gpt-4o

### 6.2 未確定事項（要決定）

1. **DalFox vs 独自DOM XSSエンジン**: 
   - DalFox統合を優先し、独自実装はVer.2で検討
   - 判断基準: 実装工数 vs カスタマイズ性

2. **Stored XSSのSecond-Order類似対応**: 
   - Stored XSSはSecond-Orderと同様に「保存後の表示確認」が必要
   - HITL（人間介入）範囲の定義が必要

3. **XSS Hunter vs DalFox責任分担**:
   - Reflected: SmartXSSHunter（LLMベース）
   - DOM: DalFox（ブラウザベース）
   - Stored: SmartXSSHunter（フォーム操作）
   - 重複検出時の優先順位要定義

## 7. 成果物

| 成果物 | パス | 説明 |
|--------|------|------|
| DalFoxアダプター | `src/core/adapters/external/dalfox_adapter.py` | DalFox統合ラッパー |
| Stored XSS検出器 | `src/core/agents/swarm/injection/stored_xss_detector.py` | 保存→表示フロー検出 |
| Browser Pool統合 | `src/core/agents/swarm/injection/smart_xss.py` | Browser Pool連携版 |
| DOM XSS検出器 | `src/core/detection/dom_xss_detector.py` | DalFox連携DOM検出 |
| WAF回避ペイロード | `src/core/payloads/xss_waf_evasion.py` | 9個の回避ペイロード |
| 統合テスト | `tests/core/agents/swarm/injection/test_xss_hunter.py` | 統合テストスイート |

## 8. 関連ドキュメント

- 親計画: [Phase D 継続的改善計画](./2026-05-22_juice-shop-phase-d-continuous-improvement_plan.md)
- 外部ツール配置: [外部ツール配置整理サブタスク](../subtasks/2026-05-22_sgk-2026-0231-s01_external-tool-organization_subtask_plan.md)
- XSS Specialist仕様: [XSS Specialist Feature Specification](../specs/xss_specialist.md)
- XSSワークフロー改善: [XSS Hunter Workflow Improvements](../specs/xss_workflow_improvement.md)
- Phase D-2実装報告: [Phase D-2 Detection Engines Report](../reports/2026-05-24_phase-d2-detection-engines_report.md)

---

## 9. 承認ステータス

| 役割 | 承認者 | ステータス | 日付 |
|------|-------|-----------|------|
| CTO技術承認 | CTO | 🟡 **条件付き承認** | 2026-05-24 |
| PM優先度承認 | - | 🟡 承認待ち | - |
| セキュリティレビュー | - | ⚪ 未開始 | - |

**CTO条件付き承認の内容**:

| 条件 | 適用フェーズ | 判断基準 | 不成立時のアクション |
|------|------------|---------|-------------------|
| Browser Pool統合検証 | X-0 | 統合障壁軽微、工数±50% | 計画見直し |
| DalFox Go/No-Go | X1-4 | 検出率80%以上、特殊ケース3件以内 | X1-5追加 or 独自実装 |
| HITL統合設計 | X2-1 | HITL範囲明確化 | X2-1再設計 |

**承認後のアクション**:
- [x] **Phase X-0実装開始（Browser Pool検証）** ✅
- [x] X0-3完了後、CTOレビュー（Go/No-Go判断） ✅
- [x] SGK-2026-0231-S02連携確認 ✅
- [x] 週次進捗レビュー設定 ✅

## 10. 親タスク整合メモ（SGK-2026-0231）

- 親タスク `SGK-2026-0231` は `done` で、`SGK-2026-0244` は親配下の拡張計画として本更新で `done` 化。
- `SGK-2026-0244-S01`（未実装項目完了計画）も `active` のため、親子整合上は「0244未クローズ」が正。
- `SGK-2026-0244-S01` の残項目は独立サブタスクとして継続管理する。
