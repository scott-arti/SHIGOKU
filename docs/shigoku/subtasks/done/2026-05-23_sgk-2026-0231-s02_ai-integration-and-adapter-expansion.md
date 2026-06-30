---
task_id: SGK-2026-0231-S02
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0231
related_docs:
  - docs/shigoku/plans/phase_e2_next_action_plan.md
  - docs/shigoku/reports/phase_e2_cto_review.md
  - docs/shigoku/subtasks/2026-05-22_sgk-2026-0231-s01_external-tool-organization_subtask_plan.md
created_at: '2026-05-23'
updated_at: '2026-06-30'
---

# Phase E-2: 外部ツールAI統合とAdapter拡張計画

## タスク特定

- **タスクID**: SGK-2026-0231-S02
- **タイトル**: Phase E-2: 外部ツールAI統合とAdapter拡張
- **親タスク**: SGK-2026-0231 (Juice Shop Phase D: 継続的改善計画)
- **前提タスク**: SGK-2026-0231-S01 (外部ツール配置整理 - Phase E-1完了)

## 背景と目的

Phase E-1で新外部ツール統合基盤（DalFoxAdapter, NucleiAdapter, AIToolBridge）を構築したが、以下の課題が残存している：

1. **AIエージェントが新ツールを使用不可** - Bridgeは実装済だがManager統合未実施
2. **運用監視が未整備** - セマフォ統計は取得可能だがダッシュボード・自動アラート未実装
3. **残Adapter未実装** - Ffuf, Nmap, Arjun, Gauのアダプターが未作成
4. **後方互換性未整備** - 旧Wrapperからの段階的移行計画が未確定

本タスクでは、CTOレビュー指摘事項を解消しつつ、Phase E-2の完了を目指す。

---

## CTOレビュー指摘事項の分析と解消策

### 1. SRE/インフラエンジニア観点

#### 指摘1: セマフォ値固定（現状: 固定値5）

**要件・重要性分析:**
- **要件**: 環境（CPU/メモリ/ネットワーク）に応じた並行度調整
- **重要性**: 高 - リソース枯渇時の対応力を左右する
- **懸念点**: 固定値では環境変化に対応できない

**解消方法:**
```python
# 実装方針: 環境変数による上書き機構
# external_tool_executor.py の ExecutorConfig に追加

@dataclass
class ExecutorConfig:
    max_concurrent: int = field(default_factory=lambda: int(
        os.getenv("SHIGOKU_EXTERNAL_TOOL_CONCURRENCY", "5")
    ))
    timeout_seconds: float = 60.0
    enable_logging: bool = True
```

**実装タスク:**
- [ ] `ExecutorConfig` に環境変数読み込み機能追加
- [ ] `.env.example` に `SHIGOKU_EXTERNAL_TOOL_CONCURRENCY` 追加
- [ ] 設定値検証（1-20の範囲チェック）

---

#### 指摘2: アラート・自動通知未実装

**要件・重要性分析:**
- **要件**: 異常検知時の自動通知（実行時間異常、エラー率上昇等）
- **重要性**: 中 - 運用負荷軽減のための監視自動化
- **懸念点**: 手動ログ確認に依存し異常検知が遅れる

**解消方法:**
```python
# 実装方針: 閾値ベースアラート + ロギング統合
# external_tool_executor.py に追加

class ExternalToolExecutor:
    def __init__(self, config: ExecutorConfig):
        # ... existing code ...
        self._alert_thresholds = {
            "avg_wait_ms": 500,      # 500ms超過で警告
            "error_rate": 0.05,      # 5%エラー率で警告
            "slow_factor": 2.0,      # 基準2倍時間で警告
        }
    
    def _check_alerts(self, result: ToolResult, baseline_ms: float):
        alerts = []
        if result.execution_time_ms > baseline_ms * self._alert_thresholds["slow_factor"]:
            alerts.append(f"Slow execution: {result.execution_time_ms:.0f}ms (baseline: {baseline_ms:.0f}ms)")
        # ログ出力 + 将来的にWebhook通知
        for alert in alerts:
            logger.warning(f"[ALERT] {alert}")
```

**実装タスク:**
- [ ] 閾値設定機能実装
- [ ] 警告ログ出力統合
- [ ] （将来対応）Webhook通知インターフェース設計

---

#### 指摘3: リアルタイム監視ダッシュボード未実装

**要件・重要性分析:**
- **要件**: logs/ディレクトリの監視・統計可視化
- **重要性**: 中 - 運用時の並行度最適化に必須
- **懸念点**: セマフォ統計を取得できるが可視化されていない

**解消方法:**
```python
# 実装方針: 簡易CLIダッシュボード + ログ集計
# src/core/monitoring/external_tools_monitor.py 新規作成

class ExternalToolsMonitor:
    """外部ツール実行監視ダッシュボード"""
    
    def show_dashboard(self):
        """リアルタイム統計表示（定期実行用）"""
        executor = get_global_executor()
        stats = executor.get_semaphore_stats()
        
        # Richテーブルで表示
        console.print(f"[bold]External Tools Status[/bold]")
        console.print(f"Active: {stats['current_active']}/{stats['max_concurrent']}")
        console.print(f"Total Executed: {stats['total_executed']}")
        console.print(f"Avg Wait: {stats.get('avg_waiting_time_ms', 0):.1f}ms")
```

**実装タスク:**
- [ ] `external_tools_monitor.py` 作成
- [ ] `/external-tools-dashboard` CLIコマンド追加
- [ ] 定期的な統計ログ出力（5分間隔）

---

### 2. ソフトウェアアーキテクト観点

#### 指摘1: 2系統のToolRegistry

**要件・重要性分析:**
- **要件**: `src/tools/__init__.py` と `src/core/tool_registry.py` の統合または明確な分離
- **重要性**: 中（長期的技術的負債）- 2系統の並行運用は複雑性を増大させる
- **懸念点**: 
  - 同一機能を2つのシステムで実装している
  - AIエージェントがどちらを使うべきか不明確
  - メンテナンス負荷増大

**解消方法（3案比較）:**

| 案 | 説明 | 工数 | リスク | 推奨 |
|----|------|------|--------|------|
| **A. 統合** | 両者を1つに統合 | 高(5日) | 既存コード影響大 | ⚠️ 慎重検討 |
| **B. 分離明確化** | 責任を明確に分離 | 中(2日) | 比較的低 | ✅ **推奨** |
| **C. 現状維持** | そのまま並行運用 | 低(0日) | 技術的負債蓄積 | ❌ 非推奨 |

**採用案: B. 分離明確化**

```python
# 責任分離設計

# src/tools/__init__.py (ToolRegistry)
用途: "外部ツール（FOSSツールラッパー）の登録"
対象: BaseExternalAdapterを継承したAdapterクラス
方法: AIToolBridge経由でAIに公開

# src/core/tool_registry.py (Core ToolRegistry)
用途: "内部コアツール（Cartographer, Fingerprinter等）の登録"
対象: エージェントの組み込み機能
方法: 直接AIに公開

# 統合点: BaseManagerAgent
class BaseManagerAgent:
    def __init__(self):
        # コアツール登録
        core_registry = get_core_tool_registry()
        for tool in core_registry.get_enabled_tools():
            self.register_tool(tool.name, tool.func, tool.description)
        
        # 外部ツール登録（Bridge経由）
        from src.core.adapters.external.ai_tool_bridge import register_external_tools_with_manager
        register_external_tools_with_manager(self)
```

**実装タスク:**
- [ ] `src/core/tool_registry.py` → `src/core/core_tool_registry.py` リネーム（明確化）
- [ ] 両レジストリの用途をドキュメント化
- [ ] `BaseManagerAgent` で両方統合登録

---

#### 指摘2: AIToolBridgeのasync問題

**要件・重要性分析:**
- **要件**: Bridge.run()はasyncだが呼び出し元がawait未対応の可能性
- **重要性**: 高 - 統合失敗のリスク
- **懸念点**: 既存Managerが同期呼び出しを期待している可能性

**解消方法:**
```python
# 実装方針: 呼び出し元調査 + 必要に応じて同期ラッパー提供

# 調査方法
1. grep "\.run\(" src/core/agents/swarm/ -r | grep -v async
2. 同期呼び出し箇所を特定

# 対応策（同期呼び出し発見時）
class AIToolBridge(BaseTool):
    def run_sync(self, **kwargs) -> Dict[str, Any]:
        """同期呼び出し用ラッパー"""
        return asyncio.run(self.run(**kwargs))
    
    # BaseToolのrun()メソッドは維持（非同期）
```

**実装タスク:**
- [ ] 呼び出し元調査（grepで特定）
- [ ] 同期呼び出し発見時は `run_sync()` メソッド追加
- [ ] 統合テストで呼び出しパターン網羅

---

### 3. デバッガー観点

#### 指摘1: ExecutionSnapshot未実装

**要件・重要性分析:**
- **要件**: 再現性確保のため実行環境スナップショット
- **重要性**: 中 - 移行時の回帰バグ再現・検証用
- **懸念点**: PIIMaskerは実装済だがスナップショット機能未統合

**解消方法:**
```python
# 実装方針: 軽量スナップショット（環境変数・コンテキストのみ）
# セキュリティ: PIIMaskerで機密情報マスキング

class ExecutionSnapshot:
    """実行環境スナップショット（機密情報マスキング済）"""
    
    def __init__(self):
        self.masker = PIIMasker()
    
    def capture(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "environment": self._mask_env(os.environ),
            "context": self._mask_context(context),
            "tool_version": self._get_tool_versions(),
        }
    
    def _mask_env(self, env: Dict[str, str]) -> Dict[str, str]:
        masked = {}
        for key, value in env.items():
            # 機密キーワード検出
            if any(pattern in key.upper() for pattern in ["KEY", "TOKEN", "SECRET", "PASSWORD"]):
                result = self.masker.mask(value)
                masked[key] = result.masked
            else:
                masked[key] = value
        return masked
```

**実装タスク:**
- [ ] `ExecutionSnapshot` クラス実装
- [ ] ToolResultに `snapshot` フィールド追加（オプション）
- [ ] デバッグモード時のみ記録（パフォーマンス考慮）

---

#### 指摘2: タイムアウト時の途中経過保持

**要件・重要性分析:**
- **要件**: Timeout時に部分的なstdoutを保持
- **重要性**: 低 - 現状でもToolResult.raw_outputで保持されている
- **懸念点**: 確認済みだが改善余地あり

**解消方法（既存で充足、文書化のみ）:**
```python
# 現状: タイムアウト時もraw_output保持済
# external_tool_executor.py の既存コード

except asyncio.TimeoutError:
    proc.kill()
    await proc.wait()
    # stdoutは取得済み（await proc.communicate()前の内容）
    
return ToolResult(
    status=ToolStatus.TIMEOUT,
    raw_output=stdout.decode() if stdout else None,  # ← 保持されている
    error_message=f"Timed out after {timeout}s"
)
```

**実装タスク:**
- [ ] ドキュメントに「タイムアウト時も部分結果確認可能」を明記
- [ ] テストケース追加（タイムアウト時のraw_output検証）

---

### 4. CTO総合指摘

#### 指摘1: 2系統の並行運用の複雑性

**要件・重要性分析:**
- **要件**: 旧Wrapperと新Adapterの並行運用期間を最小化
- **重要性**: 高 - コード複雑性・メンテナンス負荷増大
- **懸念点**: 長期並行運用は混乱を招く

**解消方法:**
```yaml
# 段階的移行計画（3ヶ月移行期間）

Month 1:
  - フィーチャーフラグ: use_new_external_tools=false（デフォルト）
  - AIToolBridge統合検証
  - 新旧比較テスト（95%一致目標）

Month 2:
  - フィーチャーフラグ: use_new_external_tools=true（50%トラフィック）
  - 監視・異常検知
  - 問題発生時は即座にロールバック

Month 3:
  - フィーチャーフラグ: use_new_external_tools=true（100%トラフィック）
  - 旧Wrapperに非推奨警告を強化
  - 移行完了準備

Month 4:
  - 旧Wrapper削除
  - 全面移行完了
```

**実装タスク:**
- [ ] `config/features.yaml` に `use_new_external_tools` 追加
- [ ] 分岐ロジック実装（新/旧選択）
- [ ] ロールバック手順書作成

---

#### 指摘2: Sprint 1成功が分水嶺

**要件・重要性分析:**
- **要件**: Sprint 1（AI統合検証）が成功すれば全面移行を承認
- **重要性**: 最高 - 全体計画の可否を決定
- **懸念点**: 失敗時は設計見直しが必要

**解消方法（Go/No-Go判定基準）:**

| 判定項目 | Go基準 | No-Go基準 | 判定方法 |
|----------|--------|-----------|----------|
| 機能等価性 | 新旧95%一致 | 90%未満 | MigrationValidator自動比較 |
| パフォーマンス | ±10%以内 | 20%以上劣化 | 実行時間比較 |
| エラー率 | 5%以内 | 10%以上 | エラーログ集計 |
| AI統合 | 選択・実行可能 | 選択されない/実行失敗 | 手動検証 |

**実装タスク:**
- [ ] Go/No-Go判定シート作成
- [ ] 自動判定スクリプト（MigrationValidator）
- [ ] 週次進捗レポートフォーマット

---

## 統合実装計画

### フェーズ構成

```
Phase E-2
├── Sprint 1: AI統合検証（最重要・分水嶺）
├── Sprint 2: 残Adapter実装
├── Sprint 3: 後方互換性整備
└── Sprint 4: 運用監視構築
```

### Sprint 1: AI統合検証（2-3日）【分水嶺】

#### 1.1 要件定義

| 要件ID | 要件内容 | 重要性 | 検証方法 |
|--------|----------|--------|----------|
| AI-INT-001 | AIがnuclei_scanを選択・実行可能 | 必須 | 手動テスト |
| AI-INT-002 | AIがdalfox_scanを選択・実行可能 | 必須 | 手動テスト |
| AI-INT-003 | 新旧実装結果一致率95%以上 | 必須 | 自動比較 |
| AI-INT-004 | パフォーマンス劣化10%以内 | 必須 | ベンチマーク |

#### 1.2 懸念点と対策

| 懸念点 | 影響 | 対策 | フォールバック |
|--------|------|------|----------------|
| Bridge統合失敗 | 高 | 事前に呼び出し元調査 | 旧Wrapper維持 |
| async/await問題 | 高 | 同期ラッパー準備 | run_sync()追加 |
| AIが新ツールを選ばない | 中 | プロンプト調整 | 強制選択モード |

#### 1.3 実装タスク詳細

```python
# scanner/manager.py への統合

class ScannerSwarm(BaseManagerAgent):  # 変更: SwarmManager → BaseManagerAgent
    def __init__(self, config=None):
        super().__init__(config)
        
        # Phase E-2: AIToolBridge統合
        from src.core.adapters.external.ai_tool_bridge import register_external_tools_with_manager
        register_external_tools_with_manager(self)
        
        # 旧Specialistは当面維持（後方互換）
        self.specialists = [...]
```

#### 1.4 検証手順

```bash
# 1. ヘルスチェック
$ python -c "from src.core.adapters.external.nuclei_adapter import NucleiAdapter; import asyncio; print(asyncio.run(NucleiAdapter().health_check()))"

# 2. 直接実行テスト
$ python -m pytest tests/core/adapters/external/test_nuclei_integration.py -v

# 3. AI統合テスト（手動）
$ python -c "
from src.core.agents.swarm.scanner.manager import ScannerSwarm
swarm = ScannerSwarm()
print('Available tools:', list(swarm.available_tools.keys()))
"
# 期待結果: 'nuclei_scan', 'dalfox_scan' が含まれる
```

---

### Sprint 2: 残Adapter実装（3-5日）

#### 2.1 優先順位と実装順序

| 優先度 | Adapter | 理由 | 実装工数 | 依存関係 |
|--------|---------|------|----------|----------|
| 1 | FfufAdapter | fuzzingマネージャー高頻度使用 | 4h | Sprint 1成功後 |
| 2 | NmapAdapter | scannerマネージャー使用 | 4h | Sprint 1成功後 |
| 3 | ArjunAdapter | param fuzzing用 | 3h | Ffuf完了後 |
| 4 | GauAdapter | URL収集用 | 3h | Arjun完了後 |

#### 2.2 実装仕様

**FfufAdapter:**
```python
class FfufAdapter(BaseExternalAdapter):
    """Ffufディレクトリ発見アダプター"""
    
    def validate_inputs(self, input_data: ToolInput) -> Tuple[bool, Optional[str]]:
        # FUZZキーワード必須チェック
        if "FUZZ" not in input_data.target:
            return False, "Target must contain FUZZ keyword"
        return True, None
    
    async def execute(self, input_data: ToolInput) -> ToolResult:
        # ffufコマンド構築
        cmd = [
            str(binary_path),
            "-u", input_data.target,
            "-w", input_data.options.get("wordlist", "common.txt"),
            "-mc", input_data.options.get("match_codes", "200,204,301,302,401,403"),
            "-json"
        ]
```

**NmapAdapter:**
```python
class NmapAdapter(BaseExternalAdapter):
    """Nmapポートスキャンアダプター"""
    
    async def execute(self, input_data: ToolInput) -> ToolResult:
        # Nmap XML出力をパース
        cmd = [
            str(binary_path),
            "-p", input_data.options.get("ports", "1-65535"),
            "-sV",  # サービス検出
            "-oX", "-",  # XML出力をstdout
            input_data.target
        ]
```

---

### Sprint 3: 後方互換性整備（2-3日）

#### 3.1 移行ラッパー実装

```python
# nuclei_wrapper.py - 後方互対版

class NucleiWrapper:
    """[DEPRECATED] 新基盤へ移行中 - 2026-08-31削除予定
    
    移行期間中: 内部でNucleiAdapterを使用
    """
    
    def __init__(self):
        warnings.warn(
            "NucleiWrapper is deprecated. Use NucleiAdapter directly.",
            DeprecationWarning,
            stacklevel=2
        )
        # 新基盤を内部で使用
        self._adapter = NucleiAdapter()
        self._executor = get_global_executor()
    
    async def scan(self, target: str, tags: List[str] = None) -> List[Dict]:
        """旧インターフェースを維持"""
        result = await self._executor.execute(
            self._adapter,
            ToolInput(
                target=target,
                options={"tags": ",".join(tags) if tags else "cve"}
            )
        )
        return self._convert_to_legacy(result)
```

#### 3.2 フィーチャーフラグ実装

```yaml
# config/features.yaml
features:
  external_tools:
    use_new_adapter:
      description: "Use new BaseExternalAdapter framework"
      default: false
      rollout_percentage: 0  # Sprint 1後: 0 → 50 → 100
```

---

### Sprint 4: 運用監視構築（2-3日）

#### 4.1 監視ダッシュボード

```python
# src/core/monitoring/external_tools_dashboard.py

class ExternalToolsDashboard:
    """外部ツール実行監視ダッシュボード"""
    
    def show_realtime_stats(self):
        """リアルタイム統計表示"""
        executor = get_global_executor()
        stats = executor.get_semaphore_stats()
        
        table = Table(title="External Tools Execution Stats")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Active / Max", f"{stats['current_active']} / {stats['max_concurrent']}")
        table.add_row("Total Executed", str(stats['total_executed']))
        table.add_row("Avg Wait Time", f"{stats.get('avg_waiting_time_ms', 0):.1f}ms")
        
        console.print(table)
```

#### 4.2 CLIコマンド追加

```python
# cli/commands.py

@CommandRegistry.register("external-tools-monitor", "Monitor external tools in real-time")
def cmd_external_tools_monitor(cli):
    """リアルタイム監視ダッシュボード"""
    from src.core.monitoring.external_tools_dashboard import ExternalToolsDashboard
    
    dashboard = ExternalToolsDashboard()
    
    with Live(dashboard.generate_table(), refresh_per_second=1) as live:
        while True:
            time.sleep(5)
            live.update(dashboard.generate_table())
```

---

## 品質基準と成功指標

### Go/No-Go判定基準

| フェーズ | Go基準 | No-Go基準 | 検証方法 |
|----------|--------|-----------|----------|
| Sprint 1 | 全必須要件満足 | 1つ以上の必須要件失敗 | 自動+手動テスト |
| Sprint 2 | 全Adapterテストパス | 50%以上テスト失敗 | pytest |
| Sprint 3 | 後方互換維持確認 | 既存機能破壊 | 回帰テスト |
| Sprint 4 | 監視データ取得確認 | 監視不能 | 手動検証 |

### 技術的品質基準

```yaml
品質基準:
  カバレッジ:
    unit_test: ">= 80%"
    integration_test: ">= 90%"
  
  パフォーマンス:
    execution_time: "旧実装の±10%以内"
    memory_usage: "旧実装の±20%以内"
  
  信頼性:
    error_rate: "< 5%"
    timeout_handling: "100%適切"
  
  保守性:
    code_complexity: "< 10 (radon)"
    documentation: "全public API"
```

---

## リスク管理

### リスク登録簿

| ID | リスク | 確率 | 影響 | 対策 | 担当 |
|----|--------|------|------|------|------|
| R001 | AI統合失敗 | 低 | 高 | 設計見直し・旧Wrapper維持 | Architect |
| R002 | パフォーマンス劣化 | 低 | 中 | セマフォ調整・キャッシュ導入 | SRE |
| R003 | 旧Wrapper互換破壊 | 中 | 中 | 段階的移行・ロールバック手順 | Dev |
| R004 | 監視データ増大 | 高 | 低 | ログローテーション・サンプリング | SRE |
| R005 | セキュリティ設定漏れ | 低 | 高 | 4層防御チェックリスト徹底 | Security |

### エスカレーションパス

```
問題検出
    ↓
Sprint内解決（担当者）
    ↓
日次スタンドアップで共有
    ↓
週次レビューでCTO判断（Go/No-Go）
    ↓
設計見直し or 継続決定
```

---

## 成果物一覧

| 成果物 | パス | 種別 | 完了基準 |
|--------|------|------|----------|
| AI統合検証レポート | `docs/shigoku/reports/sgk-2026-0231-s02_sprint1_verification.md` | レポート | Sprint 1完了時 |
| FfufAdapter | `src/core/adapters/external/ffuf_adapter.py` | 実装 | テストパス |
| NmapAdapter | `src/core/adapters/external/nmap_adapter.py` | 実装 | テストパス |
| ArjunAdapter | `src/core/adapters/external/arjun_adapter.py` | 実装 | テストパス |
| GauAdapter | `src/core/adapters/external/gau_adapter.py` | 実装 | テストパス |
| 移行ラッパー | `src/tools/scanners/nuclei_wrapper.py`等 | 修正 | 非推奨警告追加 |
| 監視ダッシュボード | `src/core/monitoring/external_tools_dashboard.py` | 実装 | 動作確認 |
| Go/No-Go判定書 | `docs/shigoku/reports/sgk-2026-0231-s02_go_no_go_decision.md` | レポート | 最終レビュー時 |

---

## タイムライン

```
2026-05-23 (Day 1)
├── 台帳更新
├── 本計画書作成
└── Sprint 1準備

2026-05-24〜26 (Day 2-4)
├── Sprint 1: AI統合検証
├── 要件検証
├── 問題発生時は即座にエスカレーション
└── 週次レビュー（Go/No-Go判定）

2026-05-27〜30 (Day 5-8) 【Go判定時のみ】
├── Sprint 2: 残Adapter実装
├── Sprint 3: 後方互換性
└── Sprint 4: 運用監視

2026-05-31 (Day 9)
└── 最終レビュー・成果物整理
```

---

## メモ

- **本タスクはSGK-2026-0231-S01の直接の後続**
- **Sprint 1が分水嶺** - 失敗時は設計見直し、成功時は残Sprint実行
- **週次進捗レポート必須** - CTOレビュー指摘事項の追跡
- **Go/No-Go判定は客観的基準に基づく** - 主観的判断を排除
