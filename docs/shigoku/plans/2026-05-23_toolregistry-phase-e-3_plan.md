---
task_id: SGK-2026-0241
doc_type: plan
doc_usage: implementation_plan
status: done
parent_task_id: null
related_docs:
- docs/shigoku/plans/phase_e2_next_action_plan.md
- docs/shigoku/reports/sgk-2026-0241_work_report.md
title: ToolRegistry統合と技術的負債解消 (Phase E-3) - 修正版
created_at: '2026-05-23'
updated_at: '2026-05-25'
tags:
- shigoku
- technical_debt
- architecture
- registry
---

# ToolRegistry統合計画 (Phase E-3) - レビュー反映修正版

## 1. 現状の問題

### 1.1 2系統のToolRegistry

| Registry | 場所 | パターン | 管理対象 |
|----------|------|---------|---------|
| **外部ツール** | `src/tools/__init__.py` | デコレータ登録 | BaseTool継承ツール |
| **内部ツール** | `src/core/tool_registry.py` | ToolInfo登録 | 組み込みツール |

**問題**:
- 開発者がどちらを使うべきか混乱
- ツール登録が分散（一貫性の欠如）
- AI統合時に両方を確認必要
- ドキュメントメンテナンスが複雑

---

## 2. 目標

### 2.1 主要目標
- 単一のツールアクセスポイントを提供
- 内部ツール・外部ツールを透過的に管理
- 既存コードの互換性100%維持
- 段階的・リスク最小化の移行

### 2.2 成功基準 (Go/No-Go判定用)

| 基準 | 閾値 | 測定方法 |
|------|------|---------|
| 新旧結果一致率 | ≥98% | MigrationValidator |
| パフォーマンス劣化 | ≤5% | 実行時間比較 |
| エラー率 | ≤2% | 監視ダッシュボード |
| 互換性テスト | 100% pass | 既存テストスイート |

---

## 3. 設計方針

### 3.1 推奨アーキテクチャ: Facadeパターン

```
┌─────────────────────────────────────┐
│    ToolRegistryFacade (統一入口)    │
├─────────────────────────────────────┤
│  + execute(name, **kwargs)          │
│  + get_by_name(name) → ToolProvider │
│  + list_all() → List[ToolInfo]      │
└──────────────┬────────────────────┘
               │
    ┌──────────┴──────────┐
    │                     │
┌───▼────┐           ┌────▼────┐
│External │           │ Internal│
│Registry │           │ Registry│
│(AITool) │           │(ToolInfo│
│ Bridge) │           │  based) │
└─────────┘           └─────────┘
```

**設計理由**:
- **SRP遵守**: Facadeは統一入口のみ担当、実体は委譲
- **型安全性**: `execute()`は統一インターフェース、実装は隠蔽
- **拡張性**: 新カテゴリはProviderとして追加可能

### 3.2 インターフェース設計

```python
class ToolProvider(Protocol):
    """ツール提供インターフェース（内部・外部抽象化）"""
    def get_by_name(self, name: str) -> Optional[Any]: ...
    def has(self, name: str) -> bool: ...

class ToolRegistryFacade:
    """統一ツールレジストリファサード
    
    Phase E-3: 技術的負債解消
    外部・内部ツールを透過的に管理
    """
    
    def __init__(self):
        self._external = ExternalToolProvider()   # AIToolBridge管理
        self._internal = InternalToolProvider()     # ToolInfo管理
        self._logger = logging.getLogger(__name__)
    
    def execute(self, name: str, **kwargs) -> ToolResult:
        """ツール実行（統一インターフェース）
        
        検索順序: 外部 → 内部
        ログ: どちらのProviderを使用したかDEBUG出力
        """
        if self._external.has(name):
            self._logger.debug(f"Using external provider for {name}")
            return self._external.execute(name, **kwargs)
        if self._internal.has(name):
            self._logger.debug(f"Using internal provider for {name}")
            return self._internal.execute(name, **kwargs)
        raise ToolNotFoundError(f"Tool '{name}' not found in any provider")
    
    def get_by_name(self, name: str) -> Optional[Any]:
        """ツール取得（メタデータ参照用）"""
        return self._external.get_by_name(name) or self._internal.get_by_name(name)
    
    def list_all(self) -> List[ToolMetadata]:
        """全ツール一覧（統合ビュー）"""
        external = self._external.list_all()
        internal = self._internal.list_all()
        return external + internal
```

---

## 4. タスク分解

### Week 1: 基盤実装 + 単一ツール移行検証

| タスク | 内容 | 期間 | 成果物 | 検証項目 |
|--------|------|------|--------|----------|
| **E-3.1** | ExternalToolProvider実装 | 2日 | `external_tool_provider.py` | 既存AIToolBridge動作確認 |
| **E-3.2** | InternalToolProvider実装 | 1日 | `internal_tool_provider.py` | 既存ToolRegistryラッパー |
| **E-3.3** | ToolRegistryFacade実装 | 2日 | `tool_registry_facade.py` | 単体テスト |
| **E-3.4** | nuclei移行検証 | 2日 | 検証レポート | 新旧結果一致率測定 |

**Week 1終了時 Go/No-Go判定**:
- Go: nuclei一致率≥98% → Week 2継続
- No-Go: 設計見直し or 中止検討

### Week 2: 残りツール移行 or 中止

| タスク | 内容 | 期間 | 成果物 |
|--------|------|------|--------|
| **E-3.5** | 全外部ツール移行 | 3日 | 6 Adapter統合 |
| **E-3.6** | 内部ツール移行 | 2日 | CoreTool統合 |
| **E-3.7** | 統合テスト | 2日 | テストレポート |

---

## 5. ロールバック手順

### 5.1 自動ロールバックトリガー

```yaml
# config/features.yaml
external_tools:
  unified_registry:
    enabled: true
    auto_rollback:
      error_rate_threshold: 0.05      # 5%超過で自動無効化
      response_time_threshold_ms: 5000 # 5s超過で自動無効化
      consecutive_failures: 3        # 3連続失敗で自動無効化
```

### 5.2 手動ロールバック

```bash
# 1. Facade無効化
export SHIGOKU_UNIFIED_REGISTRY=0

# 2. 旧Registry使用確認
python -c "
from src.tools import ToolRegistry  # 旧Registry確認
print(ToolRegistry.get('nuclei'))
"

# 3. 監視
python src/cli/monitoring_dashboard.py
```

---

## 6. 可観測性・監視計画

### 6.1 ログ出力

| ログレベル | 内容 | 出力タイミング |
|-----------|------|---------------|
| DEBUG | どのProviderを使用したか | 毎回 |
| INFO | ツール実行開始/完了 | 毎回 |
| WARNING | Provider fallback発生 | fallback時 |
| ERROR | ツール未発見 | 未発見時 |

### 6.2 メトリクス

```python
# Prometheus形式メトリクス例
tool_registry_calls_total{provider="external"} 150
tool_registry_calls_total{provider="internal"} 230
tool_registry_errors_total{provider="external",error="timeout"} 5
tool_registry_duration_seconds{provider="external",quantile="0.95"} 0.8
```

### 6.3 トレーシング

```python
# OpenTelemetry統合
with tracer.start_as_current_span("tool_registry.execute") as span:
    span.set_attribute("tool.name", name)
    span.set_attribute("tool.provider", provider_name)
    result = provider.execute(**kwargs)
```

---

## 7. リスク管理

| リスク | 確率 | 影響 | 対策 |
|--------|------|------|------|
| 新旧結果不一致 | 中 | 高 | Week 1でnuclei検証、Go/No-Go判定 |
| パフォーマンス劣化 | 低 | 中 | 自動ロールバック、閾値5%設定 |
| 循環参照発生 | 中 | 中 | Providerパターンで分離、レビュー必須 |
| 既存コード破壊 | 低 | 高 | 互換性テスト100%、段階的移行 |

---

## 8. 成果物

| 成果物 | 種別 | 期間 |
|--------|------|------|
| 本計画書 | plan | Week 0 |
| ExternalToolProvider | code | Week 1 |
| InternalToolProvider | code | Week 1 |
| ToolRegistryFacade | code | Week 1 |
| nuclei検証レポート | work_report | Week 1 |
| 移行完了レポート | work_report | Week 2 |
| 作業ログ | work_log | 継続 |

---

## 9. 検証

```bash
# ドキュメント検証
python3 scripts/validate_shigoku_docs.py

# 統合テスト
.venv/bin/pytest tests/core/adapters/test_tool_registry_facade.py -v

# 移行検証
.venv/bin/python tests/core/adapters/test_migration_validator.py
```
