---
task_id: SGK-2026-0224
doc_type: manual
status: done
parent_task_id: SGK-2026-0224
related_docs:
- docs/shigoku/plans/done/phase_e2_next_action_plan.md
- docs/shigoku/plans/done/ai_tool_integration_guide.md
- docs/shigoku/reports/phase_e2_cto_review.md
created_at: '2026-05-23'
updated_at: '2026-07-02'
---

# 外部ツール運用マニュアル

## 概要

Phase E-2で実装した新外部ツール統合基盤（BaseExternalAdapter）の運用手順。

---

## 監視ダッシュボード

### 起動方法

```bash
# リアルタイムモニタリング
.venv/bin/python -m src.cli.monitoring_dashboard

# または直接
.venv/bin/python src/cli/monitoring_dashboard.py

# 単発レポート出力
.venv/bin/python src/cli/monitoring_dashboard.py --export
```

### 表示項目

| セクション | 内容 | 閾値 |
|-----------|------|------|
| **Semaphore** | 並行度統計 | 使用率>80%: 警告 |
| **Tool Stats** | ツール別実行統計 | 成功率<95%: 警告 |
| **Recent** | 最近の実行履歴 | - |
| **Alerts** | リアルタイムアラート | 待ち時間>500ms, エラー率>5% |

---

## 環境変数設定

### 必須環境変数

```bash
# 並行度調整（1-20推奨）
export SHIGOKU_EXTERNAL_TOOL_CONCURRENCY=10

# 検証
python -c "
from src.core.adapters.external.external_tool_executor import ExecutorConfig
c = ExecutorConfig()
print(f'max_concurrent: {c.max_concurrent}')
"
```

### デフォルト値

| パラメータ | デフォルト | 範囲 |
|-----------|-----------|------|
| `max_concurrent` | 5 | 1-20 |
| `timeout_seconds` | 300 | 60-600 |

---

## フィーチャーフラグ操作

### config/features.yaml

```yaml
external_tools:
  # 新基盤使用フラグ
  use_new_adapter_framework:
    enabled: false          # trueで新基盤有効化
    rollout_percentage: 0   # 0-100で段階的ロールアウト
  
  # 個別ツール設定
  adapters:
    nuclei:   { use_new_adapter: false }
    dalfox:   { use_new_adapter: false }
    ffuf:     { use_new_adapter: false }
    nmap:     { use_new_adapter: false }
    arjun:    { use_new_adapter: false }
    gau:      { use_new_adapter: false }
```

### ロールアウト手順

```bash
# 1. 10%ロールアウト
# config/features.yaml編集
# rollout_percentage: 10

# 2. 監視（30分）
python src/cli/monitoring_dashboard.py
# エラー率<5%、待ち時間<500msを確認

# 3. 50%ロールアウト
# rollout_percentage: 50

# 4. 100%ロールアウト
# rollout_percentage: 100
# enabled: true
```

---

## トラブルシューティング

### セマフォ待ち時間が高い

```bash
# 症状: avg_waiting_time_ms > 500ms
# 対策: 並行度増加
export SHIGOKU_EXTERNAL_TOOL_CONCURRENCY=10

# 検証
python src/cli/monitoring_dashboard.py
```

### エラー率が高い

```bash
# 症状: error_rate > 5%
# 対策1: バイナリヘルスチェック
python -c "
from src.core.adapters.external.nuclei_adapter import NucleiAdapter
import asyncio
a = NucleiAdapter()
print(asyncio.run(a.health_check()))
"

# 対策2: BinaryManagerリセット
rm -rf ~/.shigoku/binaries/
```

### タイムアウト頻発

```bash
# 症状: TIMEOUT status増加
# 対策: タイムアウト値増加
# ToolInput(timeout_seconds=600) を指定
```

---

## パフォーマンス最適化

### 推奨設定（環境別）

| 環境 | CPU | メモリ | SHIGOKU_EXTERNAL_TOOL_CONCURRENCY |
|------|-----|--------|-----------------------------------|
| 開発 | 4核 | 8GB | 3-5 |
| CI/CD | 2核 | 4GB | 2-3 |
| 本番 | 8核+ | 16GB+ | 10-15 |

### チューニング手順

1. **ベースライン測定**
   ```bash
   # デフォルト設定で10分間監視
   python src/cli/monitoring_dashboard.py
   # avg_waiting_time_ms, error_rate, total_executedを記録
   ```

2. **並行度増加**
   ```bash
   export SHIGOKU_EXTERNAL_TOOL_CONCURRENCY=8
   ```

3. **再測定**
   ```bash
   # 10分間監視
   python src/cli/monitoring_dashboard.py
   ```

4. **判定**
   - error_rate < 5% かつ avg_waiting_time_ms < 500ms → 維持
   - それ以外 → 減少または元に戻す

---

## 移行ガイド

### Adapter直結（現行）

```python
from src.core.adapters.external.nuclei_adapter import NucleiAdapter
from src.core.adapters.external.external_tool_executor import get_global_executor
from src.core.adapters.external.base_external_adapter import ToolInput

adapter = NucleiAdapter()
executor = get_global_executor()
result = await executor.execute(
    adapter,
    ToolInput(target="https://example.com")
)
```

---

## 関連ドキュメント

- [AI Tool Integration Guide](../plans/done/ai_tool_integration_guide.md)
- [Phase E-2 Action Plan](../plans/done/phase_e2_next_action_plan.md)
- [CTO Review Report](../reports/phase_e2_cto_review.md)

---

## サポート

問題発生時:
1. 監視ダッシュボードで統計確認
2. 環境変数設定確認
3. バイナリヘルスチェック実行
4. チームにエスカレーション
