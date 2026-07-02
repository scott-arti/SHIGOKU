---
task_id: SGK-2026-0115
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Dynamic Resource Scaling Specification

## 1. 概要

SHIGOKUのパフォーマンスと安定性を最大化するため、システムリソース（CPU/メモリ）とタスクの応答遅延（レイテンシ）をリアルタイムに監視し、並列実行数（Concurrency）とレート制限（Rate Limiting）を自律的に調整する `SystemResourceManager` を導入する。

## 2. 目的

1.  **OOM (Out Of Memory) 回避**: メモリ使用率が高騰した際に、強制的にGCを実行し並列数を下げることで、プロセスのクラッシュを防ぐ。
2.  **スループット最適化**: システムリソースやターゲットの応答に余裕がある場合、並列数を自動的に引き上げ、スキャン時間を短縮する。
3.  **適応型制御**: ユーザーが環境ごとの固定値を設定する必要をなくし、VPS、ローカル、ハイスペックサーバーなどあらゆる環境で最適なパフォーマンスを発揮させる。

## 3. アーキテクチャ

### 3.1 新規コンポーネント: `SystemResourceManager`

- **配置**: `src/core/engine/resource_manager.py`
- **役割**:
  - **監視**: `psutil` を使用してシステム全体のCPU/メモリ使用率を監視。
  - **分析**: 各タスクカテゴリ（`ParallelOrchestrator`内）の平均レイテンシとスループットを分析。
  - **制御**: `ParallelOrchestrator` の `TaskConfig` (workers, rate_limit) を動的に更新。

### 3.2 既存コンポーネントへの変更

- **`ParallelOrchestrator`**:
  - `TaskConfig` を動的に変更可能な設計に変更。
  - 各カテゴリの現在のメトリクス（実行中タスク数、平均レイテンシ）を `SystemResourceManager` に提供するインターフェースを追加。
- **`AdaptiveRateLimiter`**:
  - レート制限（429応答）の発生状況を外部から参照可能にする。
- **`MasterConductor`**:
  - `SystemResourceManager` のライフサイクル管理（起動・停止）。

## 4. 制御ロジック

### 4.1 メモリ保護 (Emergency Brake)

- **条件**: メモリ使用率 > 85%
- **アクション**:
  1.  `gc.collect()` を強制実行。
  2.  全カテゴリの `workers` (並列数) を **50% 削減** (最小値 1)。
  3.  ログに警告を出力。

### 4.2 レイテンシベース・スケーリング

- **条件**: メモリ < 80% かつ CPU < 70%
- **アクション**:
  - **Scale Up**:
    - 平均レイテンシ < 目標値 (例: 1.0秒) \* 0.5
    - かつ 429エラーが発生していない。
    - => `workers` を +1 (最大値まで)。
  - **Scale Down**:
    - 平均レイテンシ > 目標値 \* 1.5
    - または 429エラー発生率 > 閾値。
    - => `workers` を -1 (最小値まで)。

## 5. データ構造

### TaskConfig (Current) -> DynamicTaskConfig

```python
@dataclass
class DynamicTaskConfig:
    category: str
    min_workers: int = 1
    max_workers: int = 20
    current_workers: int = 3
    base_rate_limit: float = 10.0
    current_rate_limit: float = 10.0
```

## 6. 実装ステップ

1.  **依存関係追加**: `psutil` を `pyproject.toml` に追加。
2.  **Core実装**: `SystemResourceManager` クラスの実装。
3.  **Orchestrator改修**: 動的設定変更への対応。
4.  **統合**: `MasterConductor` に組み込み。

## 7. リスクと対策

- **ハンチング（振動）**: 変更後にクールダウン期間（例: 30秒）を設け、頻繁な設定変更を防ぐ。
- **オーバーヘッド**: 監視間隔を適切（例: 5秒ごと）に設定し、CPU負荷を抑える。
