---
task_id: SGK-2026-0141
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 仕様書: 統合パフォーマンス最適化 (Performance Optimization v2)

## 概要

SHIGOKU のスキャンスピードおよびリソース効率を劇的に向上させるため、インフラ（ネットワーク）、戦略（タスク間引き）、ツール実行（バッチ化）の3つのレイヤーで最適化を行います。

## 課題

1. **ネットワーク効率**: エージェントごとにセッションを生成しており、大量のハンドシェイクが発生。
2. **無駄な探索**: 低ROI（静的ファイル等）への攻撃により、実効速度が低下。
3. **固定的な並列度**: ターゲットの応答性が高い場合でもスループットを上げられない。
4. **プロセス起動コスト**: 外部ツールの頻繁な起動によるCPU負荷。

## 解決策

### 1. ネットワーク・セッション・プーリング

- `MasterConductor` がライフサイクルを管理する単一の `AsyncNetworkClient` (Shared Session) を提供。
- 各エージェント（Specilaist）は、自身のコンストラクタでクライアントを生成せず、注入された共有クライアントを使用。
- `TCPConnector` を最適化（同一ホストへの同時接続数、キープアルバイブの維持）。

### 2. ROI ベースのタスク・プルーニング (StrategyOptimizer 強化)

- `StrategyOptimizer` に以下の詳細ルールを追加：
  - 意味のない静的ファイル（.jpg, .css等）への脆弱性診断の除外。
  - 既に発見された脆弱性と同一パターン、あるいは低深刻度アセットの後回し。
- ユーザー設定により「攻撃的（高速/見落とし容認）」か「保守的（低速/網羅重視）」かを選択可能に。

### 3. 適応型動的スケーリング (Dynamic Scaling)

- `AdaptiveRateLimiter` のフィードバック（エラー率、遅延）を `ParallelOrchestrator` に連携。
- エラーが少ない正常稼働時にはワーカー数を自動的に増やし、スループットを最大化。

### 4. Nuclei バッチ実行モード

- 個別のプロセスタイムアウトや起動コストを避けるため、一定数のターゲットをまとめて `nuclei -u t1 -u t2` 形式で実行するバッファリング層の実装。

## 変更範囲

- `src/core/engine/master_conductor.py`: セッション管理ロジックの追加
- `src/core/infra/network_client.py`: シングルトンアクセスおよびプール設定の最適化
- `src/core/engine/strategy_optimizer.py`: プルーニングロジックの強化
- `src/core/engine/parallel_orchestrator.py`: 動的スケールインターフェースの追加
- `src/core/tools/nuclei_integrator.py`: バッチ実行対応

## 制約事項

- `EthicsGuard` および `PIIMasker` のセキュリティチェックは、セッション共有後も各リクエストで維持されなければならない。
- `SharedWorkspace` との競合が発生しないよう、スレッドセーフな実装を徹底する。
