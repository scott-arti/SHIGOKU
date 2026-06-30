---
task_id: SGK-2026-0170
doc_type: subtask_plan
status: backlog
parent_task_id: null
related_docs: []
created_at: '2026-02-13'
updated_at: '2026-06-30'
---

# Implementation Plan: Phase 2 - 頭脳のアップグレード

## 概要

Master Conductorへの `StrategyOptimizer` 導入と、モード別プロンプトの適用。

## タスクリスト (Task List)

### 1. TaskQueue の拡張 (Day 1)

- [ ] `src/core/engine/task_queue.py` の改修
  - [ ] `remove_tasks_for_assets(asset_ids)` の追加
  - [ ] `boost_priority_for_assets(asset_ids, boost_value)` の追加
  - [ ] `get_tasks_summary()` の追加
- [ ] ユニットテストの作成 (`tests/core/engine/test_task_queue_ext.py`)

### 2. StrategyOptimizer の実装 (Day 2)

- [ ] `src/core/engine/strategy_optimizer.py` の新規作成
  - [ ] ROI評価ロジック（ルールベース）の実装
  - [ ] タスク間引き・優先度ブースト命令の生成
- [ ] ユニットテストの作成 (`tests/core/engine/test_strategy_optimizer.py`)

### 3. モード別人格の定義 (Day 3)

- [ ] `src/core/engine/conductor_prompts.py` の新規作成
  - [ ] `BASE_SYSTEM_PROMPT`, `CTF_PLANNING_PROMPT`, `BB_PLANNING_PROMPT` の定義
- [ ] `src/core/engine/master_conductor.py` の `__init__` 改修
  - [ ] モードに応じたシステムプロンプトの動的適用
  - [ ] `StrategyOptimizer` の初期化

### 4. 戦略的メインループへの統合 (Day 4)

- [ ] `src/core/engine/master_conductor.py` の `run` (またはそれに相当するループ) の改修
  - [ ] 定期的な `StrategyOptimizer` 呼び出しの追加
  - [ ] 最重点ターゲット情報のコンテキストへの反映
- [ ] ログ出力の強化（戦略的判断の可視化）

### 5. 結合テストと調整 (Day 5)

- [ ] BBモードでの不要タスク削減テスト
- [ ] CTFモードでのターゲット集中テスト
- [ ] 最終調整とドキュメント更新

## 完了条件 (Definition of Done)

- 全ての新規・修正メソッドに対してテストが Pass している。
- 実際の診断実行において、戦略的なタスク増減がログで確認できる。
- CTF/BBモードの切り替えが意図通りに動作する。
