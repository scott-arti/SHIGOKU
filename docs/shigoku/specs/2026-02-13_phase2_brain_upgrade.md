---
task_id: SGK-2026-0084
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-02-13'
updated_at: '2026-05-19'
---

# Specification: Phase 2 - 頭脳のアップグレード (Brain Upgrade)

## 1. 概要

Master Conductor (MC) を単なるタスク実行者から、戦況（スキャン結果）を分析してリソースを最適化する「指揮官」へと進化させる。

## 2. 実装対象 (Target)

- Roadmap Phase 2: 頭脳のアップグレード (MC & Strategy)

## 3. 主な変更点 (Changes)

### 3.1 StrategyOptimizer の新規実装

- `src/core/engine/strategy_optimizer.py`
- 資産のROIを評価し、タスクキューの「間引き (Pruning)」と「優先順位の調整 (Re-prioritization)」を行う。
- 軽量なルールベースから開始し、必要に応じてLLMを活用する。

### 3.2 TaskQueue の機能拡張

- `src/core/engine/task_queue.py`
- `remove_tasks_for_assets(asset_ids)`: 特定資産のタスクを一括削除。
- `boost_priority_for_assets(asset_ids, boost_value)`: 特定資産のタスクの優先度を上げる。
- `get_tasks_summary()`: 現在のキューの状態をLLMが理解しやすい形式で要約。

### 3.3 モード別プロンプト (Persona) の導入

- `src/core/engine/conductor_prompts.py`
- CTFモードとBug Bountyモードで異なるシステムプロンプト（思考回路）を定義。
- CTF: フラグ獲得最優先、深さ優先、ノイジーなスキャン容認。
- BB: ROI重視、広範探索、ステルス性・効率重視、重複排除。

### 3.4 MasterConductor メインループの刷新

- `src/core/engine/master_conductor.py`
- ループ内に「戦略フェーズ」を導入。
- `StrategyOptimizer` を定期的に呼び出し、作戦の修正を行う。

## 4. 完了条件 (Verification) / テストケース

1. **Pruning Test**: 画像ファイル等の低ROI資産に関連するタスクが自動的にキューから削除されること。
2. **Boosting Test**: ログイン画面やAPIエンドポイント等の高ROI資産に関連するタスクの優先度が上がること。
3. **Persona Test**: CTFモード時に「Flag」を探索する挙動（プロンプトの反映）が確認できること。
4. **Integration Test**: 戦略見直し後にMCが新しい優先度に従ってタスクをディスパッチすること。
