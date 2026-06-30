---
task_id: SGK-2026-0322
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/plans/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0321_recon-step-state-resume-diff_subtask_plan.md
- docs/shigoku/plans/done/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- docs/shigoku/subtasks/done/2026-06-24_sgk-2026-0300_run-narrative-target-profile-markdown_subtask_plan.md
title: 'P1: ReconState完全化＋並行タスク途中保存＋判断ツリー可視化'
created_at: '2026-06-29'
updated_at: '2026-06-30'
tags:
- shigoku
- recon
- visibility
target: src/recon/pipeline.py, src/recon/parallel_tasks.py, src/reporting/, scripts/shigoku_ops_cli.py
---

# 実装計画書：P1 ReconState完全化＋並行タスク途中保存＋判断ツリー可視化

> たたき台（ブラッシュアップ前提）。SGK-2026-0321(P0) の保存基盤を拡張し、並行タスクと判断フロー全体の可視化を完成させる。

## 1. 達成したいゴール（ユーザー視点）
- [ ] ReconState に欠落していた情報（tech_stack/screenshots_count/results 詳細、並行タスク途中状態）も保存され、step 3-5 の部分再開で情報欠損しない。
- [ ] Step 5 Phase 2 の fire-and-forget 並行タスク（Full Port / Visual / Permutation / Dead Sub）の進捗・完了が途中保存され、中断後の再実行判断に使える。
- [ ] Recon→MC→Swarm→Worker→MC→Report の「何をどう判断して実行し結果がどうで次にどう判断したか」が、フロー/ツリー状の Markdown で俯瞰できる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/pipeline.py`: `ReconState` の完全化、`run()` と並行タスクの state 統合。
  - `src/recon/parallel_tasks.py`: 並行タスク（`ParallelTasks`）の進捗を state に反映する checkpoint。
  - `src/reporting/`: 判断ツリーフォーマッタ新設（`decision_tree_formatter.py` を想定）。
  - `scripts/shigoku_ops_cli.py`: `report decision-tree` サブコマンド。
- **データの流れ / 依存関係:**
  - 各 step / 並行タスク完了 → ReconState 更新 → save（P0 基盤を利用）
  - `session_*.json.run_ledger` + `decision_traces` + `task_execution_records` → 判断ツリーフォーマッタ → `decision_tree.md`

## 3. 現状の前提（実装踏まえた評価）
- `ReconState` の `save()` は `tech_stack`/`screenshots_count`/`results` を含まない（`pipeline.py:80`）。
- `parallel_tasks.py` の `permutation_executed` 等のガードはメモリのみ（再起動で消失）。
- Run Ledger（`run_ledger`/`decision_traces`/`task_execution_records`）は SGK-2026-0299 で session に保存済み。
- Run Narrative（`run_narrative.md`）は時系列テキスト。ツリー/フロー図としては `attack_paths.md`（Mermaid）があるが、全判断フローのツリー化は未実装。

## 4. 具体的な仕様と制約条件
- **入力情報 (Input):** ReconState（完全版）、並行タスク進捗レコード、session の run_ledger/decision_traces/task_execution_records。
- **出力/結果 (Output):**
  - 完全化された `recon_state.json`（並行タスク状態セクション付き）
  - `decision_tree.md`：Recon→Attack→Report の判断ノード・分岐・結果をツリー/Mermaid で表現。各ノードに event_id/task_id/finding_id 参照。
- **制約・ルール:**
  - 一次証拠（session/ledger）由来のみ。推定は `estimated` 明記（SGK-2026-0300 の規約に準拠）。
  - ツリーは巨大化防止のため、phase/actor で畳み込み可能にする。
  - secret/PII は既存 redactor 経由。
  - 並行タスク保存は冪等（同タスクの再保存は上書き）。

## 5. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `ReconState` に `tech_stack`, `screenshots_count`, `results`(カテゴリ別 count 概要), `parallel_task_progress: dict` を追加し save/load を対応（P0 の schema_version を維持）。
- [ ] ステップ2: `ParallelTasks` の各タスク（full_port/visual/permutation/dead_sub）完了時に `state.parallel_task_progress[name]` を更新して save する hook を追加。
- [ ] ステップ3: 並行タスクの再開判定ロジック（`parallel_task_progress` を見て未完了のみ再実行）を `run_parallel_tasks` に追加。
- [ ] ステップ4: `decision_tree_formatter.py` を実装。run_ledger を phase/actor でグループ化し、親子関係（`parent_event_id`/`source_refs`）からツリー構築。Mermaid `graph TD` で出力。
- [ ] ステップ5: `shigoku-ops report decision-tree --session <path>` サブコマンド追加。
- [ ] ステップ6: 単体テスト + 実 session artifact でのフォーマッタ検証。

## 5.1 フェーズ分割
- Phase A: ReconState 完全化 + 並行タスク checkpoint（ステップ1-3）
- Phase B: 判断ツリー可視化（ステップ4-5）
- Phase C: 検証（ステップ6）

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] ツリーが巨大化して読めなくなる。phase/actor 畳み込みと「失敗/重要判断のみ展開」の既定表示。
- [ ] [重要度:中] 並行タスクの再開で重複ファイル生成を避ける（成果物ファイル名の日付プレフィックスと idempotency）。
- [ ] [重要度:中] Swarm 内部の think ループまでは decision_traces に統合されていない。本タスクでは MC/Recon 層の判断に限定し、Swarm 詳細は SGK-2026-0293 設計に委ねる。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0322-D01
    title: "継続監視: Swarm think ループの判断ツリー統合"
    reason: "Swarm 内部の thought/action 統合は脆弱性管理設計に依存"
    impact: medium
    tracking_task_id: SGK-2026-0293
    recommended_next_action: "SGK-2026-0293 で execution_log と decision_traces の統合を設計する"
```
