---
task_id: SGK-2026-0321
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/plans/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
- docs/shigoku/subtasks/2026-06-20_sgk-2026-0281_recon-resume-recipe-phasegate_subtask_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0322_reconstate-completion-parallel-checkpoint-decision-tree_subtask_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0326_flexible-report-generation-reinjection_subtask_plan.md
title: 'P0: Recon step状態自動保存＋再開CLI＋前回差分可視化'
created_at: '2026-06-29'
updated_at: '2026-06-30'
tags:
- shigoku
- recon
- resume
target: src/recon/pipeline.py, src/recon/__init__.py, src/main.py, scripts/shigoku_ops_cli.py
---

# 実装計画書：P0 Recon step状態自動保存＋再開CLI＋前回差分可視化

> たたき台（ブラッシュアップ前提）。SGK-2026-0281 の Phase A 相当を具体化する。

## 1. 達成したいゴール（ユーザー視点）
- [ ] Recon が各 step 完了時に状態を自動保存し、中断後に「step N から再開」できる。
- [ ] `--recon-resume` / `--recon-start-step` を CLI から指定して途中再開できる。
- [ ] 前回の Recon 結果（サブドメイン/URL/ポート等）との added/removed/modified 差分を見て、再開やスキップを判断できる。
- [ ] 再開可能ポイントと現在の進捗が一覧で見える。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/pipeline.py`: `ReconState` の保存完全化、`run()` への自動 checkpoint 挿入、差分生成。
  - `src/recon/__init__.py`: 差分フォーマッタの export。
  - `src/main.py`: `--recon-resume` / `--recon-start-step` の CLI ワイヤリング（`--recon-start-step`/`--recon-end-step` は既存フラグあり、復元連動を追加）。
  - `scripts/shigoku_ops_cli.py`: `recon status` / `recon diff` サブコマンド追加。
- **データの流れ / 依存関係:**
  - step 完了 → `ReconState.save()` 自動呼び出し → `projects/<target>/recon_state.json`
  - 再開時 → `ReconState.load()` → `start_step = current_step + 1` で `run()` へ
  - 前回 state.json と今回結果 → 差分（added/removed/modified）→ Markdown/JSON 出力

## 3. 現状の前提（実装踏まえた評価）
- `ReconPipeline.run(target, start_step=1, end_step=8)` は step レンジを既にサポート（`pipeline.py:3696`）。
- `ReconState.save()/load()` は存在するが本番未呼び出し（`pipeline.py:80/97`）。
- `mark_step_complete()` で `completed_steps`/`current_step` を更新するが保存しない。
- 保存フィールド不足: `tech_stack`, `screenshots_count`, `results` が `save()` に含まれない（完全化は P1/SGK-2026-0322 で扱うが、P0 でも最小限必要な分は追加する）。
- 差分比較機能は未存在。

## 4. 具体的な仕様と制約条件
- **入力情報 (Input):** ReconState（current_step, completed_steps, all_subs, live_subs, dead_subs, tech_stack, target, project_name）、前回 state.json パス。
- **出力/結果 (Output):**
  - `projects/<target>/recon_state.json`（各 step 完了時に上書き保存、schema_version 付き）
  - `shigoku-ops recon status` → 再開可能 step 一覧と進捗
  - `shigoku-ops recon diff` → added/removed/modified 差分（JSON/Markdown）
- **制約・ルール:**
  - 保存フォーマットに `recon_state_schema_version: 1` を付け、旧 reader を壊さない。
  - 差分は一次証拠（state.json）由来のみ。推定値は `estimated` 明記。
  - secret/PII マスクは既存 redactor を通す（Recon のサブドメインは概ね公開情報だが、内部名や cookie 由来は除く）。
  - Single URL Mode で Step 1-2 スキップ時も `*_skipped` マークを保存する。

## 5. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `ReconState.save()` に `tech_stack`, `screenshots_count`, `results`(概要), `recon_state_schema_version`, 保存タイムスタンプを追加。`load()` も対応。
- [ ] ステップ2: `run()` の各 step 完了後（`mark_step_complete()` 呼び出し箇所）に `self.state.save(checkpoint_path)` を自動挿入。checkpoint_path は `pm.project_dir / "recon_state.json"`。
- [ ] ステップ3: `--recon-resume` フラグ追加。`main.py` で resume 時 `ReconState.load()` し `start_step = state.current_step + 1` を算出して `run()` に渡す。`--recon-start-step` が明示指定された場合はそちらを優先。
- [ ] ステップ4: 差分生成関数 `compute_recon_diff(prev_state, curr_state)` を実装（all_subs/live_subs/dead_subs/tech_stack の set 差分 → added/removed、tech_stack は modified 相当）。
- [ ] ステップ5: `shigoku-ops recon status` / `recon diff --prev <state.json>` サブコマンドを追加（`--json`/`--json-envelope` 対応）。
- [ ] ステップ6: 単体テスト（save/load 往復、差分、resume 時 start_step 算出）。

## 5.1 フェーズ分割
- Phase A: state 自動保存 + resume CLI（ステップ1-3）
- Phase B: 差分可視化 CLI（ステップ4-5）
- Phase C: テストと実 artifact 検証（ステップ6）

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] 並行タスク（Step5 Phase2 の fire-and-forget）の途中状態は保存対象外。→ SGK-2026-0322(P1) で扱う。
- [ ] [重要度:中] 古い state.json との後方互換。schema_version で判定し、欠損時は gracefully fallback。
- [ ] [重要度:中] 差分の modified 判定が粗い（URL/ポート詳細比較は別途）。P1 で粒度向上。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0321-D01
    title: "継続監視: 並行タスク途中状態保存"
    reason: "本タスクはメインフロー step のみ。並行タスクは別設計"
    impact: medium
    tracking_task_id: SGK-2026-0322
    recommended_next_action: "SGK-2026-0322 で並行タスク checkpoint を設計する"
```
