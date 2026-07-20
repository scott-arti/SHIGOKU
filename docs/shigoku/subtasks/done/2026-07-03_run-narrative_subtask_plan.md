---
task_id: SGK-2026-0343
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0300
related_docs:
- docs/shigoku/subtasks/done/2026-06-24_sgk-2026-0300_run-narrative-target-profile-markdown_subtask_plan.md
title: Run Narrative 実行時系列・対象パス・カテゴリ判断軸レポート改善
created_at: '2026-07-03'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/reporting/run_narrative_formatter.py
---

# 実装計画書：Run Narrative 実行時系列・対象パス・カテゴリ判断軸レポート改善

## 1. 達成したいゴール（ユーザー視点）
- [x] `run_narrative.md` の実行時系列で、各イベントがいつ実行されたかを日付付き JST で読めること。
- [x] 各タスクがどの対象 URL/path に対して実行されたかを、query secret を除去した形で読めること。
- [x] タスクのカテゴリ分類について、`category` だけでなく `source_category` や `classification_reason` など判断軸を同じ行で確認できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/reporting/run_narrative_formatter.py`: 修正。run ledger と task execution record を join し、時系列・対象パス・カテゴリ判断軸を表示する。
  - `tests/unit/reporting/test_run_narrative_formatter.py`: 修正。実行時系列の絶対時刻、対象パス、カテゴリ判断軸の回帰テストを追加する。
- **データの流れ / 依存関係:**
  - `session_*.json.run_ledger` + `task_execution_records` / `completed_tasks` -> `RunNarrativeFormatter` -> `run_narrative.md`

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `run_ledger` (list), `task_execution_records` (list), `completed_tasks` (list)
- **出力/結果 (Output):** `## 実行時系列` と `## Swarm・ツール実行` に実行時刻、対象パス、カテゴリ、判断軸を追加表示する。
- **制約・ルール:**
  - session schema は変更せず、既存フィールドから additive に抽出する。
  - URL query は既存 `_mask_url()` 経由で除去し、token 等を出力しない。
  - raw evidence がない値は推測せず `-` または source field 名付きの根拠として表示する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `RunNarrativeFormatter` の run ledger 表示箇所と task record join 箇所を特定する。
- [x] ステップ2: 失敗テストで、時系列ソート、日付付き時刻、対象パス、カテゴリ判断軸を固定する。
- [x] ステップ3: helper を追加して、`target_url` / `category` / `source_category` / `classification_reason` 等を安全に表示する。
- [x] ステップ4: formatter 単体テストとサンプル生成で表示を確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] session 側に `classification_reason` が保存されていないタスクでは判断軸が `source_category` や `category field in source session` に留まる。 - 生成側の run ledger / task record に分類理由をより安定して保存する後続改善で扱う。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0343-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
