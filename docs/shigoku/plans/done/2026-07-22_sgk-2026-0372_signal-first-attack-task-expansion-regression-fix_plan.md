---
task_id: SGK-2026-0372
doc_type: plan
status: done
parent_task_id: null
related_docs:
- docs/shigoku/reports/2026-07-21_sgk-2026-0281_work_report.md
- docs/shigoku/reports/2026-07-22_sgk-2026-0372_signal-first-attack-task-expansion-regression-fix_work_report.md
- docs/shigoku/worklogs/2026-07-22_sgk-2026-0372_signal-first-attack-task-expansion-regression-fix_work_log.md
title: Signal-first attack task expansion regression fix
created_at: '2026-07-22'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/core/engine/master_conductor.py
---

# 実装計画書：Signal-first attack task expansion regression fix

## 1. 達成したいゴール（ユーザー視点）
- [x] Recon の signal-first 経路でも、複数 URL を含む攻撃タスクが URL ごとの実行タスクへ分割されること。
- [x] 従来の tagged URL 経路と同じ優先付け処理が signal-first のタスクにも適用されること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: signal-first の早期 return を共通後処理へ接続する。
  - `tests/core/engine/test_master_conductor_signal_recipe_routing.py`: 複数 signal URL の回帰テストを追加する。
- **データの流れ / 依存関係:**
  - Recon signal bundle -> `_create_attack_tasks_from_recon()` -> `TaskExpander` -> 実行キュー

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `_endpoint_signals`（URL とカテゴリを含むリスト）
- **出力/結果 (Output):** URL 単位の `Task`。単一 URL と recipe タスクの挙動は維持する。
- **制約・ルール:**
- Signal-first が従来の fallback を実行しない設計は維持する。
  - 既存の TaskExpander と優先付けロジックを再利用し、新しい分岐を増やさない。
  - URL をまとめた親タスクは、子タスクが生成された場合に実行キューへ残さない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: 複数 URL の signal-first タスクが URL 単位へ展開される失敗テストを追加する。
- [x] ステップ2: signal-first の早期 return を共通の展開・優先付け処理へ接続する。
- [x] ステップ3: signal routing、TaskExpander、関連 MasterConductor テストを実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- signal-first で扱えないカテゴリを fallback と混在させる設計は本タスクでは変更しない。今回の修正後の DVWA 再実行で必要性を確認する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0372-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
