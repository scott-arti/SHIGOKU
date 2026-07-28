---
task_id: SGK-2026-0373
doc_type: plan
status: done
parent_task_id: SGK-2026-0372
related_docs:
- docs/shigoku/plans/done/2026-07-22_sgk-2026-0372_signal-first-attack-task-expansion-regression-fix_plan.md
- docs/shigoku/reports/2026-07-22_sgk-2026-0372_signal-first-attack-task-expansion-regression-fix_work_report.md
- docs/shigoku/worklogs/2026-07-22_sgk-2026-0372_signal-first-attack-task-expansion-regression-fix_work_log.md
- docs/shigoku/reports/2026-07-22_sgk-2026-0373_signal-first-attack-generation-gap-integration_work_report.md
- docs/shigoku/worklogs/2026-07-22_sgk-2026-0373_signal-first-attack-generation-gap-integration_work_log.md
title: Signal-first attack generation gap integration
created_at: '2026-07-22'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/core/engine/master_conductor.py
---

# 実装計画書：Signal-first attack generation gap integration

## 1. 達成したいゴール（ユーザー視点）
- [x] `file_param` 系 URL が同じパラメータ名でも、値が違えば別タスクとして残ること。
- [x] signal-first routing 成功後も、coverage backfill と scenario probe の補助タスク生成が継続すること。
- [x] `candidate_labels` からしか分からない `file_param` / `crlf_candidate` signal も攻撃タスクへ変換されること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: ownership 正規化、signal-first routing、カテゴリ解決の修正
  - `tests/core/engine/test_injection_ownership_dedup.py`: query value を含む ownership 回帰テスト
  - `tests/core/engine/test_master_conductor_signal_recipe_routing.py`: signal-first 後段処理とカテゴリ解決の回帰テスト
- **データの流れ / 依存関係:**
  - recon signal bundle -> `MasterConductor._create_attack_tasks_from_recon()` -> coverage/probe planning -> `TaskExpander`

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `_signal_bundle._endpoint_signals`, legacy tagged recon results
- **出力/結果 (Output):** URL ごとの attack task、必要な coverage backfill、scenario probe task
- **制約・ルール:**
  - legacy fallback は signal-first でタスクが生成できなかった場合だけ使う
  - ownership dedup は query key だけでなく value まで保持する
  - 既存の recipe routing と per-URL expansion の流れは壊さない

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: ownership 正規化を query key/value preserving に修正し、`crlf_candidate` を attack mapping に追加する。
- [x] ステップ2: signal-first 成功時の早期 return を外し、fallback だけを空振りさせて後段の coverage/probe planning を通す。
- [x] ステップ3: targeted pytest と report/session consistency で回帰を確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- 実ランの DVWA Security=low はまだ再実行していないため、タスク数と scenario coverage の回復量は次回 run で確認が必要。
- docs validator には既知の別件（`SGK-2026-0258` 関連の欠損参照）が残っており、本タスクでは修復しない。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0373-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
