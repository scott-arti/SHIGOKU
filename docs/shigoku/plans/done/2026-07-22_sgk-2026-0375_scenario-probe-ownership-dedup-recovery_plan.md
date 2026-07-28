---
task_id: SGK-2026-0375
doc_type: plan
status: done
parent_task_id: SGK-2026-0374
related_docs:
- docs/shigoku/reports/2026-07-22_sgk-2026-0375_scenario-probe-ownership-dedup-recovery_work_report.md
- docs/shigoku/worklogs/2026-07-22_sgk-2026-0375_scenario-probe-ownership-dedup-recovery_work_log.md
- docs/shigoku/plans/done/2026-07-22_sgk-2026-0374_scenario-probe-and-data-exposure-coverage-recovery_plan.md
- docs/shigoku/reports/2026-07-22_sgk-2026-0374_scenario-probe-and-data-exposure-coverage-recovery_work_report.md
- docs/shigoku/worklogs/2026-07-22_sgk-2026-0374_scenario-probe-and-data-exposure-coverage-recovery_work_log.md
title: Scenario probe ownership dedup recovery
created_at: '2026-07-22'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/core/engine/master_conductor.py
---

# 実装計画書：Scenario probe ownership dedup recovery

## 1. 達成したいゴール（ユーザー視点）
- [x] scenario probe が同じ URL に向いていても、SCN ごとに別タスクとして残り、ownership dedup で 2本まで潰れないこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: scenario probe の ownership 識別子を付与する本体。
  - `tests/core/engine/test_master_conductor_scenario_probes.py`: same-target probe の重複抑止回帰テスト。
- **データの流れ / 依存関係:**
  - `_create_missing_core_scenario_probe_tasks()` -> `_add_tasks()` -> `_check_and_claim_ownership()` -> task queue / session。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** generated scenario probe task 群、同一 target の ownership dedup、scenario id。
- **出力/結果 (Output):** `selection_origin` が scenario ごとに分離され、distinct probe が queue に残る。
- **制約・ルール:**
  - recon / history replay / coverage backfill の既存 ownership dedup は壊さない。
  - scenario probe 同士だけを scenario 単位で分離する。
  - 対象テストと再現スクリプトで、実際に queue へ 9 本入ることを確認する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: latest session を読み、generated 9 本に対して queued 2 本になる suppress 原因を ownership dedup で再現する。
- [x] ステップ2: scenario probe task に scenario 単位の `selection_origin` を付ける。
- [x] ステップ3: 回帰テストと synthetic 再現で、same-target scenario probe が 9 本とも queue に残ることを確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- 実 DVWA rerun は未実施なので、34 task / 5 scenario がどこまで回復するかは実行確認が必要。
- `validate_shigoku_docs.py` には今回と無関係の既知不整合 `task_268_missing_file` が残る。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0375-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
