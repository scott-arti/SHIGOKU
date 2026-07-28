---
task_id: SGK-2026-0374
doc_type: plan
status: done
parent_task_id: SGK-2026-0373
related_docs:
- docs/shigoku/reports/2026-07-22_sgk-2026-0374_scenario-probe-and-data-exposure-coverage-recovery_work_report.md
- docs/shigoku/worklogs/2026-07-22_sgk-2026-0374_scenario-probe-and-data-exposure-coverage-recovery_work_log.md
- docs/shigoku/plans/done/2026-07-22_sgk-2026-0373_signal-first-attack-generation-gap-integration_plan.md
- docs/shigoku/reports/2026-07-22_sgk-2026-0373_signal-first-attack-generation-gap-integration_work_report.md
- docs/shigoku/worklogs/2026-07-22_sgk-2026-0373_signal-first-attack-generation-gap-integration_work_log.md
title: Scenario probe and data exposure coverage recovery
created_at: '2026-07-22'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/core/engine/master_conductor.py
---

# 実装計画書：Scenario probe and data exposure coverage recovery

## 1. 達成したいゴール（ユーザー視点）
- [x] signal-first 実行後でも、planned task の文言だけで scenario probe が消えず、SCN05 / SCN06 / SCN10 以降の不足 probe が生成されること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: scenario coverage 判定と scenario probe 生成の本体。
  - `tests/core/engine/test_master_conductor_scenario_probes.py`: planned task coverage の回帰テスト。
- **データの流れ / 依存関係:**
  - recon / signal-first の planned task -> `_create_missing_core_scenario_probe_tasks()` -> scenario probe task 生成 -> 実行結果が session / report へ反映。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** planned task 一覧、recon 結果、intervention scenario policy。
- **出力/結果 (Output):** explicit scenario coverage だけを根拠にした probe 追加判定、SCN05/06/10 以降の probe 復元。
- **制約・ルール:**
  - summary/report 用の scenario coverage 算出は従来どおり維持する。
  - probe planning 時だけ、推論ベースの scenario coverage を既存カバー扱いしない。
  - SHIGOKU ルールに従い、最小差分・対象テスト優先で検証する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: report/session と `master_conductor.py` を照合し、planned task が scenario coverage を先食いしていることを確認する。
- [x] ステップ2: `_create_missing_core_scenario_probe_tasks()` の coverage 判定を explicit scenario ベースへ絞る。
- [x] ステップ3: 回帰テストと再現スクリプトで、SCN05 / SCN10 を含む probe 復元を確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- `tests/core/engine/test_master_conductor_scenario_probes.py` 全体は、今回の修正とは別件の compiled guard `policy_unavailable` 前提で落ちるケースが残っている。
- 実 DVWA rerun は未実施なので、実 session 上の task 数回復量は次回確認が必要。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0374-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
