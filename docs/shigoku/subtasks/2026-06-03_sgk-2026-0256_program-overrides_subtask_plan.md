---
task_id: SGK-2026-0256
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0253
related_docs:
- docs/shigoku/subtasks/2026-06-02_sgk-2026-0253_program-overrides_subtask_plan.md
- docs/shigoku/reports/2026-06-03_sgk-2026-0253_program-overrides_work_report.md
title: SGK-2026-0256 継続監視（program overrides 運用観測）
created_at: '2026-06-03'
updated_at: '2026-07-02'
tags:
- shigoku
target: attack-chain-overrides-observability
---

# 実装計画書：SGK-2026-0256 継続監視（program overrides 運用観測）

## 1. 達成したいゴール（ユーザー視点）
- [ ] program override 適用後の probe 判断・audit 観測・切り戻し条件を継続監視し、異常増加や説明不能な挙動を早期に検知できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `docs/shigoku/reports/2026-06-03_sgk-2026-0253_program-overrides_work_report.md`: 継続監視の起点と完了時点の基準値
  - `docs/shigoku/subtasks/2026-06-02_sgk-2026-0253_program-overrides_subtask_plan.md`: 実装済み仕様、切り戻し条件、audit 項目の正本
  - `src/core/engine/master_conductor.py`: rollout 判定、audit 項目、runtime guard の観測対象
  - `src/core/intelligence/chain_builder.py`: rule / workflow / tactical policy 解決の観測対象
- **データの流れ / 依存関係:**
  - runtime/audit metrics -> 継続監視レビュー -> 異常有無判定 -> 必要時は追加修正または切り戻し判断

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `blocked_defer_ratio`, `planned_task_count_before_override`, `planned_task_count_after_override`, `qps_cap_target`, `applied_override_keys`, 継続回帰テスト結果
- **出力/結果 (Output):** 継続監視レビュー結果、追加修正要否、切り戻し要否、親タスクへの反映判断
- **制約・ルール:**
  - 実装済みの `program override > runtime flag > config default` 優先順位は変更しない
  - `blocked` / `defer` 優先と read-only 切り戻し条件は安全側に倒す
  - 継続監視で新規不具合が見つかった場合は、監視タスク内で修正判断を分離し、親完了報告を巻き戻さない

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `SGK-2026-0253` 完了報告を基準値として、監視対象メトリクス（`blocked/defer ratio`、`planned_task_count_before_override` / `planned_task_count_after_override`、`qps_cap_target`、`audit completeness`）を明文化し、初回レビューの判定基準を固定する。判定基準は「`blocked/defer ratio` が報告時点から悪化しない」「`planned_task_count_before_override` / `planned_task_count_after_override` の差分が報告値を超えない」「`qps_cap_target` が報告値と一致する」「audit 必須項目の欠落がない」の4点とする。
- [ ] ステップ2: 関連回帰テストと運用観測結果を定期確認し、precedence / 統合一致 / 切り戻し条件の逸脱有無を記録する。逸脱がなければ監視継続、逸脱があれば修正タスク起票へ進める。
- [ ] ステップ3: 逸脱があれば別修正タスクを起票し、逸脱がなければ親タスク `SGK-2026-0253` の継続監視欄へレビュー結果を反映する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] `program_override` の許可キーが現状 `allow` / `deny` / `per_asset_qps_cap` / `global_probe_budget` 中心であり、`race_mode` / `dry_run` / `fail_closed` の program-level 解決は継続観測中。継続監視で追加需要を見極め、必要なら別修正タスクを起票する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0256-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
