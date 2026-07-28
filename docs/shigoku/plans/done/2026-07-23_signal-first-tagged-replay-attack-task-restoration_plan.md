---
task_id: SGK-2026-0376
doc_type: plan
status: done
parent_task_id: SGK-2026-0375
related_docs:
- docs/shigoku/reports/2026-07-23_sgk-2026-0376_signal-first-tagged-replay-attack-task-restoration_work_report.md
- docs/shigoku/worklogs/2026-07-23_sgk-2026-0376_signal-first-tagged-replay-attack-task-restoration_work_log.md
- docs/shigoku/plans/done/2026-07-22_sgk-2026-0375_scenario-probe-ownership-dedup-recovery_plan.md
title: Signal-first tagged replay attack task restoration
created_at: '2026-07-23'
updated_at: '2026-07-28'
tags:
- shigoku
target: ''
---

# 実装計画書：Signal-first tagged replay attack task restoration

## 1. 達成したいゴール（ユーザー視点）
- [x] DVWA low の攻撃試行数低下について、最新 report/session と旧 run を整合確認したうえで原因を切り分ける。
- [x] signal-first 成功時に旧 tagged 経路が丸ごと無効化され、signal bundle に無いカテゴリまで消える回帰を修正する。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: signal-first routing 後の legacy tagged 補強条件を修正。
  - `tests/core/engine/test_master_conductor_signal_recipe_routing.py`: signal bundle に無い tagged カテゴリを落とさない回帰テストを追加。
- **データの流れ / 依存関係:**
  - recon_results `_signal_bundle` -> signal-first タスク生成 -> signal 未カバー tagged カテゴリだけ legacy fallback -> `_finalize_attack_tasks()`

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** recon_results (`dict`), `_signal_bundle._endpoint_signals` (`list`)
- **出力/結果 (Output):** signal-first で生成済みカテゴリは重複生成せず、未カバー tagged カテゴリのみ攻撃タスクへ復帰する。
- **制約・ルール:**
  - 旧 tagged 経路の全面復活ではなく、signal-first 未カバー分だけ補う。
  - SCN08/10/12 の human_preferred 手動保留ポリシーは変更しない。
  - 既存の URL 単位展開と coverage-critical 優先順位を維持する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: 2026-07-23 00:03 run と 2026-07-17 baseline の report/session consistency を確認。
- [x] ステップ2: skipped task の `_intervention.approval.status=deferred_manual_v1` と manual defer policy を確認。
- [x] ステップ3: signal-first 成功時に fallback が空になる箇所へ回帰テストを追加し、RED を確認。
- [x] ステップ4: signal-first に無い tagged カテゴリだけ補強する最小修正を実装。
- [x] ステップ5: 関連テストと実 tagged ファイルによる生成見積もりを確認。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] 83件 baseline への完全復帰ではない。現在の tagged ファイル自体は legacy-only 見積もりで約46件であり、残り差分は recon 入力量・手動保留・当時の localhost/127.0.0.1 alias 重複の影響が大きい。
- [ ] [重要度:中] SCN08/10/12 は `defer_scn07_12_hitl_v1=True` により手動保留される。自動実行化する場合は別途安全設計が必要。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0376-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
