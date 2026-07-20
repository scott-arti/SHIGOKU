---
task_id: SGK-2026-0360
doc_type: plan
status: done
parent_task_id: null
related_docs:
- docs/shigoku/plans/done/2026-07-14_sgk-2026-0359_dvwa-low-session-report-bundle-fix_plan.md
- docs/shigoku/reports/2026-07-14_sgk-2026-0360_work_report.md
- docs/shigoku/worklogs/2026-07-14_sgk-2026-0360_work_log.md
title: SCN06 Meta Observability Coverage Task Promotion Fix
created_at: '2026-07-14'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/core/engine/master_conductor.py, src/core/engine/task_queue.py, src/core/engine/strategy_optimizer.py, src/core/engine/task_pruning_policy.py
---

# 実装計画書：SCN06 Meta Observability Coverage Task Promotion Fix

## 1. 達成したいゴール（ユーザー視点）
- [x] DVWA Security=low run で `tagged_meta_observability` 候補が存在する場合、SCN06 (`scn_06_data_exposure_diff`) 用taskが派生タスク上限で落ちないこと。
- [x] SCN06用taskが task queue / strategy optimizer / pruning policy の後段間引きでも保護されること。
- [x] 2026-07-14 09:29 run の「候補はあるがSCN06未cover」の原因を、session/tagged artifactと回帰テストで説明できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: `tagged_meta_observability`, `meta_observability`, `scn_06_data_exposure_diff` を coverage-critical task として優先・上限例外化。
  - `src/core/engine/task_queue.py`: asset pruning からSCN06 meta-observability taskを保護。
  - `src/core/engine/strategy_optimizer.py`: low-value asset 判定からSCN06 meta-observability taskを除外。
  - `src/core/engine/task_pruning_policy.py`: pruning policyの保護条件へSCN06 meta-observabilityを追加。
  - `tests/core/engine/*`: derived cap / queue pruning / strategy pruning / policy protection の回帰テスト。
- **データの流れ / 依存関係:**
  - Recon promoted uncategorized -> `tagged_meta_observability` -> MasterConductor task expansion -> `_add_tasks()` -> queue/pruning/optimizer -> completed task -> scenario coverage。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `tagged_meta_observability` recon result、`max_derived_tasks_per_session` 到達済み状態、SCN06関連task params。
- **出力/結果 (Output):** `Meta/Observability Exposure Scan` が上限到達後もキューへ投入され、後段pruningから保護される。
- **制約・ルール:**
  - 通常の派生タスク上限は維持し、例外は scenario/coverage-critical task に限定する。
  - report/sessionの結論は consistency checker と source session の状態を分けて扱う。
  - 既存の unrelated local changes は戻さない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: 2026-07-14 09:29 run のsession/report/tagged_urlsを確認し、SCN06候補がtask化されていないことを特定。
- [x] ステップ2: derived task cap到達時にSCN06 meta-observability taskが落ちる赤テストを追加。
- [x] ステップ3: MasterConductor・queue・optimizer・pruning policyの保護条件を最小差分で統一。
- [x] ステップ4: targeted tests と実artifact確認を実行し、旧runとの差分を確認。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:中] 修正後にDVWA Security=lowを再実行し、SCN06がScenario Coverageへ復帰することを実地確認する。
- [ ] [重要度:低] 2026-07-14 09:29 のHaddix reportはsource_sessionヘッダが `/app/...` を指しており、ローカルcheckerでは `source_session_not_found` になる。必要ならreport再生成でheaderを正規化する。
- [ ] [重要度:低] `graphify update .` は120秒timeout。AST抽出は完了したがgraph更新完了までは確認できていない。
