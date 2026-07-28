---
task_id: SGK-2026-0377
doc_type: plan
status: done
parent_task_id: SGK-2026-0376
related_docs:
- docs/shigoku/plans/done/2026-07-23_signal-first-tagged-replay-attack-task-restoration_plan.md
- docs/shigoku/reports/2026-07-23_sgk-2026-0377_vulntest-mode-compiled-guard-fallback-alignment_work_report.md
- docs/shigoku/worklogs/2026-07-23_sgk-2026-0377_vulntest-mode-compiled-guard-fallback-alignment_work_log.md
title: Vulntest mode compiled guard fallback alignment
created_at: '2026-07-23'
updated_at: '2026-07-28'
tags:
- shigoku
target: ''
---

# 実装計画書：Vulntest mode compiled guard fallback alignment

## 1. 達成したいゴール（ユーザー視点）
- [x] DVWA low の `vulntest` 実行で、signal-first に含まれない tagged 補強カテゴリが compiled guard の `policy_unavailable` により落ちないこと。
- [x] 最新 session の recon 結果を再投入したとき、`tagged_redirect_param` / `tagged_admin` / `tagged_meta_observability` などの補強タスクが復元されること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: recon 結果から attack task を生成する本体。
  - `tests/core/engine/test_master_conductor_signal_recipe_routing.py`: signal-first + legacy tagged 補強の回帰テスト。
- **データの流れ / 依存関係:**
  - `session.context.target_info["mode"]` -> `MasterConductor._resolve_current_mode_name()` -> compiled guard 適用可否 -> 補強タスク生成。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** recon 結果 (`_signal_bundle` + `tagged_*`), session context mode。
- **出力/結果 (Output):** `vulntest` では bugbounty 専用 compiled guard を通さず、PhaseGate が許可する補強タスクを生成する。
- **制約・ルール:**
  - bugbounty 実行では従来通り compiled guard を使う。
  - 既存の `_resolve_current_mode_name()` を使い、モード解決ロジックを重複させない。
  - TDDでRED/GREENを確認する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `target_info["mode"]="vulntest"` かつ `self.mode="bugbounty"` の再現テストを追加する。
- [x] ステップ2: `_create_attack_tasks_from_recon()` の compiled guard 判定を `_resolve_current_mode_name()` に揃える。
- [x] ステップ3: targeted tests と最新 session recon 再投入で補強タスク復元を確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:中] 実DVWA再実行はユーザー環境での確認が必要。今回のローカル検証は session artifact 再投入と単体テストで行う。
