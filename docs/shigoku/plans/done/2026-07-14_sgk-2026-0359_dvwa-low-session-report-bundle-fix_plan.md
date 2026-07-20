---
task_id: SGK-2026-0359
doc_type: plan
status: done
parent_task_id: null
related_docs:
- docs/shigoku/specs/TECHNICAL_SPEC_JA.md
- docs/shigoku/reports/2026-07-14_sgk-2026-0359_work_report.md
- docs/shigoku/worklogs/2026-07-14_sgk-2026-0359_work_log.md
title: DVWA Low Session Task Coverage and Auto Report Bundle Fix
created_at: '2026-07-14'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/core/project, src/main, src/core/engine
---

# 実装計画書：DVWA Low Session Task Coverage and Auto Report Bundle Fix

## 1. 達成したいゴール（ユーザー視点）
- [x] DVWA Security=low 実行後のセッション保存先が起動cwdに引きずられず、正規の `workspace/projects/<target>/sessions/` に揃うこと。
- [x] 通常完了後に `run_narrative_*`, `target_profile_*`, `haddix_report_*`, `haddix_gate_*`, `haddix_deferred_*` を自動生成すること。
- [x] scenario probe / coverage backfill 系タスクが派生タスク上限で落ちず、旧来のシナリオカバレッジ密度を維持できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/project/project_manager.py`: default `workspace/projects` を repo root 基準へ解決。
  - `src/main.py`: 完了後の標準レポート束生成ヘルパーと `--target` 完了後hookを復活。
  - `src/core/engine/master_conductor.py`: coverage-critical task を `max_derived_tasks_per_session` の通常カウンタ対象外にする。
  - `tests/core/test_project_manager.py`: cwd drift regression。
  - `tests/unit/main/test_main_auto_report_bundle.py`: auto report bundle regression。
  - `tests/core/engine/test_master_conductor_scenario_probes.py`: scenario probe cap regression。
- **データの流れ / 依存関係:**
  - `start_interactive_session` 完了 -> 最新 session 解決 -> Narrative/Profile/Haddix/Gate/Deferred を `reports/` に生成 -> CLIへパス表示。
  - Recon由来タスク -> `_add_tasks()` -> scenario probe / coverage guard は上限到達後もキューへ残す。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** target URL, latest valid `session_*.json`, recon-derived `Task` list。
- **出力/結果 (Output):** 正規project配下の session/report artifacts、coverage-critical tasks を含む task queue。
- **制約・ルール:**
  - 既存の明示 `base_dir` 指定は壊さない。
  - report/session整合性は `source_session` ヘッダを持つHaddixレポートで検証する。
  - 通常タスクの派生上限は維持し、例外は scenario/coverage guard 系に限定する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: skipped regression を復活し、path/report/task-cap の赤テストを確認。
- [x] ステップ2: `ProjectManager` default path、auto report bundle、derived cap exception を実装。
- [x] ステップ3: targeted tests、関連テスト、実Haddixレポート整合性、gate checker を実行。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] 2026-07-14 05:55 run は修正前に `workspace/workspace/projects/...` へ保存済みのため、本修正だけでは過去artifactを移動しない。必要なら別タスクで移行/再生成を実施する。
- [ ] [重要度:低] `graphify update .` は AST extraction 後 `remap_communities_to_previous` で長時間停止したため中断。graphify側の既存グラフ警告調査は別途扱う。
