---
task_id: SGK-2026-0361
doc_type: plan
status: done
parent_task_id: SGK-2026-0001
related_docs:
  - docs/shigoku/reports/2026-07-15_sgk-2026-0361_work_report.md
  - docs/shigoku/worklogs/2026-07-15_sgk-2026-0361_work_log.md
title: Runtime Artifact Path Root Cause Fix
created_at: '2026-07-15'
updated_at: '2026-07-21'
tags:
- shigoku
target: workspace artifact path display and persistence
---

# 実装計画書：Runtime Artifact Path Root Cause Fix

## 1. 達成したいゴール（ユーザー視点）
- [x] SHIGOKUをDocker/DevContainer環境で実行しても、内部artifact保存先がコード配置ルート`/app/workspace`へ暗黙に寄らないこと。
- [x] ユーザー向けの実行後artifact一覧では、設定済みのホスト側workspaceパスを表示できること。
- [x] 既存のホスト実行では、従来どおりリポジトリ直下`workspace/projects`を使うこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/project/project_manager.py`: workspace projects基準ディレクトリの解決と表示用パス変換。
  - `src/main.py`: auto report bundle summaryの表示パス変換。
  - `src/reporting/report_session_consistency.py`: 既存artifactに残った`/app/workspace` report/session pathの互換解決。
  - `docker-compose.yml`, `docker-compose.phase-d.yml`, `.devcontainer/devcontainer.json`: コンテナ内workspace正本とホスト表示マッピングを環境変数で注入。
  - `tests/core/test_project_manager.py`, `tests/unit/main/test_main_auto_report_bundle.py`, `tests/unit/reporting/test_report_session_consistency.py`: `/app/workspace` drift防止と互換解決の回帰テスト。
- **データの流れ / 依存関係:**
  - `ProjectManager(target)` -> `SHIGOKU_WORKSPACE_PROJECTS_DIR` / `SHIGOKU_WORKSPACE_ROOT` / repo root fallback -> artifact保存先。
  - auto report bundle artifacts -> `format_workspace_display_path()` -> ユーザー向け表示。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `SHIGOKU_WORKSPACE_ROOT`, `SHIGOKU_WORKSPACE_PROJECTS_DIR`, `SHIGOKU_HOST_WORKSPACE_ROOT`
- **出力/結果 (Output):** Docker/DevContainer内部保存先は`/workspace/projects`、表示は`SHIGOKU_HOST_WORKSPACE_ROOT`配下のパスへ変換。
- **制約・ルール:**
  - artifact書き込みなど内部処理には実行環境から到達可能なruntime pathを使う。
  - ユーザー表示だけをホストパスへ変換し、内部checkerやformatterの実ファイル参照を壊さない。
  - 環境変数がないホスト実行では既存挙動を維持する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `/app/workspace`の発生源を`src/main.py`と`ProjectManager`まで逆追跡する。
- [x] ステップ2: 環境変数によるworkspace root指定と表示パス変換の赤テストを追加する。
- [x] ステップ3: `ProjectManager`のデフォルト解決とCLI表示を最小修正する。
- [x] ステップ4: Docker/DevContainerへworkspace root/display root環境変数を追加する。
- [x] ステップ5: 整合性チェッカーの`/app/workspace` report/session互換解決を追加する。
- [x] ステップ6: 対象テスト、Compose config、手動スモーク、実report consistency checkで検証する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:低] コンテナ内の既存`/app/workspace`参照は表示互換用にマッピング対象として残す。新規保存先は環境変数で`/workspace/projects`へ誘導する。
