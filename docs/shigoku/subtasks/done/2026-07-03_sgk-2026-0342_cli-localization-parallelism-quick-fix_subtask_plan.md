---
task_id: SGK-2026-0342
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0291
related_docs:
- docs/shigoku/reports/2026-06-22_sgk-2026-0290_cli-japanese-localization_work_report.md
- docs/shigoku/reports/2026-06-30_sgk-2026-0318_work_report.md
- docs/shigoku/reports/2026-07-03_sgk-2026-0342_cli-localization-parallelism-quick-fix_work_report.md
- docs/shigoku/worklogs/2026-07-03_sgk-2026-0342_cli-localization-parallelism-quick-fix_work_log.md
title: CLI表示日本語化漏れと並列設定配線の最小修正
created_at: '2026-07-03'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/core/conductor/interactive_bridge.py, src/config.py, src/core/engine/master_conductor.py,
  src/cli/messages.py
---

# 実装計画書：CLI表示日本語化漏れと並列設定配線の最小修正

## 1. 達成したいゴール（ユーザー視点）
- [x] CLIで通常スキャンを開始したとき、開始・認証・計画・実行中などのユーザー向け進行表示が日本語で読めること。
- [x] `src.config.settings` 経由の実行ループでも `parallelism.enabled` / `kill_switch` が参照でき、既存の `force_serial` 判定が設定通りに動くこと。
- [x] 既定値は安全側（並列無効・Injection完全並列無効）を維持し、明示的に有効化した場合だけ外側並列実行へ進めること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/cli/messages.py`: interactive bridge 用の短い日本語メッセージキーを追加する。
  - `src/core/conductor/interactive_bridge.py`: 残存しているユーザー向け英語 `print_step` / `print_result` を `msg()` 経由にする。
  - `src/config.py`: 実行ループが読んでいる flat settings に最小の `parallelism` 設定オブジェクトを追加する。
  - `tests/unit/core/conductor/test_interactive_bridge_mode.py`: 開始・計画・実行メッセージの日本語化を確認する。
  - `tests/unit/config/test_legacy_settings_parallelism_bridge.py`: `src.config.settings.parallelism` の既定値と環境変数上書きを確認する。
- **データの流れ / 依存関係:**
  - CLI起動 -> `start_interactive_session()` -> `msg()` -> `print_step()` -> CLI表示。
  - 環境変数 / 既定値 -> `src.config.Settings.parallelism` -> `MasterConductor.execute_with_replan()` -> `force_serial` 判定。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `mode`, `target`, `profile`, `recipe_file`, `SHIGOKU_PARALLELISM__ENABLED`, `SHIGOKU_PARALLELISM__KILL_SWITCH`
- **出力/結果 (Output):** 日本語CLI進行表示、設定可能な `settings.parallelism.enabled` / `kill_switch`
- **制約・ルール:**
  - 外部ツールの生出力、stdlib logger の内部英語ログ、JSONキーは今回も翻訳対象外とする。
  - 並列化の既定値は `enabled=False`、`kill_switch=False` を維持する。
  - `src.core.config.settings` の大規模統合は行わず、今回の不具合に必要な最小フィールドだけを `src.config.py` に追加する。
  - Cookie / Bearer token などの秘密値をログやテスト出力へ出さない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: CLI表示と並列設定配線の失敗を示す focused tests を追加し、失敗を確認する。
- [x] ステップ2: `messages.py` と `interactive_bridge.py` を最小修正し、ユーザー向け英語進行表示を日本語化する。
- [x] ステップ3: `src.config.Settings` に `ParallelismSettings` を追加し、実行ループの既存 `getattr(settings, "parallelism", None)` 判定を有効にする。
- [x] ステップ4: targeted tests、関連既存テスト、SHIGOKU docs validation、必要なら `graphify update .` を実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] `src.config.py` と `src.core.config.settings.py` の設定正本が分かれている - 今回は実行時不具合の最小修正に留め、後続で設定統合を扱う。
- [ ] [重要度:中] Injection完全並列化は安全性検証の追加が必要 - 今回は既定値を変えず、明示的な opt-in の配線確認までに留める。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0342-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
