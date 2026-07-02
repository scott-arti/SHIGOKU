---
task_id: SGK-2026-0328
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0303
related_docs:
- docs/shigoku/plans/done/2026-06-24_sgk-2026-0303_ollama-compat-cleanup_plan.md
- docs/shigoku/reports/2026-06-22_sgk-2026-0290_cli-japanese-localization_work_report.md
- docs/shigoku/reports/2026-06-30_SGK-2026-0328_work_report.md
- docs/shigoku/worklogs/2026-06-30_SGK-2026-0328_work_log.md
title: translate-logs削除とlog_translator廃止
created_at: '2026-06-30'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/main.py src/core/utils/log_translator.py tests/test_cli_localization.py
---

# 実装計画書：translate-logs削除とlog_translator廃止

## 1. 達成したいゴール（ユーザー視点）
- [x] CLI 利用者が `--help` を確認しても、現在は使われていない `--translate-logs` が表示されないこと。
- [x] Ollama 前提のログ後翻訳コードがコードベースから除去され、CLI 日本語化の責務が混ざらないこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/main.py`: （修正）CLI オプション定義と起動時の初期化経路
  - `src/cli/messages.py`: （修正）`argparse` help 文言の正本
  - `src/core/utils/log_translator.py`: （削除）実験的なログ後翻訳ハンドラ
  - `tests/test_cli_localization.py`: （修正）削除後の回帰確認
- **データの流れ / 依存関係:**
  - `argparse --help` -> `src.main` / `msg()` -> CLI help 出力
  - `args.translate_logs` -> `enable_log_translation()` -> `logging.Handler` 追加
  - 今回は後者の経路を完全に削除し、前者のみを正規経路として残す

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `python -m src.main --help`, `tests/test_cli_localization.py`
- **出力/結果 (Output):** obsolete flag が help に出ないこと、削除済みメッセージキーが残らないこと
- **制約・ルール:**
  - 削除は最小差分とし、CLI 日本語化そのものの既存挙動は変えない
  - 先に failing test を追加し、RED を確認してから実装する
  - 既存の role `tool_output_analysis` 利用者には触れず、`log_translator` のみを除去する

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `--translate-logs` の定義、help 文言、初期化経路、実装ファイル、関連 role 注記を棚卸しする
- [x] ステップ2: help 出力と message catalog から obsolete flag が消えることを検証する failing test を追加し、RED を確認する
- [x] ステップ3: `src/main.py`、`src/cli/messages.py`、`src/core/utils/log_translator.py` を最小差分で整理し、targeted test と docs validation を実行する

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:低] `tool_output_analysis` role 自体は他コンポーネントでも利用しているため、role ファイルは削除せず注記だけを更新する

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0328-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
