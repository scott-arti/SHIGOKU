---
task_id: SGK-2026-0362
doc_type: plan
status: done
parent_task_id: SGK-2026-0001
related_docs:
- docs/shigoku/reports/2026-07-15_sgk-2026-0362_work_report.md
- docs/shigoku/worklogs/2026-07-15_sgk-2026-0362_work_log.md
title: Intervention Observe Mode Deferred Prompt Root Cause Fix
created_at: '2026-07-15'
updated_at: '2026-07-21'
tags:
- shigoku
target: intervention gate observe mode
---

# 実装計画書：Intervention Observe Mode Deferred Prompt Root Cause Fix

## 1. 達成したいゴール（ユーザー視点）
- [x] `--intervention-gate-mode observe` で実行した場合、正常終了後に `Do you want to allow this action? [Y/n]:` がまとめて表示されないこと。
- [x] 強制モードでは従来どおり ExecutionSafeguard の HITL callback が対話承認を使えること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/conductor/interactive_bridge.py`: `intervention_gate_mode` を ExecutionSafeguard の HITL callback 生成に反映。
  - `tests/core/test_interactive_bridge_execution_safeguard_hitl.py`: observe/強制モードの callback 選択を回帰テスト化。
- **データの流れ / 依存関係:**
  - CLI `--intervention-gate-mode` -> `src.config.settings.intervention_gate_mode` -> InteractiveBridge -> ExecutionSafeguard RequestGuard callback。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `intervention_gate_mode` (`observe|enforce_human_preferred|enforce_hitl`)
- **出力/結果 (Output):** `observe` は非対話 auto-allow callback、強制モードは `InteractiveBridge.ask_for_approval()` callback。
- **制約・ルール:**
  - `observe` の意味を介入ゲートだけでなく ExecutionSafeguard の HITL 経路にも一貫適用する。
  - `src.core.config.settings.get_settings()` と `src.config.settings` の設定源を混同しない。
  - 既存の Bug Bounty fail-closed テストは維持する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: プロンプト文字列、ExecutionSafeguard、RequestGuard、MasterConductor intervention gate の呼び出し関係を追跡する。
- [x] ステップ2: observe callback が `ask_for_approval()` を呼ばない regression test を追加し、RED を確認する。
- [x] ステップ3: InteractiveBridge にモード正規化と callback 生成 helper を追加し、関連テストを通す。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:低] `graphify update .` で既存グラフ由来の `source_file` 欠落警告が 8 件出た。今回変更の範囲外として報告のみ。
