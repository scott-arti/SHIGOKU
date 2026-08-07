---
task_id: SGK-2026-0415
doc_type: plan
status: done
parent_task_id: null
related_docs:
- src/core/config/settings.py
- src/recon/tool_runner.py
- src/recon/pipeline.py
- src/tools/custom/httpx.py
- src/core/engine/master_conductor.py
- tests/recon/test_step3_livecheck.py
- tests/core/engine/test_master_conductor_execution_admission.py
- tests/unit/config/test_tool_command_resolution.py
- tests/unit/test_robustness_phase4.py
title: 外部ツール実行契約と偵察結果表示の整合性修正
created_at: '2026-07-31'
updated_at: '2026-08-07'
tags:
- shigoku
target: Tool command resolution, recon proxy propagation, and MasterConductor outcome
  display
---

# 実装計画書：外部ツール実行契約と偵察結果表示の整合性修正

## 1. 達成したいゴール（ユーザー視点）
  - [x] ローカルURLへの偵察を開始すると、空のツール設定によって外部コマンド起動が失敗せず、設定済みまたは標準の実行ファイルを一貫して使うこと。
  - [x] プロキシを明示設定していない場合、偵察のURL探索が暗黙のCaidoプロキシへ強制送信されないこと。
  - [x] 偵察を含むタスクが失敗して終了した場合、実行終了は保存されつつも「正常に完了」と表示されないこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/config/settings.py`: 空白を含む未指定のツールパスを、安全な標準コマンドへ解決する単一の設定処理を追加する。
  - `src/recon/tool_runner.py`: 本番の外部コマンド起動前に空の実行ファイルを明示的に拒否し、OS依存の曖昧なエラーを防ぐ。
  - `src/recon/pipeline.py`: 解決済みのhttpxコマンドを、存在確認と起動の両方に使う。プロキシは `get_proxy_url()` の結果だけを使う。
  - `src/tools/custom/httpx.py`: 同じ解決済みhttpxコマンドを使う。
  - `src/core/engine/master_conductor.py`: 既存の正常シャットダウン判定とは別に、利用者向けの成功・失敗あり・未完了を表す結果状態を追加する。
  - `tests/unit/config/test_tool_command_resolution.py`, `tests/recon/test_step3_livecheck.py`, `tests/unit/test_robustness_phase4.py`, `tests/core/engine/test_master_conductor_execution_admission.py`: 設定の優先順位、空設定、プロキシ、実行入口、表示結果を回帰テストする。
- **データの流れ / 依存関係:**
  - 設定または実行時上書き -> ツールコマンド解決 -> 同じ値で存在確認 -> `ToolRunner` 実行 -> 偵察成果物
  - タスク終端状態 -> 既存 `completion_status` -> 追加の利用者向け結果状態 -> 終了メッセージ

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `tool_httpx_path`（任意文字列）、パイプライン設定辞書、`Settings.get_proxy_url()`（任意URL）、タスクの終端状態。
- **出力/結果 (Output):** 実行用の単一コマンド文字列、明示的な設定エラー、プロキシの有無、利用者向けの結果状態。
- **制約・ルール:**
  - 空文字・空白だけのツールパスは、現在の `dict.get(..., "httpx")` が意図していた「未指定」の意味として標準コマンドへ解決する。ツール無効化の意味には使わない。
  - 明示された独自の実行ファイルパスはそのまま保持し、シェル文字列として分割・展開しない。
  - 開発モードのモック実行は、既存どおりコマンド検証より先に動作する。
  - `Settings.get_proxy_url()` が `None` のとき、Step 3bでプロキシを強制しない。明示プロキシは従来どおり全関連ツールへ渡す。
  - `completion_status` の既存意味（未完了タスクの有無）は変更しない。追加の結果状態で表示だけを正確にする。
  - 新規の外部ツールや依存ライブラリ、Juice Shop固有の分岐、レポート／セッション既存フィールドの改名は行わない。

## 4. 実装ステップ（AIに指示する手順）
  - [x] ステップ1: 既存設定・ツール実行・プロキシ・終了処理の契約をテストで再現し、空設定・独自パス・開発モード・明示／未設定プロキシ・失敗あり終端を検証する。
  - [x] ステップ2: 設定の共通コマンド解決、`ToolRunner` の空コマンド拒否、httpx利用箇所、Step 3bのプロキシ、利用者向け結果状態を最小限に修正する。
  - [x] ステップ3: 対象テスト、関連する偵察・設定・終了処理テスト、構文検査、知識グラフ、文書・台帳検証を実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [x] [重要度:高] 空設定をツール無効化として利用している既存経路 - 現行のhttpx探索は空値でも標準名で存在確認しており、空値を有効な無効化状態として扱っていないことを確認した。標準コマンドへの解決をテストで固定する。
- [x] [重要度:高] 独自パス・パス中の空白の破壊 - 解決値は単一の実行ファイル文字列として扱い、`shlex.split` やシェル実行を導入しない。
- [x] [重要度:中] 開発モードのテスト／デモを壊すこと - `ToolRunner` の空コマンド検証は実コマンドを起動する本番分岐だけに置く。
- [x] [重要度:高] 未設定プロキシを暗黙に強制すること - 既存テストが「既定Caido URLはプロキシを強制しない」と規定しているため、同じ設定正本へ統一する。
- [x] [重要度:高] 終了表示の修正が中断セッション保存を変えること - `_finished_normally` は既存のシャットダウン用途のまま維持し、利用者向けの結果状態を別にする。
- [x] [重要度:中] SPAのブラウザ内ルートを網羅する機能 - 今回の停止原因ではないため、アプリ名やフラグメント形式に依存する分岐は追加しない。修正後の汎用的な再実行で、なお成果物が無い場合だけ別タスクとして必要性を判断する。

## 6. 実装前レビュー

- **判定:** APPROVE WITH CHANGES（以下の安全条件を実装時に必須とする）。
- **既存機構の再利用:** `Settings` は設定の正本、`ToolRunner` は偵察の本番／開発モード境界、`get_proxy_url()` はプロキシの正本、`completion_status` は未完了判定として再利用する。
- **採用しない案:** `src/core/adapters/external/` のインストール用設定スキーマへ偵察経路を一括移行しない。現在の問題は実行時の設定解決であり、移行は広範囲の後方互換性リスクを増やす。
- **安全性:** スコープ判定、レート制限、タイムアウト、引数リストによるサブプロセス起動を変更しない。プロキシを未設定時に追加しないため、通信先を広げない。
- **終了処理:** 新しい結果状態は追加フィールドと表示だけに使い、`_finished_normally` の既存のセッション保存用途を変えない。
- **実装可否:** 上記の回帰テストを先に追加し、修正前に失敗することを確認できた場合にのみコードを変更する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0415-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
