---
task_id: SGK-2026-0339
doc_type: plan
status: done
parent_task_id: null
related_docs:
- src/core/conductor/interactive_bridge.py
- src/core/engine/master_conductor.py
- src/core/engine/master_conductor_session_service.py
- tests/core/engine/test_master_conductor_session_service.py
- tests/core/engine/test_master_conductor_bugbounty_bundle_preflight.py
- tests/unit/core/conductor/test_interactive_bridge_mode.py
- docs/shigoku/reports/2026-07-03_sgk-2026-0339_vulntest-mode-propagation-fix_work_report.md
- docs/shigoku/worklogs/2026-07-03_sgk-2026-0339_vulntest-mode-propagation-fix_work_log.md
title: Fix vulntest mode propagation in interactive bridge and session context
created_at: '2026-07-03'
updated_at: '2026-07-21'
tags:
- shigoku
- plan
target: interactive_bridge/session_mode_propagation
---

# 実装計画書：Fix vulntest mode propagation in interactive bridge and session context

## 1. 達成したいゴール（ユーザー視点）
- `--mode vulntest` で DVWA などを実行したとき、実行中の `target_info.mode` が欠落せず、後続 dispatch が `bugbounty` 既定値へ化けないこと。
- `BUG_BOUNTY` / `bug_bounty` といった内部表現でも bugbounty 判定が一貫し、scope fast-path と通常 dispatch の挙動が食い違わないこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/conductor/interactive_bridge.py`: セッション開始時の `target_info` 初期化を担当。
  - `src/core/engine/master_conductor.py`: scope fast-path と通常 dispatch の mode 解決を担当。
  - `tests/unit/core/conductor/test_interactive_bridge_mode.py`: bridge の mode 伝播を検証する回帰テスト。
  - `tests/core/engine/test_master_conductor_bugbounty_bundle_preflight.py`: `BUG_BOUNTY` fallback の正規化を検証する回帰テスト。
- **データの流れ / 依存関係:**
  - CLI `--mode` -> `start_interactive_session()` -> `mc.context.target_info["mode"]`
  - `target_info.mode` または `self.mode` -> `MasterConductor._resolve_current_mode_name()` -> scope fast-path / `_dispatch()`

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `mode` (`bugbounty|vulntest|ctf`), `target_info`, `self.mode`
- **出力/結果 (Output):**
  - `interactive_bridge` は `target_info.mode` を常に正規化済み lowercase で保存する。
  - `MasterConductor` は mode 解決を helper に集約し、`BUG_BOUNTY` と `bug_bounty` を `bugbounty` として扱う。
- **制約・ルール:**
  - 既存の scan profile 決定ロジックや task planning 数は変えない。
  - bundle preflight の fail-closed 方針は bugbounty でのみ維持する。
  - 変更は mode 伝播と mode 正規化に限定し、周辺の planner/recipe ロジックは触らない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: bridge の `target_info` 初期化と `MasterConductor` の mode 解決経路を確認する。
- [x] ステップ2: 先に回帰テストを追加し、`mode` 欠落と `BUG_BOUNTY` fallback 不一致で RED を確認する。
- [x] ステップ3: `interactive_bridge` と `MasterConductor` を最小修正し、対象テストと近傍テストを GREEN に戻す。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:中] `vulntest` 既定 profile が `bbpt` に寄る設計自体は今回の修正対象外。必要なら別タスクで profile 方針を見直す。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks: []
```

## 6. 検証計画
- RED:
  - `tests/unit/core/conductor/test_interactive_bridge_mode.py`
  - `tests/core/engine/test_master_conductor_bugbounty_bundle_preflight.py`
- GREEN / 近傍確認:
  - 上記 2 ファイルの再実行
  - `tests/unit/main/test_import_recon_cli.py`
  - `tests/core/engine/test_master_conductor_scope_fast_path.py`
  - `tests/core/engine/test_master_conductor_session_service.py`
