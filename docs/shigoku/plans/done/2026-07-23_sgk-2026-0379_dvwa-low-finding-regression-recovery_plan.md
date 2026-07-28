---
task_id: SGK-2026-0379
doc_type: plan
status: done
parent_task_id: SGK-2026-0378
related_docs:
- docs/shigoku/reports/2026-07-23_sgk-2026-0379_dvwa-low-finding-regression-recovery_work_report.md
- docs/shigoku/worklogs/2026-07-23_sgk-2026-0379_dvwa-low-finding-regression-recovery_work_log.md
title: DVWA low finding regression recovery
created_at: '2026-07-23'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/core/engine/master_conductor.py
---

# 実装計画書：DVWA low finding regression recovery

## 1. 達成したいゴール（ユーザー視点）
- DVWA Security=low の最新runで、旧83件run時に見つかっていた実findingの退行を防ぐ。
- SCN08〜12 の手動停止方針は正常として扱い、検知退行とは分けて判断する。
- 旧83件に存在し最新55件に欠けた `os_command_injection`、`cors_misconfiguration`、`session_fixation`、`xss_s` Stored XSS の検査経路を復元する。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: Signal-first attack task creation と legacy supplement task creation を修正。
  - `tests/core/engine/test_master_conductor_signal_recipe_routing.py`: 退行防止テストを追加。
- **データの流れ / 依存関係:**
  - Recon signal bundle / tagged JSONL -> `MasterConductor._create_attack_tasks_from_recon()` -> Attack tasks -> Injection / SessionHijacker specialists -> structured findings。

## 3. 具体的な仕様と制約条件
- `cors_candidate` は Discovery fallback ではなく CORS検査可能な InjectionSwarm に流す。
- Signal-first で `/vulnerabilities/exec/` 系URLを見た場合、旧経路と同等の `Command Injection Focused Scan` companion task を追加する。
- Signal-first で `/vulnerabilities/weak_id/` 系URLを見た場合、旧経路と同等の `Session Weak-ID Analysis` companion task を追加する。
- Signal-first / legacy supplement の Stored XSS候補では、DVWA `xss_s` のフォーム名 `txtName` / `mtxMessage` を `_context.candidate_params` として渡す。
- 83件という件数自体を目標にせず、旧runで構造化findingになっていた検査経路の漏れだけを修正する。

## 4. 実装ステップ（AIに指示する手順）
- [x] 旧83件runと最新55件runの report/session consistency を確認する。
- [x] `extract_all_findings()` で旧runと最新runのfinding差分を比較する。
- [x] CORS / Command Injection / Weak-ID / Stored XSS の欠落原因をタスク生成と実行ログから切り分ける。
- [x] 回帰テストを先に追加してREDを確認する。
- [x] `master_conductor.py` のカテゴリ表、companion task生成、Stored XSS hint付与を修正する。
- [x] 対象テストと構文チェックで検証する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:中] 実DVWA再実行でのfinding復元確認は未実施。次回runで `os_command_injection`、`cors_misconfiguration`、`session_fixation`、`xss` on `/xss_s/` が戻るか確認する。
- [ ] [重要度:低] Graphify update はAST抽出後、質問生成の betweenness centrality 計算で長時間化したため中断した。コード変更とテスト結果には影響しないが、グラフ更新は未完了。

deferred_tasks: []
