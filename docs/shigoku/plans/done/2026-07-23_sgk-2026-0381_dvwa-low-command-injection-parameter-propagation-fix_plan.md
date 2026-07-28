---
task_id: SGK-2026-0381
doc_type: plan
status: done
parent_task_id: SGK-2026-0380
related_docs:
- docs/shigoku/reports/2026-07-23_sgk-2026-0381_dvwa-low-command-injection-parameter-propagation-fix_work_report.md
- docs/shigoku/worklogs/2026-07-23_sgk-2026-0381_dvwa-low-command-injection-parameter-propagation-fix_work_log.md
title: DVWA low command injection parameter propagation fix
created_at: '2026-07-23'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/core/agents/swarm/injection
---

# 実装計画書：DVWA low command injection parameter propagation fix

## 1. 達成したいゴール（ユーザー視点）
- DVWA low の0751runで残ったCommand Injection漏れを、実行器の入力欄選択で解消する。
- `/vulnerabilities/exec/` の専用タスクに、タスク管理用の `target` / `_strategy` などが混じっても、実際の検査候補は `ip` から始まるようにする。
- Total Tasks数ではなく、旧83件runで出ていた `Command Injection/SSRF in parameter 'ip'` の復元を確認軸にする。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/agents/swarm/injection/smart_cmd_ssrf.py`: Command Injection / SSRF specialist のタスクメタ除外と `/exec/` 候補順を修正。
  - `tests/core/agents/swarm/injection/test_specialist_parameter_hints.py`: 0751run相当paramsの退行防止テストを追加。
- **データの流れ / 依存関係:**
  - `Command Injection Focused Scan` task params -> `InjectionManager.run_cmd_ssrf_hunter()` -> `SmartCmdSSRFHunter.run_as_tool()` -> `tested_params` -> deterministic precheck / finding。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** target URL、task params、`_context.discovered_params`。
- **出力/結果 (Output):** `/vulnerabilities/exec/` では `tested_params` が `ip`, `host`, `cmd`, `command` の順で始まる。
- **制約・ルール:**
  - `target`、`task_name`、`_strategy`、`_intervention` などのタスク管理項目を攻撃パラメータ扱いしない。
  - 汎用の `redirect` / `id` / `page` / `doc` より、対象画面固有の `ip` を優先する。
  - LLMの文章上の「見つけた」ではなく、構造化findingに残る検知を目標にする。

## 4. 実装ステップ（AIに指示する手順）
- [x] 0751runのreport/session consistencyを確認する。
- [x] 生finding差分でStored XSSは復元済み、Command Injectionが未復元であることを確認する。
- [x] 0751runの `cmd_focus` taskから `tested_params` が `redirect,id,page,doc,data` で止まっていることを確認する。
- [x] 0751run相当paramsのREDテストを追加する。
- [x] `SmartCmdSSRFHunter` のタスクメタ除外と `/exec/` 候補順を修正する。
- [x] 対象テスト・関連テスト・構文チェックで検証する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] 実DVWA再実行は未実施。次回runで `Command Injection/SSRF in parameter 'ip'` が復元するか確認する。

deferred_tasks:
  - deferred_id: SGK-2026-0381-D01
    title: "DVWA low Command Injection finding復元確認"
    reason: "コード上の候補順は修正済みだが、実DVWA runは未確認"
    impact: medium
    tracking_task_id: SGK-2026-0379
    recommended_next_action: "次回DVWA low runでCommand Injection findingの有無を確認する"
