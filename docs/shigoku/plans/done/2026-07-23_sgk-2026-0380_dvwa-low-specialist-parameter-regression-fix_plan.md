---
task_id: SGK-2026-0380
doc_type: plan
status: done
parent_task_id: SGK-2026-0379
related_docs:
- docs/shigoku/reports/2026-07-23_sgk-2026-0380_dvwa-low-specialist-parameter-regression-fix_work_report.md
- docs/shigoku/worklogs/2026-07-23_sgk-2026-0380_dvwa-low-specialist-parameter-regression-fix_work_log.md
title: DVWA low specialist parameter regression fix
created_at: '2026-07-23'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/core/agents/swarm/injection
---

# 実装計画書：DVWA low specialist parameter regression fix

## 1. 達成したいゴール（ユーザー視点）
- DVWA Security=low の最新runで、旧83件runにあった実findingのうち、タスクは存在するのに専門検査器内で空振りしている漏れを解消する。
- SCN08 / SCN10 / SCN12 は手動方針として正常扱いし、件数83への復元ではなく「旧findingの漏れ防止」を目的にする。
- `/vulnerabilities/exec/` では `ip`、`/vulnerabilities/xss_s/` では `txtName` / `mtxMessage` が優先的に試されること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/agents/swarm/injection/smart_cmd_ssrf.py`: Command Injection / SSRF specialist の候補パラメータ抽出を修正。
  - `src/core/agents/swarm/injection/smart_xss.py`: XSS specialist のStored XSS候補優先順位を修正。
  - `tests/core/agents/swarm/injection/test_specialist_parameter_hints.py`: 退行防止テストを追加。
- **データの流れ / 依存関係:**
  - Attack task params / `_context` / target URL -> specialist `run_as_tool()` -> candidate params selection -> deterministic precheck / ThoughtLoop -> structured findings。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** attack task の `params`、`_context`、target URL。
- **出力/結果 (Output):** specialist が試す `tested_params` の先頭候補が、対象画面に合った入力欄になる。
- **制約・ルール:**
  - `forms`、`url_evidence`、`scan_profile` などの管理用メタ情報を攻撃パラメータとして扱わない。
  - 旧83件runのfinding差分から、実行器内の空振りに絞って直す。
  - 破壊的ペイロードや検査範囲拡大は行わない。

## 4. 実装ステップ（AIに指示する手順）
- [x] 最新57件runと旧83件runのreport/session整合性を確認する。
- [x] 旧findingとの差分から、CORS / Session Fixationは復元済み、Command InjectionとStored XSSが残ることを確認する。
- [x] `/exec/` task と `/xss_s/` task の実行ログから、試行パラメータが外れていることを確認する。
- [x] REDテストを追加する。
- [x] `SmartCmdSSRFHunter` と `SmartXSSHunter` の候補パラメータ選定を修正する。
- [x] 対象・関連テストと構文チェックで検証する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] 実DVWA再実行は未実施。次回runで `/vulnerabilities/exec/` と `/vulnerabilities/xss_s/` のfinding復元を確認する。
- [ ] [重要度:低] 旧83件runと完全同一の件数にはならない可能性がある。評価軸は件数ではなく、旧finding種別・URL・パラメータ相当の漏れ有無とする。

deferred_tasks:
  - deferred_id: SGK-2026-0380-D01
    title: "DVWA low実runでのfinding復元確認"
    reason: "コード上の候補選定は修正・テスト済みだが、実DVWAへの再実行結果は未確認"
    impact: medium
    tracking_task_id: SGK-2026-0379
    recommended_next_action: "次回DVWA low runでCommand InjectionとStored XSSのfinding復元を確認する"
