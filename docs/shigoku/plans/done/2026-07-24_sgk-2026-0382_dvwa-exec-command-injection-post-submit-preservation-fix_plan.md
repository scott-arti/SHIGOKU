---
task_id: SGK-2026-0382
doc_type: plan
status: done
parent_task_id: SGK-2026-0381
related_docs:
- docs/shigoku/reports/2026-07-24_sgk-2026-0382_dvwa-exec-command-injection-post-submit-preservation-fix_work_report.md
- docs/shigoku/worklogs/2026-07-24_sgk-2026-0382_dvwa-exec-command-injection-post-submit-preservation-fix_work_log.md
title: DVWA exec command injection POST submit preservation fix
created_at: '2026-07-24'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/core/agents/swarm/injection/smart_cmd_ssrf.py
---

# 実装計画書：DVWA exec command injection POST submit preservation fix

## 1. 達成したいゴール（ユーザー視点）
- [x] DVWA Security=low の Command Injection 画面で、`ip` パラメータに対する OS Command Injection を再び検知できる入力形に戻す。
- [x] `Submit` などのフォーム制御フィールドを攻撃対象にはしないが、POST リクエスト本文には保持する。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/agents/swarm/injection/smart_cmd_ssrf.py`: Command Injection / SSRF specialist の送信パラメータ構築。
  - `tests/core/agents/swarm/injection/test_specialist_parameter_hints.py`: DVWA exec のPOSTフォーム回帰テスト。
- **データの流れ / 依存関係:**
  - InjectionManager task params -> SmartCmdSSRFHunter.run_as_tool -> HTML form解析 -> POST request params -> deterministic precheck / ThoughtLoop。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** DVWA exec URL, Cookie, HTML form fields (`ip`, `Submit`)。
- **出力/結果 (Output):** `tested_params` は `ip` 優先、POST本文は `Submit=Submit` を保持。
- **制約・ルール:**
  - `Submit` / CSRF token 類は攻撃対象パラメータとして扱わない。
  - ただし対象アプリが処理を開始するために必要なフォーム制御値は送信から落とさない。
  - 変更は SmartCmdSSRFHunter のパラメータ構築に限定する。

## 4. 実装ステップ（AIに指示する手順）
- [x] 142431 session の raw execution log で Command Injection finding が無いことを確認する。
- [x] DVWA exec 実通信で `Submit` 有無による sleep/id の差を確認する。
- [x] `Submit` を攻撃対象から除外しつつPOST本文へ保持するREDテストを追加する。
- [x] SmartCmdSSRFHunter の form field 処理を修正する。
- [x] 対象テストと関連テストを実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- なし。本タスクの範囲では継続監視タスクは作成しない。
