---
task_id: SGK-2026-0394
doc_type: work_report
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/subtasks/done/2026-07-27_candidate-gate-fail_subtask_plan.md
- AGENTS.md
- rules/reporting.md
- docs/shigoku/worklogs/2026-07-27_sgk-2026-0394_candidate-gate-fail-safe-hold_work_log.md
created_at: '2026-07-27'
updated_at: '2026-07-28'
tags:
- shigoku
- reporting
- gate
target: AI coding guardrail for known DVWA low candidate gate state
---

# 作業報告書：Candidate gate FAIL の正常状態をAIルールへ明記

## 実装内容

- `AGENTS.md` に、DVWA low の既知ベースラインでは候補5件による `candidate_above_maximum` が安全側の保留であり、単独では検知回帰や実装不具合ではないことを追加した。
- 同じ規則を `rules/reporting.md` に追加し、レポート・ゲート変更時に動的ロードするAIにも適用した。
- AIが候補数を減らすだけの修正、根拠のないconfirmed昇格、候補抑制、重複統合の拡張、`candidate_max` の緩和を始めないよう明記した。
- 再調査の条件を、candidate数またはreason codeの変化、必須confirmedの欠落、またはユーザーによる実証・方針変更の明示依頼に限定した。

## 判断理由

最新の整合済み DVWA low 実行では、18件がconfirmed、5件がcandidateであり、gateは `candidate_above_maximum` によりFAILとなる。この5件は、2アカウント証明・APIデータの機密性証明・CSRF状態変化証明が不足した未確定事項である。

このFAILをPASSにするためだけの修正は、不確実性を隠してしまう。AIが新しい会話でこの結果を見ても、既知の安全側保留として扱えるよう、全コーディング作業で読む `AGENTS.md` に明記する必要があった。

## 検証

- `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md`
  - 結果: `status=consistent`, `rerun_required=false`, `reason_codes=[]`
- `python3 scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md`
  - 結果: `status=fail`, `reason_codes=["candidate_above_maximum"]`, `confirmed_count=18`, `candidate_count=5`
- `AGENTS.md` と `rules/reporting.md` に、既知状態・禁止する対症療法・再調査条件が同じ内容で存在することを検索で確認した。

## リスク

- この規則はDVWA lowの指定ベースラインに限定する。他の対象、候補数の変化、新しいreason code、必須confirmedの欠落には適用しない。
- 候補5件の実害確認は未実施であり、confirmed vulnerabilityとして扱わない。

## deferred_tasks

- deferred_id: SGK-2026-0394-D01
  title: "候補5件の実害を必要時に証明または除外する"
  reason: "本タスクはAIの修正判断ガードレールのみを扱う。追加証拠の取得はユーザーの明示依頼時に行う。"
  impact: medium
  tracking_task_id: SGK-2026-0385
  recommended_next_action: "2アカウント比較、CSRFの状態変化、API/CORSの機密性・実害を個別に検証する。"
