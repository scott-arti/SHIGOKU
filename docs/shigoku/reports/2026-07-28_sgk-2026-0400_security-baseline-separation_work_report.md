---
task_id: SGK-2026-0400
doc_type: work_report
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/subtasks/done/2026-07-28_security_subtask_plan.md
- docs/shigoku/worklogs/2026-07-28_sgk-2026-0400_security-baseline-separation_work_log.md
created_at: '2026-07-28'
updated_at: '2026-07-28'
deferred_tasks: []
---

# SGK-2026-0400 作業報告：Securityレベル別レポート基準線の分離

## 実装内容

- report gateが保存済み基準線を使う前に、現在sessionとbaseline sessionのSecurityレベルをCookieから照合するようにした。
- レベルが異なるときは古い基準線を使わず、現在のreport/sessionを自己基準線として評価する。
- Low基準線がHigh評価へ流用されて`regression_confirmed_drop`を出さない回帰テストを追加した。

## 判断理由

LowとHighは同じ対象でも防御条件が異なるため、confirmed件数の差を回帰と解釈できない。比較対象を同一Securityレベルに限定し、不一致時は安全側に比較を止める。

## 検証

- `uv run --with pytest pytest -q tests/unit/reporting/test_initial_release_gate.py tests/unit/reporting/test_expected_detection_matrix.py tests/unit/scripts/test_shigoku_ops_expected_detection_cli.py` — 50 passed（既存のpytest設定警告1件のみ）。
- `python3 scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260728_073509.md` — FAIL理由は`candidate_above_maximum`のみで、`regression_confirmed_drop`はなし。

## リスク・未対応事項

- Security Cookieが保存されないsessionはレベル照合できない。その場合も古い異レベル基準線を流用せず、自己基準線で評価する。
