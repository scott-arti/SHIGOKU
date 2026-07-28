---
task_id: SGK-2026-0380
doc_type: work_report
status: done
parent_task_id: SGK-2026-0379
related_docs:
- docs/shigoku/plans/done/2026-07-23_sgk-2026-0380_dvwa-low-specialist-parameter-regression-fix_plan.md
- docs/shigoku/worklogs/2026-07-23_sgk-2026-0380_dvwa-low-specialist-parameter-regression-fix_work_log.md
title: DVWA low specialist parameter regression fix work report
created_at: '2026-07-23'
updated_at: '2026-07-28'
---

# 作業報告書：DVWA low specialist parameter regression fix

## 実装内容
- 最新57件runと旧83件runのreport/session consistencyを確認し、どちらも `consistent` であることを確認した。
- `extract_all_findings()` の差分では、CORS / Session Fixationは最新runで復元済みだった。
- 残っていた旧finding相当の漏れを、`/vulnerabilities/exec/` のCommand Injectionと `/vulnerabilities/xss_s/` のStored XSSに絞り込んだ。
- `src/core/agents/swarm/injection/smart_cmd_ssrf.py` で、manager由来のメタ情報を攻撃パラメータから除外し、DVWA command injection画面では `ip` を優先候補にした。
- `src/core/agents/swarm/injection/smart_xss.py` で、DVWA stored XSS画面では `txtName` / `mtxMessage` を優先し、`_context.discovered_params` の汎用候補より前に試すようにした。
- 回帰テストを `tests/core/agents/swarm/injection/test_specialist_parameter_hints.py` に追加した。

## 判断理由
- 最新57件runでは、`/vulnerabilities/exec/` の `Command Injection Focused Scan` task自体は存在したが、phase1の `tested_params` が `ip` に届いていなかった。
- 最新57件runでは、`/vulnerabilities/xss_s/` のXSS task自体は存在したが、`tested_params` が `name` / `page` / `redirect` / `id` などに偏り、DVWA stored XSSで重要な `txtName` / `mtxMessage` が優先されていなかった。
- そのため、タスク生成数の不足ではなく、専門検査器内部の入力欄選択が残りの根本原因と判断した。

## 検証
- RED:
  - `.venv/bin/pytest tests/core/agents/swarm/injection/test_specialist_parameter_hints.py -q`
  - 結果: 4 failed。メタ情報除外、`ip` hint、`txtName` / `mtxMessage` hintが未実装で期待どおり失敗。
- GREEN:
  - `.venv/bin/pytest tests/core/agents/swarm/injection/test_specialist_parameter_hints.py -q`
  - 結果: 6 passed。
- 関連テスト:
  - `.venv/bin/pytest tests/core/agents/swarm/injection/test_specialist_parameter_hints.py tests/core/agents/swarm/injection/test_smart_cmd_ssrf_metadata.py tests/core/agents/swarm/injection/test_smart_xss_logic.py tests/core/agents/swarm/injection/test_target_classifier.py tests/core/agents/swarm/injection/test_manager_classification_character.py tests/core/engine/test_master_conductor_signal_recipe_routing.py -q`
  - 結果: 55 passed。
- 構文チェック:
  - `PYTHONPYCACHEPREFIX=<tmp> .venv/bin/python -m py_compile src/core/agents/swarm/injection/smart_cmd_ssrf.py src/core/agents/swarm/injection/smart_xss.py tests/core/agents/swarm/injection/test_specialist_parameter_hints.py`
  - 結果: pass。
- 実アーティファクト確認:
  - `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260723_060612.md`
  - 結果: `status=consistent`, `rerun_required=false`, `reason_codes=[]`。
  - `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260717_222441.md`
  - 結果: `status=consistent`, `rerun_required=false`, `reason_codes=[]`。

## 残っているリスク
- 実DVWA再実行は未実施。既存の過去セッション結果は変更されないため、次回runでfinding復元を確認する必要がある。
- 件数が旧83件と一致するとは限らない。今回の評価軸は「旧finding相当が漏れていないか」であり、Total Tasks数そのものではない。
- SCN08 / SCN10 / SCN12 は手動方針のため、今回の修正対象外。

## 次のステップ
- 次回DVWA low runで、少なくとも以下を確認する。
  - `Command Injection/SSRF in parameter 'ip'` on `/vulnerabilities/exec/`
  - `XSS in parameter 'mtxMessage'` またはStored XSS相当 on `/vulnerabilities/xss_s/`

deferred_tasks:
  - deferred_id: SGK-2026-0380-D01
    title: "DVWA low実runでのfinding復元確認"
    reason: "コード上の候補選定は修正・テスト済みだが、実DVWAへの再実行結果は未確認"
    impact: medium
    tracking_task_id: SGK-2026-0379
    recommended_next_action: "次回DVWA low runでCommand InjectionとStored XSSのfinding復元を確認する"
