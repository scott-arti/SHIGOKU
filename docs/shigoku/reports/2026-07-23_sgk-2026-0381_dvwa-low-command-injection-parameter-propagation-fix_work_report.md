---
task_id: SGK-2026-0381
doc_type: work_report
status: done
parent_task_id: SGK-2026-0380
related_docs:
- docs/shigoku/plans/done/2026-07-23_sgk-2026-0381_dvwa-low-command-injection-parameter-propagation-fix_plan.md
- docs/shigoku/worklogs/2026-07-23_sgk-2026-0381_dvwa-low-command-injection-parameter-propagation-fix_work_log.md
title: DVWA low command injection parameter propagation fix work report
created_at: '2026-07-23'
updated_at: '2026-07-28'
---

# 作業報告書：DVWA low command injection parameter propagation fix

## 実装内容
- 0751runと旧83件runのreport/session consistencyを確認し、どちらも `consistent` であることを確認した。
- 生finding比較で、0751runはStored XSSが復元済みで、Command Injectionだけが未復元であることを確認した。
- 0751runの `Command Injection Focused Scan` taskを確認し、`tested_params` が `redirect` / `id` / `page` / `doc` / `data` になっており、旧findingで必要な `ip` を試していないことを確認した。
- 0751run相当のtask paramsを `SmartCmdSSRFHunter.run_as_tool()` に渡す回帰テストを追加した。
- `src/core/agents/swarm/injection/smart_cmd_ssrf.py` で、タスク管理用メタ項目を攻撃パラメータから除外した。
- `/vulnerabilities/exec/` では `ip`, `host`, `cmd`, `command` の順で候補を作るようにした。

## 判断理由
- Total Tasksが57のままなのは今回の修正範囲では正常。前回修正はタスク数ではなくタスク内部の検査候補を直すものだった。
- 0751runで raw findings は21から22に増え、`/vulnerabilities/xss_s/` の `XSS in parameter 'txtName'` が復元していた。
- 一方で、`/vulnerabilities/exec/` は専用タスクが存在するにもかかわらず、構造化findingが0だった。
- 旧83件runでは、risk-forced深掘り中の `run_cmd_ssrf_hunter` が `ip` でfindingを作っていた。0751runではLLMが文章では「見つけた」と書いたが、ツール実行の構造化結果が残っていなかった。
- そのため、LLM深掘りに頼らず、phase1の候補選択時点で `ip` を先頭に戻す必要があると判断した。

## 検証
- RED:
  - `.venv/bin/pytest tests/core/agents/swarm/injection/test_specialist_parameter_hints.py -q`
  - 結果: 1 failed, 6 passed。0751run相当paramsで `target` 等の管理項目が `ip` より前に来ることを確認。
- GREEN:
  - `.venv/bin/pytest tests/core/agents/swarm/injection/test_specialist_parameter_hints.py -q`
  - 結果: 7 passed。
- 実paramsリプレイ:
  - 0751runの `cmd_focus_3ac87fae` paramsを現在コードに渡した結果、`tested_params=['ip', 'host', 'cmd', 'command', 'redirect']` になることを確認。
- 関連テスト:
  - `.venv/bin/pytest tests/core/agents/swarm/injection/test_specialist_parameter_hints.py tests/core/agents/swarm/injection/test_smart_cmd_ssrf_metadata.py tests/core/agents/swarm/injection/test_smart_xss_logic.py tests/core/agents/swarm/injection/test_target_classifier.py tests/core/agents/swarm/injection/test_manager_classification_character.py tests/core/engine/test_master_conductor_signal_recipe_routing.py -q`
  - 結果: 56 passed。
- 構文チェック:
  - `PYTHONPYCACHEPREFIX=<tmp> .venv/bin/python -m py_compile src/core/agents/swarm/injection/smart_cmd_ssrf.py src/core/agents/swarm/injection/smart_xss.py tests/core/agents/swarm/injection/test_specialist_parameter_hints.py`
  - 結果: pass。

## 残っているリスク
- 実DVWA再実行は未実施。次回runでCommand Injection findingが復元するか確認する必要がある。
- 旧83件runではrisk-forced深掘りでfinding化していたが、今回の修正はphase1側で `ip` を先頭に戻すもの。これにより深掘りへの依存を下げるが、実run確認は必要。
- SCN08 / SCN10 / SCN12 は手動方針のため、今回の修正対象外。

## 次のステップ
- 次回DVWA low runで `Command Injection/SSRF in parameter 'ip'` on `/vulnerabilities/exec/` が復元するか確認する。

deferred_tasks:
  - deferred_id: SGK-2026-0381-D01
    title: "DVWA low Command Injection finding復元確認"
    reason: "コード上の候補順は修正済みだが、実DVWA runは未確認"
    impact: medium
    tracking_task_id: SGK-2026-0379
    recommended_next_action: "次回DVWA low runでCommand Injection findingの有無を確認する"
