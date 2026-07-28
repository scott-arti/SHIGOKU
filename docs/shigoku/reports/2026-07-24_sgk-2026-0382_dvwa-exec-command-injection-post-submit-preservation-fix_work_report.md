---
task_id: SGK-2026-0382
doc_type: work_report
status: done
parent_task_id: SGK-2026-0381
related_docs:
- docs/shigoku/plans/done/2026-07-24_sgk-2026-0382_dvwa-exec-command-injection-post-submit-preservation-fix_plan.md
- docs/shigoku/worklogs/2026-07-24_sgk-2026-0382_dvwa-exec-command-injection-post-submit-preservation-fix_work_log.md
created_at: '2026-07-24'
updated_at: '2026-07-28'
---

# 作業報告書：DVWA exec command injection POST submit preservation fix

## 実装内容
- `SmartCmdSSRFHunter.run_as_tool()` で、フォーム内の `Submit` など非攻撃フィールドをPOST本文へ保持するよう修正した。
- `Submit` は `tested_params` には入れず、送信時の `context.params` にだけ残す回帰テストを追加した。

## 判断理由
- 142431 session では Command Injection finding が0件だった。
- DVWA exec への実通信で、`ip=127.0.0.1;sleep 3` だけでは処理が走らず、`Submit=Submit` を付けた場合のみ遅延と `id` 出力が確認できた。
- そのため、`ip` 候補の復旧だけでは不足で、POSTフォーム制御値の保持が必要だった。

## 検証
- `.venv/bin/pytest tests/core/agents/swarm/injection/test_specialist_parameter_hints.py::test_cmd_ssrf_run_as_tool_preserves_submit_control_for_post_forms -q` -> 1 passed
- `.venv/bin/pytest tests/core/agents/swarm/injection/test_specialist_parameter_hints.py -q` -> 8 passed
- `.venv/bin/pytest tests/core/agents/swarm/injection/test_specialist_parameter_hints.py tests/core/agents/swarm/injection/test_smart_cmd_ssrf_metadata.py tests/core/agents/swarm/injection/test_smart_xss_logic.py tests/core/agents/swarm/injection/test_target_classifier.py tests/core/agents/swarm/injection/test_manager_classification_character.py tests/core/engine/test_master_conductor_signal_recipe_routing.py -q` -> 57 passed
- `PYTHONPYCACHEPREFIX=<tmp> .venv/bin/python -m py_compile src/core/agents/swarm/injection/smart_cmd_ssrf.py tests/core/agents/swarm/injection/test_specialist_parameter_hints.py` -> OK

## リスク
- 実アプリごとに submit/token の名称は異なるため、今後もフォーム制御値は「攻撃対象から除外しつつ送信には残す」前提で扱う必要がある。

## deferred_tasks
[]
