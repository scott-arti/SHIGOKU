---
task_id: SGK-2026-0383
doc_type: work_report
status: done
parent_task_id: SGK-2026-0382
related_docs:
- docs/shigoku/plans/done/2026-07-24_sgk-2026-0383_smartcmdssrf-finish-safe-verdict-false-positive-fix_plan.md
- docs/shigoku/worklogs/2026-07-24_sgk-2026-0383_smartcmdssrf-finish-safe-verdict-false-positive-fix_work_log.md
created_at: '2026-07-24'
updated_at: '2026-07-28'
title: SmartCmdSSRF finish safe verdict false positive fix work report
---

# 作業報告書：SmartCmdSSRF finish safe verdict false positive fix

## 実装内容

- `SmartCmdSSRFHunter.act()` の `finish` 判定を、単純な文字列包含判定から明示的な verdict 判定へ変更した。
- `{"status": "Safe", "reason": "... not vulnerable ..."}` のような安全判定が `os_command_injection` finding として登録されない回帰テストを追加した。

## 判断理由

`session_20260723_162936.json` では `DVWA exec / ip` の command injection は raw finding として復旧していた。一方で、`open_redirect/password` について証拠本文が安全判定を示しているにもかかわらず、本文内の `vulnerable` という単語だけで `self.vulnerable` が立つ誤検知経路が見つかったため、判定を厳密化した。

## 検証

- `.venv/bin/pytest tests/core/agents/swarm/injection/test_specialist_parameter_hints.py::test_cmd_ssrf_finish_safe_json_with_not_vulnerable_text_stays_safe -q`
  - RED: 既存実装では `hunter.vulnerable is True` となり失敗
  - GREEN: 修正後 `1 passed`
- `.venv/bin/pytest tests/core/agents/swarm/injection/test_specialist_parameter_hints.py tests/core/agents/swarm/injection/test_smart_cmd_ssrf_metadata.py -q`
  - `13 passed`
- `.venv/bin/pytest tests/core/agents/swarm/injection/test_specialist_parameter_hints.py tests/core/agents/swarm/injection/test_smart_cmd_ssrf_metadata.py tests/core/agents/swarm/injection/test_smart_xss_logic.py tests/core/agents/swarm/injection/test_target_classifier.py tests/core/agents/swarm/injection/test_manager_classification_character.py tests/core/engine/test_master_conductor_signal_recipe_routing.py -q`
  - `58 passed`
- `PYTHONPYCACHEPREFIX=<tmp> .venv/bin/python -m py_compile src/core/agents/swarm/injection/smart_cmd_ssrf.py tests/core/agents/swarm/injection/test_specialist_parameter_hints.py`
  - 成功
- `docker compose run --rm --no-deps shigoku python3 - <<'PY' ...`
  - `container_safe_vulnerable False`

## リスク

- LLM の自由文 `finish` は表現ゆれがあり得るため、今後も代表的な verdict 形式をテストへ追加する余地がある。
- 既存の docs validation には、今回とは無関係な `task_268_missing_file:docs/shigoku/subtasks/2026-06-03_sgk-2026-0258_temporal-followup_subtask_plan.md` が残っている。

## deferred_tasks

```yaml
deferred_tasks: []
```
