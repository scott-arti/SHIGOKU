---
task_id: SGK-2026-0389
doc_type: work_report
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
- docs/shigoku/subtasks/done/2026-07-25_dvwa-low-command-injection-evidence-promotion_subtask_plan.md
- docs/shigoku/worklogs/2026-07-26_sgk-2026-0389_dvwa-low-command-injection-evidence-promotion_work_log.md
created_at: '2026-07-26'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA Security=low / Command Injection evidence quality
---

# 作業報告書：DVWA low Command Injection evidence promotion

## 実装内容

- `SmartCmdSSRFHunter` が command output 型の evidence を `command_execution_evidence.output_observed` として保存するようにした。
- time-based command injection を baseline 3 回、positive 3 回、inverse condition 1 回の timing samples で保存するようにした。
- `blind_correlation.time_based.timing_samples` と `command_execution_evidence.timing_samples` の両方へ比較証拠を残すようにした。
- payload delivery telemetry と PoC request / response を finding に保存するようにした。

## 判断理由

直近の DVWA low 実行では Command Injection finding は出ていたが、`command_execution_evidence` が無く、Haddix evidence quality gate では攻撃成功の証明として扱えなかった。提出品質では「実行できた」か「攻撃時だけ遅延した」ことを構造化して残す必要がある。

## 検証

- `.venv/bin/pytest tests/core/agents/swarm/injection/test_smart_lfi.py tests/core/agents/swarm/injection/test_smart_sqli_evidence.py tests/core/agents/swarm/test_smart_cmd_ssrf.py -q`
- `.venv/bin/pytest tests/unit/reporting/test_haddix_evidence_quality_gate.py -q`
- `.venv/bin/pytest tests/core/agents/swarm/injection/test_manager_p1_metadata.py -q`
- `PYTHONPYCACHEPREFIX=/tmp/shigoku-taskc-pycache .venv/bin/python -m py_compile src/core/agents/swarm/injection/smart_lfi.py src/core/agents/swarm/injection/smart_sqli.py src/core/agents/swarm/injection/smart_cmd_ssrf.py`
- `.venv/bin/python scripts/shigoku_ops_cli.py --json report consistency --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260725_153346.md`

## リスク

- 過去のレポートは再生成していないため、この作業だけでは既存レポートの candidate 数は変わらない。
- メタ文字行列全体の reason code 化と OOB callback は未対応。

## deferred_tasks

- task_id: SGK-2026-0389
  reason: メタ文字行列と OOB preflight は後続スライスに残す。
- task_id: SGK-2026-0390
  reason: XSS browser execution evidence は別スライスで扱う。
