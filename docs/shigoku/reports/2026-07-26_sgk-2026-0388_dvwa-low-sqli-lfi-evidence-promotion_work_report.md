---
task_id: SGK-2026-0388
doc_type: work_report
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
- docs/shigoku/subtasks/done/2026-07-25_dvwa-low-sqli-and-lfi-evidence-promotion_subtask_plan.md
- docs/shigoku/worklogs/2026-07-26_sgk-2026-0388_dvwa-low-sqli-lfi-evidence-promotion_work_log.md
created_at: '2026-07-26'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA Security=low / SQLi LFI evidence quality
---

# 作業報告書：DVWA low SQLi / LFI evidence promotion

## 実装内容

- `SmartSQLiHunter` が SQL error / DB 推定 / response differential / PoC request / response を finding の `additional_info` に保存するようにした。
- blind SQLi の time-based precheck を、単発 sleep ではなく baseline 3 回、positive 3 回、inverse condition 1 回の timing samples 保存へ変更した。
- `SmartLFIHunter` が `file_marker_excerpt`、`target_file`、payload 入り request URL、PoC request / response、payload delivery telemetry を保存するようにした。
- LFI の実レスポンスから、マッチしたパターン名だけでなく実際のファイル断片を抽出するようにした。

## 判断理由

直近の DVWA low 実行では SQLi / LFI finding 自体は出ていたが、Haddix evidence quality gate が読むための構造化証拠が不足して candidate に落ちていた。検知数を増やすより、既存検知を提出品質の evidence に変換する方が TaskC の目的に合っている。

## 検証

- `.venv/bin/pytest tests/core/agents/swarm/injection/test_smart_lfi.py tests/core/agents/swarm/injection/test_smart_sqli_evidence.py tests/core/agents/swarm/test_smart_cmd_ssrf.py -q`
- `.venv/bin/pytest tests/unit/reporting/test_haddix_evidence_quality_gate.py -q`
- `.venv/bin/pytest tests/core/agents/swarm/injection/test_manager_p1_metadata.py -q`
- `PYTHONPYCACHEPREFIX=/tmp/shigoku-taskc-pycache .venv/bin/python -m py_compile src/core/agents/swarm/injection/smart_lfi.py src/core/agents/swarm/injection/smart_sqli.py src/core/agents/swarm/injection/smart_cmd_ssrf.py`
- `.venv/bin/python scripts/shigoku_ops_cli.py --json report consistency --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260725_153346.md`

## リスク

- 過去のレポートは再生成していないため、この作業だけでは既存レポートの candidate 数は変わらない。
- SQLi boolean true / false 差分、OOB callback、LFI wrapper / chain_builder 連携は未対応。

## deferred_tasks

- task_id: SGK-2026-0390
  reason: XSS の browser execution evidence は別スライスで実装する。
- task_id: SGK-2026-0388
  reason: SQLi boolean 差分、OOB preflight、LFI wrapper / chain_builder 連携は後続スライスに残す。

## 2026-07-26 追補

通常 SQLi の確定昇格バグを修正した。実レスポンスに MariaDB/MySQL の SQL syntax error が出ているのに分類器が `none` を返すケースで、response diff から SQL error evidence を補完する。

追加検証:

- `.venv/bin/pytest tests/core/agents/swarm/injection/test_smart_sqli_evidence.py`
