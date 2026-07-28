---
task_id: SGK-2026-0399
doc_type: work_report
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/subtasks/done/2026-07-28_dvwa-high_subtask_plan.md
- docs/shigoku/worklogs/2026-07-28_sgk-2026-0399_generic-capability-evaluation_work_log.md
created_at: '2026-07-28'
updated_at: '2026-07-28'
deferred_tasks: []
---

# SGK-2026-0399 作業報告：全Securityレベルの汎用検出能力評価基準

## 実装内容

- `report expected-detections`の既定を、DVWA固有の脆弱性名・URL・payloadを要求しない汎用評価にした。
- 汎用評価は、探索範囲、confirmed証拠の妥当性、candidateの保留理由、観測件数を分けて返す。
- Low専用の既存期待値matrixは削除せず、`--profile dvwa-low-regression`を明示した回帰確認だけで使うようにした。

## 判断理由

実戦投入の評価は、既知のDVWA教材を当てることではなく、対象固有の発見を証拠に応じてconfirmed/candidateへ正しく分けられるかで判定する必要がある。DVWA Lowの固定期待値は回帰検知には有用だが、既定の合否には用いない。

## 検証

- `uv run --with pytest pytest -q tests/unit/reporting/test_expected_detection_matrix.py tests/unit/scripts/test_shigoku_ops_expected_detection_cli.py` — 12 passed。
- 実Low/Medium/Highの一貫したreport/sessionに対し、`python3 scripts/shigoku_ops_cli.py --json report expected-detections --report <report>`を実行し、全て`generic_capability`かつ`status=ok`を確認した。

## リスク・未対応事項

- この評価は検出・証拠処理の健全性を測るもので、特定アプリに存在する全脆弱性を自動的に採点するものではない。
