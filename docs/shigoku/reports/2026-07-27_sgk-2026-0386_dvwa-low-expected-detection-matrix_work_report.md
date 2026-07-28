---
task_id: SGK-2026-0386
doc_type: work_report
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
- docs/shigoku/subtasks/done/2026-07-25_dvwa-low-expected-detection-matrix_subtask_plan.md
- docs/shigoku/worklogs/2026-07-27_sgk-2026-0386_dvwa-low-expected-detection-matrix_work_log.md
created_at: '2026-07-27'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA Security=low / expected detection matrix
---

# 作業報告書：DVWA low expected detection matrix

## 実装内容

- `src/reporting/expected_detection_matrix.py` に、実アプリでも起こり得る脆弱性を基準にした期待検知マトリクスを追加した。
- 比較単位を脆弱性種別・タイトル・正規化 URL とし、confirmed / candidate / 未実施を区別した。
- OOB、意味的な業務ロジック、内部トポロジーは自動検知の不足ではなく手動方針として分離した。

## 判断理由

タスク数を過去の値へ戻すことでは、実際の検知漏れや証拠不足を判断できない。DVWA 固有の教材機能への過適合を避け、現実のアプリにも成立し得る問題を基準に、以後の検知品質を比較できるようにした。

## 検証

- `.venv/bin/pytest tests/unit/reporting/test_expected_detection_matrix.py -q`
- `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md`

## リスク

- 2アカウント証明、OOB、チェーンの確証化はマトリクスの追補要件であり、このタスクだけで実装済みとは扱わない。
- 将来の検知追加では、このマトリクスを DVWA の URL 専用分岐に使わない。

## deferred_tasks

- task_id: SGK-2026-0385
  reason: 期待検知マトリクスの追補要件は、親タスクで個別の実装・テストを行う。
