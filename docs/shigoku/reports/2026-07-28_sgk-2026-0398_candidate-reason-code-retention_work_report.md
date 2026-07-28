---
task_id: SGK-2026-0398
doc_type: work_report
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/subtasks/done/2026-07-28_reason-code_subtask_plan.md
- docs/shigoku/worklogs/2026-07-28_sgk-2026-0398_candidate-reason-code-retention_work_log.md
created_at: '2026-07-28'
updated_at: '2026-07-28'
deferred_tasks: []
---

# SGK-2026-0398 作業報告：候補重複統合のreason code保持

## 実装内容

- 共通の `FindingDeduplicator` が似た finding を統合する際、全入力の標準 reason code と evidence-quality reason code を、統合後の `reason_codes` に順序を保って残すようにした。
- レポート側の候補統合でも、明示的な reason-code 欄の未知のドメイン固有コードを捨てずに残すようにした。
- 共通統合とレポート統合の両方に、`untested_no_second_account` と `session_takeover_not_verified` が同時に残る回帰テストを追加した。

## 判断理由

High 実行の候補は、報告前の共通重複統合とレポート層の候補統合の二段階を通る。片方だけを修正すると、もう片方で保留理由が失われるため、両経路に同じ「全 reason code を保持する」契約を置いた。候補件数、重複キー、confirmed/candidate の分類、ゲート閾値は変更していない。

## 検証

- `uv run --with pytest pytest -q tests/unit/core/deduplication/test_finding_deduplicator.py tests/unit/reporting/test_haddix_submission_internal_sections.py` — 90 passed。
- `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260728_014834.md` — `consistent`。
- High の同一 session を、共通重複統合とレポート候補統合に通す読み取り専用の再評価を実施した。保存済み session には `session_takeover_not_verified` 自体が生成前から無いため、このコードを新たに作る検証ではなく、二経路の回帰テストで保持を検証した。

## リスク・未対応事項

- 既に生成済みのレポートは書き換えない。次回生成からこの保持規則が適用される。
- `original_vuln_type=session_fixation` を持つ raw finding を証拠判定で session fixation として分類する改善は本タスクの範囲外であり、reason code の保持とは別の検出分類課題として扱う。
