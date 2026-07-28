---
task_id: SGK-2026-0373
doc_type: work_report
status: done
parent_task_id: SGK-2026-0372
related_docs:
- docs/shigoku/plans/done/2026-07-22_sgk-2026-0373_signal-first-attack-generation-gap-integration_plan.md
- docs/shigoku/worklogs/2026-07-22_sgk-2026-0373_signal-first-attack-generation-gap-integration_work_log.md
created_at: '2026-07-22'
updated_at: '2026-07-28'
---

# SGK-2026-0373 作業完了報告

## 実装内容

- ownership 用 URL 正規化を修正し、query parameter の key だけでなく value も保持するようにした。
- signal-first routing が成功したあとも、coverage backfill と scenario probe の補助タスク生成まで進むようにした。
- signal の `primary_label` で分からない場合でも、`candidate_labels` / `entity_type` を見て `file_param` と `crlf_candidate` を攻撃タスクへ変換するようにした。
- `crlf_candidate` を MasterConductor の attack mapping / ownership 判定対象に追加した。

## 判断理由

2026-07-22 の実 session では、signal bundle に 70 signal があるのに 20 task しか作られていなかった。原因は次の3点だった。

- `instructions.php?doc=...` 系 URL が ownership 正規化で `doc` の key だけに潰され、3件落ちていた。
- signal-first 成功時に早期 return しており、coverage backfill と scenario probe がまったく追加されなかった。
- `crlf_candidate` と、`candidate_labels` 由来でしか分からないカテゴリが signal routing でスキップされていた。

## 検証

- `env -u PYTHONHOME -u PYTHONPATH .venv/bin/pytest tests/core/engine/test_injection_ownership_dedup.py tests/core/engine/test_master_conductor_signal_recipe_routing.py`
  - 43 passed
- `.venv/bin/shigoku-ops --json report consistency --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260722_140508.md`
  - `status: consistent`, `rerun_required: false`, `reason_codes: []`
- `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260722_140508.md`
  - `status: consistent`

## リスク

- 修正後の DVWA Security=low をまだ再実行していないため、実 task 数と scenario coverage の増加量は未確認。
- `docs/shigoku/` 全体の validator には、本タスクとは別の既知不整合（`SGK-2026-0258` 欠損参照）が残っている可能性がある。

## 未対応事項

なし。
