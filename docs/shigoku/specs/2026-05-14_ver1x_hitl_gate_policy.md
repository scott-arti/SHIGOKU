---
task_id: SGK-2026-0091
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-14'
updated_at: '2026-05-19'
---

# Ver.1.x HITL Gate Policy (SCN08/10/12)

Date: 2026-05-14
Owner: SHIGOKU Core

## Purpose
- Ver.1 では `SCN08/SCN10/SCN12` は高摩擦シナリオとして HITL 前提で運用する。
- 上記 3 シナリオの未達を、初期リリース Gate の fail 理由にしない。
- ただし Gate の他条件（`confirmed_min`、`candidate_max`、required detection class）は維持する。

## Policy (Ver.1.x)
- Initial-release gate の `allowed_missing_scenarios` デフォルトは以下とする。
  - `scn_08_oob_external_channel_flow`
  - `scn_10_semantic_business_logic`
  - `scn_12_advanced_ssrf_internal_topology`
- Gate が pass した場合でも、上記が missing のときは `deferred_scenarios` として運用タスクを残す。
- `unexpected_missing_scenarios` は、上記 3 シナリオ以外が missing の場合のみ発生する。

## Non-goals
- SCN08/10/12 を「検出不要」にすることではない。
- coverage 改善トラック（HITL/manual 検証）を廃止しない。

## Operational Notes
- CLI-first での確認例:
```bash
.venv/bin/shigoku-ops --json report consistency --report <haddix_report_path>
.venv/bin/shigoku-ops --json report gate --report <haddix_report_path>
```
- 必要なら明示指定:
```bash
.venv/bin/shigoku-ops --json report gate --report <haddix_report_path> \
  --allowed-missing scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology
```

## Acceptance Criteria
- `SCN08/10/12` のみ missing の report で、他閾値を満たせば gate は pass。
- 同 report の `policy.notes` に Ver.1 例外方針が表示される。
- `deferred_scenarios` に SCN08/10/12 が必要に応じて出力される。
