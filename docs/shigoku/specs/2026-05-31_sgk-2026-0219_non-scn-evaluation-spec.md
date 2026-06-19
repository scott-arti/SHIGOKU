---
task_id: SGK-2026-0219
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs:
- docs/shigoku/plans/2026-05-19_non-scn-vulnerability-discovery-evaluation-plan-juice-shop-dvwa-crapi_plan.md
- docs/shigoku/worklogs/sgk-2026-0219_baseline_manifest_20260531_0121.md
created_at: '2026-05-31'
updated_at: '2026-05-31'
---

# SGK-2026-0219 Non-SCN Evaluation Spec (Step 2-5)

## KPI Definition
- KPI-1 Unique findings: dedup unique count.
- KPI-2 Severity distribution: `critical/high/medium/low/info/unknown` ratio.
- KPI-3 Evidence quality rate: findings with one of `reproduction_steps/request/response/impact/evidence`.
- KPI-4 False positive rate: stratified sample audit by `target x severity`.
- KPI-5 New discovery rate: 3-run moving average increment rate.

## Canonical Finding Schema
- required keys: `target`, `endpoint`, `method`, `vuln_class`, `evidence_hash`, `first_seen_at`, `confidence`
- dedup strict key: `vuln_class + normalized_endpoint + method + normalized_param_signature + evidence_hash`
- dedup relaxed key: `vuln_class + normalized_endpoint + method + normalized_param_signature`
- invalid gate: `invalid_record_rate <= 5%`

## Thresholds (V1.x)
- completion rate: `>=95%`
- false positive rate: `<=15%`
- evidence quality: `>=90%`
- new discovery rate (3-run MA): `>=5%`
- reproducibility tolerance: `max(absolute 2 findings, relative 10%)`

## Pilot Runbook Controls
- `max_concurrency=4`
- `max_runtime_minutes=180`
- stop rule:
  - no finding increment for 10 minutes
  - heartbeat miss 3 times
  - HTTP 5xx rate > 20% over sliding 50 requests

## Failure Triage
1. input validation
2. auth validation
3. target health
4. pipeline parse
5. detector output diff

unknown unresolved >24h => hold.
