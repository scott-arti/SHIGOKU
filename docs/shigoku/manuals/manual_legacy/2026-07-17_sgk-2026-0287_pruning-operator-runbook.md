---
task_id: SGK-2026-0287
doc_type: manual
status: active
parent_task_id: SGK-2026-0278
related_docs:
  - docs/shigoku/subtasks/2026-06-21_sgk-2026-0287_task-queue-pruning-policy_subtask_plan.md
  - docs/shigoku/manuals/2026-07-02_sgk-2026-0335_bugbounty-bundle-operator-runbook.md
created_at: '2026-07-17'
updated_at: '2026-07-21'
---

# Task Queue Pruning — Operator Runbook

## 1. Configuration

```yaml
# config/shigoku.yaml
pruning_mode: shadow            # shadow | active (default: shadow)
pruning_killswitch_enabled: false  # true = force shadow, deletions = 0
```

- **`pruning_mode`**: Any value other than `shadow` or `active` is fail-closed to `shadow`.
- **`pruning_killswitch_enabled`**: When `true`, all deletions are suppressed. Candidate traces are still recorded. Deletion count is always 0.
- **Session-level override is prohibited.** The mode is resolved once at conductor init via `resolve_pruning_mode()`. Session artifacts and resume paths do not override it.

## 2. Shadow Mode Operation

In shadow mode (`pruning_mode: shadow`):
- `TaskPruningPolicy` evaluates the queue for prune candidates after each batch.
- Candidates are recorded in session decision traces (`_pruning_decisions`).
- **No tasks are deleted from the queue.**
- Metrics counters (`_pruning_candidates_total`, `_pruning_protected_skip_total`) are incremented but `_pruning_applied_total` remains 0.

### Shadow Review Checklist (minimum 5 sessions before active promotion)

For each reviewed session, check against `decision_traces` in the session JSON:

| # | Check Item | Pass Criteria |
|---|---|---|
| 1 | **Protected misclassification** | No `reason_code=protected_skip` on a non-protected task, and no non-protected task appears in `applied_ids` of `prune_by_decisions()` result |
| 2 | **Unexplained prune decision** | Every `reason_code` has a corresponding entry in `REASON_CODE_TO_REASONING` |
| 3 | **Queue consistency** | `before_count - len(applied_ids) == after_count` after any active deletion |
| 4 | **Coverage gate tasks preserved** | No task with `agent_type` in `PROTECTED_AGENT_TYPES` appears in candidate list |
| 5 | **Killswitch behavior** | When enabled, `applied_ids` is always empty and mode is `shadow` |

**Review template:**
```
Session: <session_id>
Date reviewed: <YYYY-MM-DD>
Reviewer: <name>
protected_misclassification: <count>  (must be 0)
unexplained_prune_decision: <count>   (must be 0)
queue_consistency_mismatch: <count>   (must be 0)
Notes: <free text>
```

## 3. Active Mode Promotion Gate

**Current status (2026-07-17): Implementation complete — promotion pending.**

The code path for active deletion is fully wired:
- `TaskPruningPolicy.evaluate()` → candidate decisions
- `MasterConductor._evaluate_pruning_policy()` → `queue.prune_by_decisions()`
- Active mode applies deletions for approved task types.

However, `pruning_mode` remains **`shadow`** in `config/shigoku.yaml` until the gate conditions below are met.

Do **not** set `pruning_mode: active` until **all** of the following are met:

1. **5+ shadow reviews** completed using the template above.
2. **`protected_misclassification = 0`** across all reviewed sessions.
3. **`unexplained_prune_decision = 0`** across all reviewed sessions.
4. **`queue_consistency_mismatch = 0`** across all reviewed sessions.

Once promoted, active mode applies deletions for approved task types:
- `duplicate`
- `out_of_scope`
- `chain_low_value`
- `low_value_static_asset`

Other task types remain in shadow observation or protected skip.

## 4. Killswitch / Rollback

If pruning causes unexpected behavior:

```yaml
# Immediate: set killswitch
pruning_killswitch_enabled: true
```

This forces shadow mode regardless of `pruning_mode`. Candidate traces are preserved, deletions are suppressed.

**Full rollback to shadow:**
```yaml
pruning_mode: shadow
pruning_killswitch_enabled: false
```

Then restart the conductor. On resume, `resolve_pruning_mode()` reads the updated config and applies shadow mode.

## 5. Triage Guide

### Evaluation failures

- **Symptom**: Log contains `"Pruning policy evaluation failed"` with `queue_snapshot_id`.
- **Action**: Inspect the session decision traces for `eval_failure_skip` entries. Check the error message in `failure_decision["error"]`.
- **Recovery**: Evaluation failures are fail-closed — no deletions occur. Fix the root cause and re-run.

### Queue consistency mismatch

- **Symptom**: `before_count - len(applied_ids) != after_count` in `prune_by_decisions()` result.
- **Action**: Check for concurrent queue mutations. The shared deletion executor asserts main-thread execution (`PCR-P1`). Inspect `missing_ids` for tasks that were in the candidate list but not in the index.

### Killswitch not suppressing

- **Symptom**: Deletions still occur with `pruning_killswitch_enabled: true`.
- **Action**: Verify `resolve_pruning_mode()` is the single authority. Check for direct `remove_by_id()` calls outside `prune_by_decisions()`.

## 6. Metrics Reference

| Counter | Location | Meaning |
|---|---|---|
| `_pruning_candidates_total` | `MasterConductor` | Total candidate decisions evaluated across all batches |
| `_pruning_applied_total` | `MasterConductor` | Tasks actually deleted (active mode only) |
| `_pruning_protected_skip_total` | `MasterConductor` | Candidates skipped due to protection |
| `_pruning_eval_failures_total` | `MasterConductor` | Evaluation exceptions (fail-closed) |
