# Lessons & Anti-Patterns

This file contains project-specific mistakes that agents must avoid.

## Usage

- Read this file before non-trivial code changes.
- Apply only lessons relevant to the current task.
- Add a new lesson only when:
  - the same mistake happened more than once, or
  - the mistake caused a serious review failure, or
  - the rule is project-specific and cannot be inferred from code.

## Format

Use this format:

- `[YYYY-MM] LEVEL: Problem. Rule. Verification.`

LEVEL values:

- CRITICAL: Must not be violated.
- ERROR: Should block completion until fixed.
- CAUTION: Check when relevant.

## Active lessons

- `[2026-03] ERROR: Do not run broad automated formatting tools unless the task explicitly asks for formatting. Broad formatting pollutes the git diff. Verify formatting only through the repository-approved workflow.`
- `[2026-04] CAUTION: When updating UI components, verify SSR state rehydration. Do not mutate local storage during the initial render phase.`
- `[2026-05] CRITICAL: Do not write hardcoded timeouts in integration tests. Use condition-based waits such as wait-for-element patterns.`
- `[2026-06] CRITICAL: SHIGOKU docs validation is stricter than older prose rules. Every Markdown file under docs/shigoku/ must carry task_id/doc_type/status/parent_task_id/related_docs/created_at/updated_at front matter, and moving plan/subtask_plan files to done/ requires related_docs path updates everywhere. Verification: run python3 scripts/sync_shigoku_updated_at.py and python3 scripts/validate_shigoku_docs.py with zero issues.`
- `[2026-06] CRITICAL: Deferred follow-up items are not placeholders. Create the follow-up SGK task first and reference a real tracking_task_id in deferred_tasks; never leave TBD. Verification: validate_shigoku_docs.py reports no deferred link issues.`
- `[2026-06] CRITICAL: Report/session truth must come from the canonical extractor and consistency verdict. Use src/reporting/finding_extractor.extract_all_findings() for raw findings and stop if verify_report_session_consistency()/shigoku-ops returns anything except consistent. Verification: targeted reporting tests plus a real report consistency check when available.`
- `[2026-06] ERROR: Role-based LLM config silently downgrades if model= is also passed. Use LLMClient(role="...") only, and grep getattr(app_settings, "field") consumers before deleting deprecated flat config fields. Verification: rg for getattr consumers and run targeted llm config tests.`
- `[2026-06] ERROR: Secret boundaries fail when redaction lives at callsites or only scans top-level strings. Enforce redaction at the lowest write API and recurse through nested dict/list payloads, including source_refs. Verification: add tests with secrets at depth >= 2 and confirm only redacted values remain.`
- `[2026-06] ERROR: Auth-sensitive caches lie when keyed only on credential presence. Hash the actual credential values into the cache key so expired credentials cannot reuse a stale PASS. Verification: tests cover valid->expired credential changes without cache reuse.`
- `[2026-06] CAUTION: MasterConductor test paths skip __init__ and per-step closures reset state. Guard lazily initialized attrs with hasattr checks and keep per-recipe shared state outside step closures. Verification: run the __new__-based MasterConductor tests and a multi-step execution test.`
- `[2026-06] CAUTION: Network guards can swallow fail-safe auth detection. Run zero-network URL/payload checks before any network_client-dependent return in reauth flows. Verification: tests cover unsupported auth URLs with network_client=None.`
- `[2026-06] CAUTION: Notification dedup state must follow delivery, not candidate preparation. Do not call _mark_sent() inside normalize/process_batch helpers; mark sent only after send or dry-run success. Verification: tests show the first send happens and only retries are deduplicated.`
- `[2026-06] CAUTION: Generator and fixer parallelism can corrupt shared Python package surfaces. Do not let multiple fixers edit the same __init__.py in parallel, and bundle module deletion with import cleanup or make the dependency order explicit. Verification: inspect the final export file and run dependent import tests.`
- `[2026-06] CAUTION: CLI/report tests should verify artifacts and message keys, not assumptions. main.main() report paths may return None and msg("key") renders ??key?? when missing, so assert files/content and grep src/cli/messages.py before adding a new key usage. Verification: targeted CLI tests pass and rg finds the key.`
- `[2026-06] CAUTION: In this Codex shell, host python3 -c snippets break at semicolons. Use .venv/bin/python -c or avoid ; in host python3 -c command strings. Verification: rerun the command without semicolons and confirm it executes as one process.`
