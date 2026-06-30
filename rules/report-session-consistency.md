## 8) Mandatory Report/Session Consistency Gate
- This section is mandatory for any user request that includes a report path (for example `haddix_report_*.md`).
- Before recommending re-run, before comparing with any older run, and before summarizing results, run:
  - `python3 scripts/verify_report_session_consistency.py --report <absolute-report-path>`
- Never mix timestamps from different reports in one conclusion.
- The provided report path is the primary source of truth for that turn.
- If consistency check fails or session cannot be resolved, do not guess. Explicitly say it is blocked by missing/invalid artifacts.
- Any re-run recommendation must include the checker verdict and reason codes.

### Report/Session Terminology
- `report`: a generated Markdown artifact such as `haddix_report_*.md`; summaries are derived from a session and formatter logic.
- `session`: the raw execution artifact such as `session_*.json`; this is the closest record of what the run actually produced.
- `primary source of truth`: the report path explicitly provided by the user for the current turn, together with the session resolved from the consistency checker.
- `backfill`: report-time or gate-time enrichment derived from scenario coverage or heuristics rather than directly from raw findings; do not present backfill as raw evidence unless clearly labeled.

## Canonical extraction rules

- Raw findings must be extracted via `src/reporting/finding_extractor.extract_all_findings()`. Do not rely on ad hoc fields such as `vulnerabilities_found` or `task["vulnerabilities_found"]`.
- When `shigoku-ops --report ...` or `verify_report_session_consistency()` resolves a session, the resolved session path alone is not enough. If the checker verdict is anything other than `consistent`, stop and report the inconsistency instead of generating or summarizing output.
