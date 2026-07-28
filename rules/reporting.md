## 10) Reporting / Gate Completion Criteria
- For report-formatting or report-summary changes:
  - Validate with targeted unit tests first.
  - If a real `haddix_report_*.md` is available, also run the consistency checker against that real report.
- For gate or quality-policy changes:
  - Validate with targeted gate-related tests first.
  - If a real report path is available, also run `scripts/check_initial_release_gate.py` against that report before claiming completion.
- For detection/reporting pipeline changes:
  - Prefer verifying both unit tests and at least one real session/report artifact.
- Report whether validation covered only tests, only real artifacts, or both.

## Candidate Gate FAIL: Known Safe Hold (DVWA low baseline)

- A gate result of `candidate_above_maximum` is not automatically a bug. For the consistent DVWA low baseline `haddix_report_20260727_095226.md` / `session_20260727_095226.json`, five candidates are intentionally held below confirmation because their impact is unproven.
- The documented reason-code set is: `payload_request_mismatch`, `untested_no_second_account`, `authz_impact_not_proven`, `public_data_cross_origin_read`, and `state_change_not_verified`.
- Do not alter detection, promotion, deduplication, task generation, or gate policy solely to reduce these five candidates. That would conceal uncertainty rather than improve detection quality.
- Investigate or implement a follow-up only if a consistent report differs from this baseline (new reason code, candidate count change, required confirmed detection missing), or if the user explicitly asks to obtain the missing proof or change policy.
