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
