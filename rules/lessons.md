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