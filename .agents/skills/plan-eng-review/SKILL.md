---
name: plan-eng-review
description: Review an implementation plan for a Python CLI application before coding. Use for architecture, scope, tests, error handling, safety, maintainability, agent workflow, CLI behavior, and artifact quality review.
---

# Plan Engineering Review

Review the plan before code changes.

This skill is for Python CLI applications, especially AI-agent-driven CLI workflows that produce reports, sessions, logs, or other artifacts.

Project instructions take priority over this skill. Use `AGENTS.md` and relevant files under `rules/` as higher-priority instructions.

If the plan includes multi-perspective review notes such as SRE, Software Architect, Debugger, or CTO findings, treat them as advisory inputs. Do not assume they are accepted unless the plan explicitly marks them as adopted.

## Inputs

Use the available inputs:

- Implementation plan, design note, issue, or task description

- Relevant existing code

- `AGENTS.md`

- Relevant rule files under `rules/`

- Existing tests, reports, sessions, or artifacts related to the plan

Do not assume behavior from filenames alone. Verify with code, tests, docs, or artifact references.

## Rule loading

Before reviewing a plan, read:

- `AGENTS.md`

- `rules/lessons.md` for non-trivial code changes

- `rules/codingrules.md` for implementation, refactoring, error handling, async, typing, subprocess, file operations, dependencies, logging, or secrets

- Any other rule file listed in `AGENTS.md` that matches the plan scope

At the end of the review, report which rule files were consulted.

If a relevant rule file is missing, state that it was expected but not found.

## Review focus selection

Classify the plan before reviewing.

Use one or more of these labels:

- feature

- refactor

- bug fix

- agent workflow

- CLI behavior

- reporting/session behavior

- test infrastructure

- async/concurrency

- dependency/tooling

- documentation

- validation/gating

- security/safety

Use the matching focus areas, but always check:

- scope

- existing code reuse

- tests

- error handling

- safety

- secrets

- user-visible behavior

- validation commands

## Review depth

Use the smallest review depth that fits the plan.

- LIGHT: small bug fix, docs-only change, isolated test change, small internal cleanup

- STANDARD: normal feature, refactor, CLI behavior change, report behavior change, validation change

- DEEP: agent workflow, safety boundary, report/session schema, async/concurrency, dependency/tooling, architecture, distribution, or security-sensitive change

LIGHT reviews may summarize low-risk sections as `No issues found`.

STANDARD and DEEP reviews must evaluate all required sections.

DEEP reviews must include:

- failure modes

- artifact behavior

- safety boundaries

- validation expectations

- user decision points

- rollback or recovery concerns where relevant

If the plan changes scope enforcement, target handling, secrets, active probing behavior, report/session schema, or agent decision logic, use DEEP.

If the review depth is unclear, choose STANDARD and explain why.

## Plan review boundary

This skill reviews the implementation plan before editing code.

Do not edit code during this review.

When code references are needed, inspect existing code only to verify:

- current behavior

- reuse opportunities

- constraints

- integration points

- risks

- test locations

- artifact formats

Do not propose line-by-line code patches unless the user explicitly asks for an implementation patch.

Do not modify files, create commits, run destructive commands, or write review logs during this review unless the user explicitly asks.

The output should help decide whether the plan is ready for implementation, not implement the plan.

## Security review boundary

Focus on engineering safety, scope enforcement, error handling, reproducibility, logging, report quality, and guardrails.

Do not expand the plan into:

- unauthorized exploitation steps

- destructive testing instructions

- credential theft

- stealth behavior

- bypass of third-party restrictions

- evasion of monitoring or rate limits

- instructions to access systems outside authorized scope

If a requested change could enable unsafe action, recommend a safer design:

- dry-run mode

- explicit scope validation

- target allowlist checks

- rate limits

- concurrency limits

- timeout limits

- confirmation gates

- redaction

- audit logs

- passive-first workflow

- fail-closed behavior

## Required behavior

1. Identify the goal and scope.

2. Check existing code before recommending new code.

3. Challenge unnecessary scope, abstractions, dependencies, and rewrites.

4. Review architecture, code quality, tests, performance, failure modes, CLI behavior, artifact quality, observability, and safety.

5. Prefer explicit, tested, maintainable Python.

6. Prefer existing project patterns, Python standard library, or existing helpers before new custom logic.

7. Do not recommend public behavior changes without corresponding tests and documentation.

8. Do not use network access unless the user explicitly allows it.

9. Do not write files, logs, commits, or review metadata unless the user explicitly asks.

10. Do not stop for every minor finding. Stop only for decisions that affect scope, architecture, dependencies, public behavior, safety, destructive operations, or long-term maintainability.

## Step 0: Scope challenge

Before reviewing implementation details, answer:

- What existing code already solves part of this problem?

- What existing command, flow, helper, model, report, session, or validation script can be reused?

- What is the smallest complete change that satisfies the stated goal?

- Does the plan introduce unnecessary classes, services, dependencies, abstractions, or custom logic?

- Does the plan change public behavior?

- Does the plan touch more files or modules than the goal requires?

- Are any items out of scope and better deferred?

- Are any safety, target-scope, destructive-operation, or secret-handling risks present?

If the plan appears overbuilt, recommend a smaller complete plan and ask before proceeding.

Completeness means fully handling the agreed behavior: tests, edge cases, error paths, validation, and documentation where relevant. It does not mean adding unrelated capabilities.

## 1. Architecture review

Evaluate:

- Module boundaries

- Dependency direction

- Data flow

- Agent loop design

- State and session persistence

- Tool boundary design

- External command boundary design

- Network boundary design

- Scope and safety gates

- Failure isolation

- Retry behavior

- Timeout behavior

- Distribution path for the CLI

- Whether the plan preserves existing public behavior unless explicitly changed

For AI-agent workflows, check:

- Planning step

- Tool selection

- Tool execution boundary

- Observation handling

- State update

- Stop condition

- Human confirmation point

- Failure recovery path

- Out-of-scope prevention before action execution

Produce an ASCII diagram for non-trivial data flow, agent loop, state machine, or processing pipeline.

## 2. Code quality review

Evaluate against `rules/codingrules.md`:

- Existing project patterns

- Duplication

- Module organization

- Naming

- Type safety

- Error handling

- File operations

- Subprocess handling

- Async and timeout behavior

- Logging

- Secret redaction

- Dependency choices

- Accidental complexity

- Whether public behavior changes have tests and documentation

Flag:

- Bare `except:`

- Empty exception handlers

- Broad `Exception` catches without boundary justification

- Ignored subprocess failures

- Arbitrary sleeps used for synchronization

- Global environment mutation that leaks across tests

- Raw secrets in logs, stdout, stderr, fixtures, examples, or reports

- New dependencies that are not justified against stdlib or existing helpers

## 3. Bug bounty safety review

Check whether the plan:

- Enforces target scope boundaries before active actions

- Separates passive collection from active probing

- Uses safe defaults for network-heavy actions

- Has rate limits or concurrency limits

- Avoids destructive or state-changing actions unless explicitly confirmed

- Fails closed when scope, config, authorization, or target identity is unclear

- Redacts secrets, tokens, cookies, credentials, and sensitive findings in logs and reports

- Records enough evidence for reproducibility without exposing sensitive data

- Provides dry-run, preview, or confirmation behavior for risky operations

- Prevents accidental actions against out-of-scope targets

- Handles platform policy constraints as explicit guardrails, not hidden assumptions

If a plan can perform active probing, state whether the review found:

- scope validation before action

- rate limiting

- timeout

- user confirmation for risky actions

- logging redaction

- recoverable failure behavior

## 4. Test review

Require tests for:

- Changed behavior

- Edge cases

- Failure paths

- CLI arguments

- Exit codes

- stdout/stderr behavior

- Config precedence

- External I/O with mocks or fakes

- Subprocess failures

- Timeout and cancellation paths

- Session output formats

- Report output formats

- Secret redaction

- Out-of-scope prevention

- Regression cases for bug fixes

Produce a small test diagram showing which behavior each test covers.

Example format:

```text
Input/config
   |
   v
CLI command ----> Agent workflow ----> Tool boundary ----> Artifact output
   |                   |                    |                    |
 tests: args      tests: decisions      tests: failures      tests: schema
 tests: exits     tests: stop cond      tests: timeout       tests: redaction
```

For every new codepath identified in the diagram, list one realistic failure mode and whether:

1. A test covers it

2. Error handling exists

3. The user sees a clear error

4. The failure is recoverable

5. Secrets remain redacted

If a failure mode has no test, no error handling, and would fail silently, flag it as a critical gap.

## 5. LLM and prompt review

If the plan changes prompts, agent policies, ranking logic, tool-selection logic, summarization logic, report-generation logic, or model-facing context, check:

- What behavior is expected to change

- What behavior must not change

- Which examples or eval cases cover the change

- Whether outputs are deterministic enough to review

- Whether failures are detectable

- Whether unsafe or out-of-scope actions are blocked before tool execution

- Whether the model asks for confirmation at the correct points

- Whether model output is validated before being trusted

- Whether prompt or context changes can leak secrets

- Whether report text remains evidence-based and does not overclaim

Require evals or golden examples when the change affects:

- vulnerability classification

- scope decisions

- report severity

- report wording

- tool choice

- target prioritization

- safety decisions

- automatic gating decisions

## 6. Artifact and persistence review

Check:

- Session files are deterministic enough to compare and debug

- Reports preserve evidence, commands, observations, limitations, and uncertainty

- Intermediate artifacts have clear ownership

- Cleanup behavior is defined

- Re-running the same command does not corrupt prior results

- Partial failures leave recoverable state

- Output schemas are documented and tested

- File paths are predictable

- Generated artifacts do not expose secrets

- Existing report/session consistency rules are followed when applicable

For report or session changes, verify:

- where artifacts are written

- whether existing artifacts are overwritten, appended, or versioned

- what happens on interrupted runs

- how users can inspect or reproduce results

- whether validation scripts need updates

## 7. Observability review

Check:

- Logs explain what the agent did, skipped, retried, and failed

- Progress output is useful without being noisy

- User-facing errors are actionable

- Debug logs do not expose secrets

- Exit codes distinguish success, user error, config error, runtime failure, partial success, and safety block

- Machine-readable output is stable when provided

- Validation output includes exact commands and observed results

- Long-running operations expose enough progress to diagnose hangs

- Failures include context without leaking sensitive data

CLI applications have no WebUI, so stdout, stderr, logs, reports, and exit codes are the user interface.

## 8. Dependency and external tool review

Check:

- New dependencies are justified against Python stdlib and existing project helpers

- External tools are detected before use

- Missing tools produce clear installation guidance

- Tool versions are pinned, checked, or documented when behavior matters

- Subprocess failures are not ignored

- stderr is captured when useful

- secrets are redacted from command output

- commands use safe argument passing rather than unsafe shell composition where possible

- network calls have explicit timeouts

- long-running external commands have cancellation behavior

- dependency changes include tests and documentation where relevant

Do not approve a new dependency when a small local helper, stdlib feature, or existing project helper solves the actual requirement with less maintenance burden.

## 9. Performance review

Evaluate:

- Slow code paths

- Repeated I/O

- Repeated parsing

- Memory growth

- Large report/session handling

- Concurrency limits

- Timeout defaults

- Cache opportunities

- Unbounded queues or task creation

- N+1-style repeated lookups

- External command fan-out

- Large stdout/stderr capture behavior

For agent workflows, check whether performance limits are explicit:

- max targets

- max requests

- max concurrency

- max retries

- max runtime

- timeout per operation

- artifact size limits

## 10. CLI behavior review

Evaluate:

- Command names

- Subcommands

- Options

- Defaults

- Help text

- Config precedence

- Environment variable handling

- stdout/stderr separation

- Exit codes

- Dry-run behavior

- Confirmation behavior

- Machine-readable output

- Human-readable summaries

- Error message clarity

Check that CLI behavior is testable without real external targets where possible.

## Verdict criteria

Use one of:

- APPROVE: No blocking issues. Remaining issues are minor and do not affect correctness, safety, maintainability, or user-visible behavior.

- APPROVE WITH CHANGES: The plan is directionally correct, but required changes should be made before implementation.

- BLOCK: The plan has unresolved scope, safety, architecture, data-loss, secret-handling, dependency, testability, or public-behavior problems.

A BLOCK verdict is required when any of these exist:

- out-of-scope action risk

- destructive behavior without confirmation

- secret leakage risk

- untested critical failure path

- silent failure in a critical path

- unclear artifact overwrite behavior

- broad dependency or architecture change without justification

- plan conflicts with `AGENTS.md` or relevant `rules/`

## Review failure conditions

The review is incomplete if any of these happen:

- It gives a verdict without reading `AGENTS.md`.

- It gives a verdict without checking relevant rule files.

- It recommends new code without checking existing code first.

- It approves a plan that changes behavior without tests or validation expectations.

- It ignores secret handling, scope boundaries, or destructive-operation risks.

- It omits `NOT in scope`.

- It omits validation expectations.

- It claims something is safe, verified, or ready without evidence.

- It treats missing information as approval instead of naming the uncertainty.

- It skips failure modes for DEEP reviews.

- It skips artifact behavior for report or session changes.

- It skips CLI behavior for user-facing command changes.

If any failure condition occurs, state `Review incomplete` and list the missing work.

## Required output

Return the review in this structure:

```text
# Plan Engineering Review

## Verdict
APPROVE / APPROVE WITH CHANGES / BLOCK

## Review depth
LIGHT / STANDARD / DEEP

## Review focus
- ...

## Rule files consulted
- ...

## Step 0: Scope challenge
- Existing code reuse:
- Smallest complete change:
- Scope risks:
- Recommendation:

## What already exists
- ...

## Architecture findings
1. ...

## Code quality findings
1. ...

## Bug bounty safety findings
1. ...

## Test review
- Test diagram:
- Missing tests:
- Critical gaps:

## LLM and prompt findings
1. ...

## Artifact and persistence findings
1. ...

## Observability findings
1. ...

## Dependency and external tool findings
1. ...

## Performance findings
1. ...

## CLI behavior findings
1. ...

## Failure modes
| Codepath | Failure mode | Test exists | Error handling exists | User-visible error | Recoverable | Severity |
|---|---|---|---|---|---|---|

## NOT in scope
- ...

## Questions requiring user decision
Ask only about decisions that affect scope, architecture, dependencies, public behavior, safety, destructive operations, or long-term maintainability.

## Recommended next actions
1. ...

## Validation expectations
- Targeted command:
- Broader command if needed:
- Expected evidence:
```

## Question policy

Do not stop for every finding.

Ask the user only when a decision affects:

- scope

- architecture

- dependencies

- public behavior

- safety posture

- destructive operations

- data model or artifact schema

- long-term maintainability

- distribution or installation behavior

For ordinary issues, provide a concrete recommended fix.

When asking, provide:

- the issue

- 2 or 3 options

- recommendation

- reason

- tradeoff

- whether the option changes scope, risk, or maintenance burden

## NOT in scope policy

Every review must include a `NOT in scope` section.

List work that was considered and explicitly deferred.

Each item must include:

- what is deferred

- why it is deferred

- whether it should become a TODO

## Parallelization review

Analyze whether the implementation can be split across parallel worktrees or independent workstreams.

Skip if:

- all steps touch the same primary module

- the plan has fewer than 2 independent workstreams

- parallel work would increase merge risk more than it saves time

If useful, produce:

```text
## Parallelization

| Lane | Workstream | Modules touched | Depends on | Conflict risk |
|---|---|---|---|---|

Execution order:
- Launch ...
- Merge ...
- Then ...
```

Use module or directory level, not guessed file-level details.

## Final summary

End with:

```text
## Completion summary

- Verdict:
- Review depth:
- Review focus:
- Scope challenge:
- Architecture issues:
- Code quality issues:
- Safety issues:
- Test gaps:
- Critical failure gaps:
- LLM/prompt issues:
- Artifact/persistence issues:
- Observability issues:
- Dependency/tooling issues:
- Performance issues:
- CLI behavior issues:
- NOT in scope written:
- User decisions required:
- Recommended next action:
```
