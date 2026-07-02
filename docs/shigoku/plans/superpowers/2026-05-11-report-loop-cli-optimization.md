---
task_id: SGK-2026-0050
doc_type: plan
status: backlog
parent_task_id: null
related_docs: []
created_at: '2026-05-11'
updated_at: '2026-07-02'
---

# Report Loop CLI Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** SHIGOKU の report/session 判定ループを、Codex が低ノイズ・低トークン・低誤判定で自走できる CLI 形状に最適化する。

**Architecture:** 既存 `scripts/shigoku_ops_cli.py` を中核として、report ループ専用オーケストレーションを `src/reporting` に分離する。`consistency -> gate -> findings(optional)` の固定シーケンスを 1 コマンドで実行し、安定 JSON 契約と終了コードで分岐可能にする。既存ロジックは再利用し、スキーマ破壊は行わず追加フィールドのみで拡張する。

**Tech Stack:** Python 3.10+, argparse, existing reporting modules, pytest

---

## Scope and Expected Effect

- 対象スコープ: `report/session/gate` の AI Loop（重スキャン本体は対象外）
- 期待効果（採用判定基準）:
  - report-session 取り違え事故: 80%以上削減
  - ループ収束コマンド回数: 30%以上削減
  - AI向けトークン消費: 20%以上削減

---

### Task 1: Freeze JSON Contract for Agent Loops

**Files:**
- Modify: `scripts/shigoku_ops_cli.py`
- Create: `tests/unit/scripts/test_shigoku_ops_cli_contract.py`
- Modify: `docs/manual/cli_first_ops_plan.md`

- [ ] **Step 1: Write failing contract tests**

```python
def test_report_consistency_contract_has_stable_top_level_keys():
    payload = run_cli_json(["report", "consistency", "--report", str(report_file)])
    assert set(["status", "reason_codes", "report", "session", "comparison"]).issubset(payload.keys())
```

- [ ] **Step 2: Run contract tests and verify fail**

Run: `./.venv/bin/pytest -q tests/unit/scripts/test_shigoku_ops_cli_contract.py`  
Expected: FAIL (contract key assertions missing)

- [ ] **Step 3: Add envelope metadata without breaking existing fields**

```python
def _wrap_agent_payload(payload: dict[str, Any], *, command: str) -> dict[str, Any]:
    return {
        "schema_version": "shigoku.ops.v1",
        "command": command,
        "payload": payload,
    }
```

- [ ] **Step 4: Keep backward compatibility path**

```python
if args.compat_flat_json:
    _emit_payload(payload, output_json=True)
else:
    _emit_payload(_wrap_agent_payload(payload, command=cmd_name), output_json=True)
```

- [ ] **Step 5: Re-run tests**

Run: `./.venv/bin/pytest -q tests/unit/scripts/test_shigoku_ops_cli.py tests/unit/scripts/test_shigoku_ops_cli_contract.py`  
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add scripts/shigoku_ops_cli.py tests/unit/scripts/test_shigoku_ops_cli_contract.py docs/manual/cli_first_ops_plan.md
git commit -m "feat(ops-cli): add stable json envelope contract for agent loops"
```

---

### Task 2: Add `report loop` Orchestrator Command (Primary ROI)

**Files:**
- Create: `src/reporting/report_loop_orchestrator.py`
- Modify: `scripts/shigoku_ops_cli.py`
- Create: `tests/unit/reporting/test_report_loop_orchestrator.py`
- Modify: `tests/unit/scripts/test_shigoku_ops_cli.py`

- [ ] **Step 1: Write failing orchestrator tests**

```python
def test_report_loop_runs_consistency_then_gate(tmp_path):
    result = run_report_loop(report=report_file)
    assert result["stages"][0]["name"] == "consistency"
    assert result["stages"][1]["name"] == "gate"
```

- [ ] **Step 2: Run targeted test**

Run: `./.venv/bin/pytest -q tests/unit/reporting/test_report_loop_orchestrator.py`  
Expected: FAIL (`run_report_loop` not found)

- [ ] **Step 3: Implement orchestrator module**

```python
def run_report_loop(...):
    consistency = verify_report_session_consistency(...)
    if consistency["status"] == "blocked":
        return blocked_result(...)
    gate = evaluate_initial_release_gate(...)
    if include_findings:
        findings = inspect_session_findings(...)
    return assembled_result(...)
```

- [ ] **Step 4: Wire new CLI subcommand**

```python
report_loop = report_sub.add_parser("loop", help="Run consistency->gate->findings for AI loops.")
report_loop.add_argument("--report", required=True)
report_loop.add_argument("--include-findings", action="store_true")
report_loop.set_defaults(handler=_run_report_loop)
```

- [ ] **Step 5: Define aggregate exit code policy**

```python
# 0: consistency=consistent and gate=pass
# 3: consistency=inconsistent or gate=fail
# 2: any blocked path
```

- [ ] **Step 6: Verify tests**

Run: `./.venv/bin/pytest -q tests/unit/reporting/test_report_loop_orchestrator.py tests/unit/scripts/test_shigoku_ops_cli.py`  
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/reporting/report_loop_orchestrator.py scripts/shigoku_ops_cli.py tests/unit/reporting/test_report_loop_orchestrator.py tests/unit/scripts/test_shigoku_ops_cli.py
git commit -m "feat(ops-cli): add report loop orchestration command"
```

---

### Task 3: Add Loop Payload Controls (`--max-findings`, `--finding-fields`)

**Files:**
- Modify: `src/reporting/session_finding_inspector.py`
- Modify: `scripts/shigoku_ops_cli.py`
- Modify: `tests/unit/reporting/test_session_finding_inspector.py`
- Modify: `tests/unit/scripts/test_shigoku_ops_cli.py`

- [ ] **Step 1: Add failing tests for capped/minimal payload**

```python
def test_session_findings_respects_max_findings():
    summary = inspect_session_findings(session_file, max_findings=1)
    assert summary["findings_count"] == 1
```

- [ ] **Step 2: Run targeted tests**

Run: `./.venv/bin/pytest -q tests/unit/reporting/test_session_finding_inspector.py`  
Expected: FAIL (new args unsupported)

- [ ] **Step 3: Implement payload controls**

```python
def inspect_session_findings(..., max_findings: int | None = None, finding_fields: list[str] | None = None):
    ...
```

- [ ] **Step 4: Expose controls on CLI**

```python
session_findings.add_argument("--max-findings", type=int)
session_findings.add_argument("--finding-fields", help="comma separated fields")
```

- [ ] **Step 5: Re-run tests**

Run: `./.venv/bin/pytest -q tests/unit/reporting/test_session_finding_inspector.py tests/unit/scripts/test_shigoku_ops_cli.py`  
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/reporting/session_finding_inspector.py scripts/shigoku_ops_cli.py tests/unit/reporting/test_session_finding_inspector.py tests/unit/scripts/test_shigoku_ops_cli.py
git commit -m "feat(ops-cli): add findings payload controls for ai loops"
```

---

### Task 4: Add Deterministic Validation Suite for This Workflow

**Files:**
- Modify: `scripts/shigoku_ops_cli.py`
- Modify: `tests/unit/scripts/test_shigoku_ops_cli.py`
- Create: `docs/analysis/report_loop_kpi_baseline_2026-05-11.md`

- [ ] **Step 1: Add named suite for loop workflow**

```python
VALIDATION_SUITES["report_loop"] = [
    "tests/unit/reporting/test_report_session_consistency.py",
    "tests/unit/reporting/test_initial_release_gate.py",
    "tests/unit/reporting/test_session_finding_inspector.py",
    "tests/unit/reporting/test_report_loop_orchestrator.py",
    "tests/unit/scripts/test_shigoku_ops_cli.py",
]
```

- [ ] **Step 2: Add test for suite selection**

Run: `./.venv/bin/pytest -q tests/unit/scripts/test_shigoku_ops_cli.py -k validate`  
Expected: PASS with `report_loop` recognized

- [ ] **Step 3: Capture baseline KPI runbook**

```bash
python3 scripts/shigoku_ops_cli.py --json report loop --report <real_report_path> --include-findings --max-findings 20
```

Record:
- elapsed_ms
- command_count
- payload_bytes
- status path (`consistent/pass`, `inconsistent`, `blocked`)

- [ ] **Step 4: Commit**

```bash
git add scripts/shigoku_ops_cli.py tests/unit/scripts/test_shigoku_ops_cli.py docs/analysis/report_loop_kpi_baseline_2026-05-11.md
git commit -m "test(ops-cli): add report_loop validation suite and kpi baseline runbook"
```

---

## Validation Plan (Execution Order)

1. `./.venv/bin/pytest -q tests/unit/scripts/test_shigoku_ops_cli.py tests/unit/scripts/test_shigoku_ops_cli_contract.py`
2. `./.venv/bin/pytest -q tests/unit/reporting/test_report_loop_orchestrator.py tests/unit/reporting/test_session_finding_inspector.py`
3. `./.venv/bin/pytest -q tests/unit/reporting/test_report_session_consistency.py tests/unit/reporting/test_initial_release_gate.py`
4. Real artifact smoke:
   - `python3 scripts/shigoku_ops_cli.py --json report loop --report <abs_haddix_report_path>`

Expected:
- Unit tests pass
- Real report run returns deterministic JSON
- Exit code matches stage result policy

---

## Rollback Conditions

- `report loop` の導入で既存 `report consistency` / `report gate` の出力互換が崩れた場合は即ロールバック。
- JSON envelope が既存運用を壊す場合は `--compat-flat-json` をデフォルト有効に戻す。
- real artifact smoke で `blocked` が増加した場合は session 解決ロジック変更を分離して再評価する。

---

## Adoption Gate (Go / No-Go)

Go 条件:
- KPI で command_count 30%以上削減
- token/payload 推定で 20%以上削減
- report-session mismatch オペミスが検証期間で 0 件

No-Go 条件:
- 既存 CLI 互換破壊
- Exit code 不一致で自動分岐失敗
- 運用チームが手動コマンドを増やす必要が出る

