---
task_id: SGK-2026-0056
doc_type: plan
status: backlog
parent_task_id: null
related_docs: []
created_at: '2026-05-14'
updated_at: '2026-05-19'
---

# Required Detection Class Hybrid Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** required detection class 判定で `session_detection_class_summary` と `detection_class_summary_raw` のズレを吸収し、過小判定による false fail を減らす。

**Architecture:** `evaluate_initial_release_gate` 内で required-class 判定専用の confirmed count ソースを「session優先」から「session/raw のクラスごと max」へ変更する。判定ロジックと `required_detection_class_evaluation.class_confirmed_counts` を同じ合成ソースで統一し、`decision_source` を `hybrid_session_raw_detection_class_summary_max` に固定する。テストは fail-first で既存ケースを拡張し、実レポートで consistency/gate を再確認する。

**Tech Stack:** Python 3, pytest, jq, shigoku-ops CLI

---

### Task 1: Gate 判定ソースを hybrid(max) に変更

**Files:**
- Modify: `src/reporting/initial_release_gate.py`
- Test: `tests/unit/reporting/test_initial_release_gate.py`

- [ ] **Step 1: fail-first テスト追加（session/raw 乖離ケース）**

```python
def test_initial_release_gate_uses_hybrid_detection_class_counts_for_required_class_decision(tmp_path: Path) -> None:
    verdict = evaluate_initial_release_gate(
        report_file,
        required_confirmed_classes=["access_control", "idor_bola", "mass_assignment", "endpoint_bfla"],
        required_class_confirmed_min=1,
    )
    required_eval = verdict["report_metrics"]["required_detection_class_evaluation"]
    assert required_eval["decision_source"] == "hybrid_session_raw_detection_class_summary_max"
    assert required_eval["status"] == "pass"
```

- [ ] **Step 2: fail-first 実行**

Run: `.venv/bin/pytest -q tests/unit/reporting/test_initial_release_gate.py::test_initial_release_gate_uses_hybrid_detection_class_counts_for_required_class_decision`
Expected: FAIL（現状 decision_source が session のみで missing_classes が出る）

- [ ] **Step 3: minimal 実装（hybrid 合成）**

```python
# required_detection_classes ブロック直前に追加
required_detection_class_source = "raw_detection_class_summary"
raw_confirmed_by_detection_class = detection_class_summary_raw.get("confirmed_by_detection_class", {})
session_confirmed_by_detection_class = session_detection_class_summary.get("confirmed_by_detection_class", {})

if not isinstance(raw_confirmed_by_detection_class, dict):
    raw_confirmed_by_detection_class = {}
if not isinstance(session_confirmed_by_detection_class, dict):
    session_confirmed_by_detection_class = {}

if bool(session_detection_class_summary.get("available")):
    required_detection_class_source = "hybrid_session_raw_detection_class_summary_max"

def _hybrid_confirmed_count_for_class(detection_class: str) -> int:
    raw_v = int(_safe_int(raw_confirmed_by_detection_class.get(detection_class)) or 0)
    session_v = int(_safe_int(session_confirmed_by_detection_class.get(detection_class)) or 0)
    return max(raw_v, session_v)
```

```python
# 判定ループを置換
for detection_class in required_detection_classes:
    confirmed_for_class = _hybrid_confirmed_count_for_class(detection_class)
    if confirmed_for_class < int(required_class_confirmed_min):
        missing_required_detection_classes.append(detection_class)
```

```python
# required_detection_class_eval.class_confirmed_counts も同じ合成ソースに統一
required_detection_class_eval["class_confirmed_counts"] = {
    detection_class: _hybrid_confirmed_count_for_class(detection_class)
    for detection_class in required_detection_classes
}
```

- [ ] **Step 4: 対象テスト再実行**

Run: `.venv/bin/pytest -q tests/unit/reporting/test_initial_release_gate.py::test_initial_release_gate_uses_hybrid_detection_class_counts_for_required_class_decision`
Expected: PASS

- [ ] **Step 5: Gate関連テスト一式実行**

Run: `.venv/bin/pytest -q tests/unit/reporting/test_initial_release_gate.py`
Expected: PASS

---

### Task 2: 実アーティファクトで consistency + gate 再評価

**Files:**
- Validate artifact: `tmp/bench_fast_parallel5_rawgate_20260514_000551/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_000811.md`
- Validate artifact: `tmp/bench_fast_parallel5_rawgate_20260514_000551/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_001055.md`
- Validate artifact: `tmp/bench_fast_parallel5_rawgate_20260514_000551/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_001348.md`

- [ ] **Step 1: 必須 consistency チェック（3本）**

Run:
```bash
python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_20260514_000551/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_000811.md
python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_20260514_000551/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_001055.md
python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_20260514_000551/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_001348.md
```
Expected: 3本とも `status=consistent`

- [ ] **Step 2: gate 再評価（3本）**

Run:
```bash
.venv/bin/python scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_20260514_000551/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_000811.md --allowed-missing "scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology" --required-confirmed-classes "access_control,idor_bola,mass_assignment,endpoint_bfla" --required-class-confirmed-min 1
.venv/bin/python scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_20260514_000551/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_001055.md --allowed-missing "scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology" --required-confirmed-classes "access_control,idor_bola,mass_assignment,endpoint_bfla" --required-class-confirmed-min 1
.venv/bin/python scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_20260514_000551/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_001348.md --allowed-missing "scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology" --required-confirmed-classes "access_control,idor_bola,mass_assignment,endpoint_bfla" --required-class-confirmed-min 1
```
Expected: `required_detection_class_below_minimum` が消える（`unexpected_missing_scenarios` は残る想定）

- [ ] **Step 3: 追加確認（decision_source と counts）**

Run:
```bash
jq '.report_metrics.required_detection_class_evaluation' /home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_20260514_000551/workspace/projects/127.0.0.1:8888/reports/benchmark_scn01_07_P0/P0_run01_gate.json
```
Expected: `decision_source="hybrid_session_raw_detection_class_summary_max"`, `class_confirmed_counts.access_control >= 1`, `mass_assignment >= 1`

---

### Task 3: 最終レポート（変更理由・検証結果・残課題）

**Files:**
- No file changes (reporting task)

- [ ] **Step 1: 変更点を明確化**

Include:
- 何を変えたか（判定ソースの合成ロジック）
- なぜ必要か（session/raw 表現ズレ対策）

- [ ] **Step 2: 検証結果を列挙**

Include exact commands and observed outputs:
- unit test
- consistency check
- gate check

- [ ] **Step 3: リスクと next step を記載**

Include:
- 残る fail 理由（`unexpected_missing_scenarios`）
- 次の改善候補（SCN11 埋め）
