---
task_id: SGK-2026-0057
doc_type: plan
doc_usage: implementation_plan
status: backlog
parent_task_id: null
related_docs: []
created_at: '2026-05-14'
updated_at: '2026-05-19'
---

# Ver1 SCN08/10/12 Policy Lock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ver.1 方針に合わせて SCN08/10/12 を deferred 運用として固定し、運用ゲート実行コマンドと検証結果を 08/10/12 前提に統一する。

**Architecture:** コードの検出ロジックは変更せず、運用ドキュメントの allowed-missing を `scn_08, scn_10, scn_12` に統一する。直近ベンチアーティファクトに対して consistency と gate を再実行し、`SCN11` を missing 例外に含めずに pass することを証明する。

**Tech Stack:** Markdown docs, shigoku-ops/check_initial_release_gate, jq

---

### Task 1: 運用ドキュメントの allowed-missing を Ver.1 方針へ固定

**Files:**
- Modify: `docs/2026-05-12_log_codex_handover_v2.md`

- [ ] **Step 1: 失敗条件を確認する検索（現状把握）**

Run:
```bash
rg -n "allowed-missing|scn_11_multi_vector_chain" docs/2026-05-12_log_codex_handover_v2.md
```
Expected: `allowed-missing` に `scn_11_multi_vector_chain` が含まれる既存記述が見つかる。

- [ ] **Step 2: 最小実装（ドキュメント更新）**

```markdown
- `allowed-missing` を `scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology` に変更
- 文脈説明に「SCN11 は coverage 対象（例外除外しない）」を追記
```

- [ ] **Step 3: 差分確認**

Run:
```bash
git diff -- docs/2026-05-12_log_codex_handover_v2.md
```
Expected: SCN11 が allowed-missing から削除され、Ver.1 運用注記が追加されている。

---

### Task 2: 実アーティファクトで Ver.1 運用の成立を検証

**Files:**
- Validate artifact: `tmp/bench_fast_parallel5_rawgate_20260514_005124/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_005407.md`
- Validate artifact: `tmp/bench_fast_parallel5_rawgate_20260514_005124/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_005705.md`
- Validate artifact: `tmp/bench_fast_parallel5_rawgate_20260514_005124/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_005942.md`

- [ ] **Step 1: 必須 consistency チェック（3本）**

Run:
```bash
python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_20260514_005124/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_005407.md
python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_20260514_005124/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_005705.md
python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_20260514_005124/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_005942.md
```
Expected: 3本とも `status=consistent`。

- [ ] **Step 2: Ver.1 運用ゲート（allowed-missing=08/10/12）**

Run:
```bash
.venv/bin/python scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_20260514_005124/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_005407.md --allowed-missing "scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology" --required-confirmed-classes "access_control,idor_bola,mass_assignment,endpoint_bfla" --required-class-confirmed-min 1
.venv/bin/python scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_20260514_005124/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_005705.md --allowed-missing "scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology" --required-confirmed-classes "access_control,idor_bola,mass_assignment,endpoint_bfla" --required-class-confirmed-min 1
.venv/bin/python scripts/check_initial_release_gate.py --report /home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_20260514_005124/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260514_005942.md --allowed-missing "scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology" --required-confirmed-classes "access_control,idor_bola,mass_assignment,endpoint_bfla" --required-class-confirmed-min 1
```
Expected: 3本とも `status=pass`、`reason_codes=[]`。

- [ ] **Step 3: SCN11 が coverage 済みであることを確認**

Run:
```bash
jq '.scenario_coverage.coverage_items[] | select(.scenario_id=="scn_11_multi_vector_chain")' /home/bbb/Documents/App/Shigoku/tmp/bench_fast_parallel5_rawgate_20260514_005124/workspace/projects/127.0.0.1:8888/sessions/session_20260514_005938.json
```
Expected: `covered=true` かつ `count>=1`。

---

### Task 3: 最終報告（運用固定点の明文化）

**Files:**
- No file changes

- [ ] **Step 1: 変更点を報告**

Include:
- ドキュメントの fixed policy（SCN08/10/12 deferred、SCN11 coverage）

- [ ] **Step 2: 検証結果を報告**

Include exact outputs summary:
- consistency 3/3
- gate 3/3 pass

- [ ] **Step 3: 次の指示待ち**

Include:
- 「方針固定は完了。次指示を待機」

