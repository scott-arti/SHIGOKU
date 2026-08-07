---
task_id: SGK-2026-0421
doc_type: work_report
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0421_vdp-evidence-gap-driven-verification-and-safe-follow-up_subtask_plan.md
- docs/shigoku/plans/done/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0420_vdp-capability-driven-hypothesis-generation-shadow-workflow_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0422_vdp-canonical-evidence-reporting-and-separated-quality-gates_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_subtask_plan.md
title: VDP evidence gap driven verification and safe follow-up 作業完了報告
created_at: '2026-08-03'
updated_at: '2026-08-07'
tags:
- shigoku
target: src/core/engine,src/core/models,src/core/config,tests
---

# 作業完了報告書：SGK-2026-0421

## 1. 最終状態

**DONE**。固定済み計画書の必須条件を全件再監査し、`in_scope_blocker` は0件になった。最終実測は **VDP関連25ファイル 629件すべてPASS**（0421新規202件、既存VDP回帰427件）。`tests/unit/engine` + `tests/unit/config` 全体は **1234件PASS**。0421のVDP経路は実VDPや外部サイトへ接続せず、注入したfake transportで検証した（socket実接続0件を実経路テストで確認）。

## 2. 実装概要

- 公開reason vocabularyの全known codeを決定論的なNextAction、manual review、terminal、re-evaluateへ写像し、unknown codeはgeneric scanへ送らず停止する。
- M2 shadowではNextAction保存だけを行い、queue/networkを呼ばない。M3aは明示scope、明示capability許可、read-only意味判定、HITL、budget、idempotencyを通信直前に再評価する。
- 0421で真に再現できる無認証・無payloadの読取requestだけをexact replayする。値・body・認証が入力境界で破棄されたrequestや、timing/auth/browser/OOB/state-changeは、不正確なgeneric requestを送らずpending/manual reviewに残す。
- hidden retry、WAF mutation、cache、redirect追従を無効化し、注入済みnetwork clientだけを利用する。
- Attempt/Evidence/candidate Verdict/NextActionを同じID系列で保存し、confirmedは生成しない。dependency failureをrefutedへ変換しない。
- queue部分失敗、EvidenceWriter backpressure、checkpoint失敗をdegradedとして記録し、pending actionと返却済みEvidenceを失わない。
- budget、follow-up、concurrency、idempotencyを部分消費しない予約経路を追加し、post-send checkpointへbudget・retry/circuit・idempotency・state-change guard・pending actionを保存／復元する。
- formは既存signal bundleの`location == "form"`からtyped Observation化する。他6源は確認済み理由付きunavailableとし、観測0件と区別する。
- `readonly_enforce`以外のM3b/M3c設定値はoffへfail-safeし、明示gateなしに有効化できない。

## 3. 固定済み完了条件の監査

| 条件 | 結果 | 主な証拠 |
|---|---|---|
| reason code coverage 100%、unknown generic scan 0 | PASS | `test_vdp_follow_up.py` |
| M2 shadow queue/network 0 | PASS | `test_master_conductor_vdp_follow_up.py` |
| M3a state-changing action 0、HITL bypass 0 | PASS | `test_vdp_readonly_guard.py`, `test_vdp_hitl_and_admission.py` |
| confirmedの直接生成0、dependency failure→refuted 0 | PASS | `test_vdp_follow_up_executor.py`, `test_vdp_follow_up_resilience.py` |
| queue silent loss 0、backpressureをdegradedへ反映 | PASS | `test_master_conductor_vdp_follow_up.py` |
| budget超過・retry超過・scope逸脱0 | PASS | `test_vdp_budget.py`, `test_vdp_scope_failclosed.py`, executor tests |
| 二重state change 0 | PASS | `test_vdp_follow_up_resilience.py`, checkpoint復元test |
| exact replay/PoC不一致検出 | PASS | `test_vdp_follow_up_executor.py` |
| negative control失敗時に未確定 | PASS | timing gapをmanual reviewに保持する反証test |
| 7観測源のtyped/unavailable、0件との区別 | PASS | `test_vdp_observation_form_source.py` |
| Attempt/Evidence/Verdict/NextAction lineage | PASS | full-path integration + M0 gate |
| session保存→M0 gate→restore | PASS | full-path integration |
| 0420回帰なし | PASS | 427件PASS（VDP系合計629） |
| 0422/0423への越境なし | PASS | production engineからreporting import 0、confirmed factory呼出0、実VDP通信0 |

## 4. 実経路と実測値

`MasterConductor → reason mapping → pending checkpoint → DynamicTaskQueue → dispatch → scope/capability/read-only/HITL/budget/idempotency → injected fake network → Attempt/Evidence保存 → post-send checkpoint → session保存 → M0 gate → session復元`を通した。

- 成功する1回のexact replay: network 1回、request budget 1、queue成功1。
- scope、kill switch、state-change、HITL、budget、concurrency、fingerprint不一致: network 0回。
- timeout/dependency failure: 実送信試行1回、hidden retry 0、Attempt/Evidenceは捏造せず未保存、status=degraded、refuted 0、verdictはcandidateのまま。
- responseのsecret値は保存前にredactし、spec/Attempt/Evidence/sessionで既知secret文字列0件を反証testで確認した。

## 5. 最終監査の分類

### in_scope_blocker

0件。

### deferred_followup

- canonical Evidence Validator、confirmed proof、署名provider分離、report/gate統合: `SGK-2026-0422`。
- 実VDP rollout、hidden holdout、M3b/M3c本番運用、M4、kill switch演習: `SGK-2026-0423`。

### non_blocking_observation

- crawler、JavaScript、API schema、GraphQL、browser traffic、proxy historyは、受動producerまたは安全な既存artifactを確認できないため理由付きunavailable。新規crawlや通信は起動していない。実接続は後続タスクへ追跡（deferred_tasks D03）。
- exact replayはmethod/URL/body/header位置のfingerprintで照合し、param値・body・認証が入力境界で破棄されたrequestは誤った証拠を作らずpending/manual reviewに保持する。
- `tests/core/engine` 全体は692 PASS / 30 FAIL / 1 ERROR。失敗はLLM API key認証・Caido未達・bundle欠如・既存スキーマ不一致等の環境依存で、**変更前（0421差分を一時stashしたbaseline）でも同一30件が失敗することを差分比較で確認**しており、0421起因の失敗は0件である。

## 6. 検証（最終実測）

```bash
# VDP関連25ファイル（新規202件 + 既存回帰427件）
.venv/bin/pytest tests/unit/engine/test_vdp_admission.py tests/unit/engine/test_vdp_auth_cache.py \
  tests/unit/engine/test_vdp_budget.py tests/unit/engine/test_vdp_contract.py \
  tests/unit/engine/test_vdp_follow_up.py tests/unit/engine/test_vdp_follow_up_executor.py \
  tests/unit/engine/test_vdp_follow_up_resilience.py tests/unit/engine/test_vdp_hitl_and_admission.py \
  tests/unit/engine/test_vdp_hypothesis_generator.py tests/unit/engine/test_vdp_infrastructure.py \
  tests/unit/engine/test_vdp_observation_adapter.py tests/unit/engine/test_vdp_observation_form_source.py \
  tests/unit/engine/test_vdp_readonly_guard.py tests/unit/engine/test_vdp_real_integration.py \
  tests/unit/engine/test_vdp_resilience.py tests/unit/engine/test_vdp_scope_failclosed.py \
  tests/unit/engine/test_recipe_contracts.py tests/unit/config/test_vdp_mode_settings.py \
  tests/unit/engine/test_task_queue.py tests/unit/engine/test_task_queue_main_thread.py \
  tests/core/engine/test_master_conductor_vdp_hypothesis.py tests/core/engine/test_master_conductor_vdp_follow_up.py \
  tests/core/engine/test_master_conductor_recipe_contracts.py tests/core/engine/test_master_conductor_failure_reason_codes.py \
  tests/core/engine/test_master_conductor_hitl_pending.py -q
# 629 passed (exit 0)

# unit/engine + unit/config 全体
.venv/bin/pytest tests/unit/engine/ tests/unit/config/ -q
# 1234 passed (exit 0)

# MC・session系広域回帰（0421外の既存環境依存30件は変更前baselineと同一）
.venv/bin/pytest tests/core/engine/ tests/test_session_resume.py tests/core/test_config_yaml.py -q
# 692 passed / 30 failed / 1 error (exit 1) — stash差分比較で0421起因0件

git diff --check
# 0 files changed（whitespace 0）
git diff --no-index --check /dev/null <新規13ファイル>
# 全13ファイル whitespace CLEAN

graphify update .
# exit 0; graph.json / GRAPH_REPORT.md更新（新規symbol索引済み）
```

## 7. 残存リスクと未完了事項

0421の未完了事項はない。上記deferred follow-upは実在する0422/0423へ追跡済みであり、固定済み0421完了条件を阻害しない。

## 8. deferred_tasks

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0421-D01
    title: "canonical evidence proof・report・gate統合"
    reason: "confirmed生成、canonical proof、署名境界、report/gateは0421のNOT in scope"
    impact: high
    tracking_task_id: SGK-2026-0422
    recommended_next_action: "0421が保存したAttempt/Evidence/candidate Verdict/NextActionをcanonical Evidence Validatorへ接続する"
  - deferred_id: SGK-2026-0421-D02
    title: "実VDP rollout・hidden holdout・M3b/M3c運用とkill switch演習"
    reason: "実VDP運用判定と段階進級は0423の範囲"
    impact: high
    tracking_task_id: SGK-2026-0423
    recommended_next_action: "隔離環境と事前固定gateでrollout・recoveryを評価する"
  - deferred_id: SGK-2026-0421-D03
    title: "未接続6観測源（crawler/javascript/api_schema/graphql/browser_traffic/proxy_history）の実接続"
    reason: "0421では受動producerを確認できず理由付きunavailableとした。producer特定後は同じObservation契約で接続する（新規crawl禁止のまま）"
    impact: low
    tracking_task_id: SGK-2026-0423
    recommended_next_action: "0423のshadow rollout段階で受動artifact producerを特定し、各sourceをObservationAdapterへ接続する"
```
