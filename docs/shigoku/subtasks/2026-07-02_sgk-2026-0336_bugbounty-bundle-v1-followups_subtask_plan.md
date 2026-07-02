---
task_id: SGK-2026-0336
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0282
related_docs:
  - docs/shigoku/subtasks/done/2026-07-01_bug-bounty-scope-bundle-guard-policy-compile_subtask_plan.md
  - docs/shigoku/reports/2026-07-02_sgk-2026-0335_work_report.md
  - docs/shigoku/specs/2026-07-02_sgk-2026-0335_v1-acceptance-criteria.md
  - docs/shigoku/manuals/2026-07-02_sgk-2026-0335_bugbounty-bundle-operator-runbook.md
title: Bug Bounty bundle V1 deferred follow-ups
created_at: '2026-07-02'
updated_at: '2026-07-02'
tags:
  - shigoku
target: src/core/security/, src/core/engine/, docs/shigoku/
---

# 実装計画書：Bug Bounty bundle V1 deferred follow-ups

## 1. 達成したいゴール（ユーザー視点）
- [ ] SGK-2026-0335 の V1 完了時に deferred とした運用・品質残課題が、単一の active task で追跡され続ける。
- [ ] 各 deferred 項目に優先度、完了条件、次アクションがあり、後続の実装判断で宙に浮かない。
- [ ] V1 の closeout document と運用 runbook から、この follow-up task を正本の追跡先として辿れる。

## 2. 対象スコープ
- `SGK-2026-0335-D01`: stale bundle detection（age-based）
- `SGK-2026-0335-D02`: concurrent bundle update control（file lock）
- `SGK-2026-0335-D03`: Prometheus endpoint for metrics export
- `SGK-2026-0335-D04`: automated shadow->enforcement stage promotion
- `SGK-2026-0335-D05`: `--scope` internal code removal（Phase C-E）

## 3. 実施方針
- stale / concurrency / metrics export / auto-promotion / legacy removal を同一サブタスク配下で管理し、必要になった時点で個別実装タスクへ再分割する。
- `SGK-2026-0335` の V1 受け入れ条件は維持し、この subtask では V1 scope 外とした改善だけを扱う。
- 新規実装に着手する際は、本 subtask を親として追加の `plan` / `subtask_plan` を起票してもよい。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: bundle registry に age tracking を追加し、staleness threshold と warning / block 条件を定義する。
- [ ] ステップ2: bundle import / compile / activate に file-based advisory lock を導入し、競合時の fail-closed / retry policy を定義する。
- [ ] ステップ3: `guard_metrics.snapshot()` を Prometheus exposition format へ変換する export 経路を追加する。
- [ ] ステップ4: metrics-based readiness check を実装し、shadow から enforcement への自動 promotion 条件と rollback 条件を定義する。
- [ ] ステップ5: bug bounty mode で封鎖済みの legacy `--scope` 内部コードを Phase C-E で段階撤去する。

## 5. deferred_tasks との対応表
| deferred_id | title | 追跡先 |
| --- | --- | --- |
| SGK-2026-0335-D01 | stale bundle detection（age-based） | SGK-2026-0336 |
| SGK-2026-0335-D02 | concurrent bundle update control（file lock） | SGK-2026-0336 |
| SGK-2026-0335-D03 | Prometheus endpoint for metrics export | SGK-2026-0336 |
| SGK-2026-0335-D04 | automated shadow->enforcement stage promotion | SGK-2026-0336 |
| SGK-2026-0335-D05 | `--scope` internal code removal（Phase C-E） | SGK-2026-0336 |

## 6. 既知のリスクと次回の申し送り
- [ ] [重要度:中] 5 項目を単一 task に束ねているため、実装着手時にスコープ過大なら再分割が必要。
- [ ] [重要度:中] V1 運用で false block や bundle churn が増えた場合、優先順位は stale / auto-promotion より rollback safety を優先して見直す。
