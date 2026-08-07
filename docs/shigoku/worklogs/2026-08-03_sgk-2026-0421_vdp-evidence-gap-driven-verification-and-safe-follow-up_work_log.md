---
task_id: SGK-2026-0421
doc_type: work_log
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/reports/2026-08-03_sgk-2026-0421_vdp-evidence-gap-driven-verification-and-safe-follow-up_work_report.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0421_vdp-evidence-gap-driven-verification-and-safe-follow-up_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0422_vdp-canonical-evidence-reporting-and-separated-quality-gates_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_subtask_plan.md
title: VDP evidence gap driven verification and safe follow-up 作業ログ
created_at: '2026-08-03'
updated_at: '2026-08-07'
tags:
- shigoku
---

# 作業ログ：SGK-2026-0421

## 実施内容

1. AGENTS.md、関連rules、固定済み計画書、親・依存・後続計画を再読し、実装前監査（17項目）を3ラウンドで承認まで引き上げた。
2. Graphify queryと実コードを照合し、reason code正本・scope fail-closed・HITL strict化・budget原子性・queue main-thread強制などの矛盾21件を監査へ反映した。
3. 承認されたTDD順序（15ステップ）で実装した。各ステップで失敗テストを先行させ、最小実装でGREENへ進めた。
4. M3aフック（`_queue_vdp_follow_ups` / `_dispatch_vdp_follow_up`）をMasterConductorへadditive接続し、queue前pending保存→実queue→dispatch→通信直前再admission→fake network→Attempt/Evidence→session保存→M0 gate→復元の実経路テストを通した。
5. task_queueのdocstring内assert（C23）を実コードへ移動し、非main threadからのmutationをAssertionErrorで拒否するテストを追加した。
6. 最終回帰でVDP系629件・unit全体1234件PASSを確認し、tests/core/engineの30失敗が変更前baselineと同一（環境依存）であることをstash差分比較で証明した。
7. `graphify update .`を実行し、新規symbolとartifact更新時刻を確認した。
8. work report/work log、計画書checkbox、registry、ledgerをDONEへ同期した（計画書はdone/へ移動済み）。

## TDD記録（実測）

- Step1 reason mapping: 失敗テスト（vocabulary/unknown/coverage）→ `recipe_contracts`拡張 + `vdp_follow_up.py` → 70件PASS。
- Step3 form観測源: `location=="form"`接続 + source別unavailable → 12件PASS。
- Step4 scope fail-closed: singleton不使用の純粋判定へ書換 → 12件PASS。
- Step5 read-only guard: method単独でなく意味判定（GraphQL mutation拒否等）→ 18件PASS。
- Step6-7 HITL実在/binding + admission順序・budget原子性 → 19件PASS（0419の任意ticket通過テスト2件をstrict化）。
- Step8-9 executor・決定論ID・fingerprint → 21件PASS。
- Step11-12 resilience（circuit/concurrency/redirect/backpressure/StateChangeGuard/dedup/secret）→ 13件PASS。
- Step13-14 MC実経路統合（real-path + zero-socket + kill switch + enqueue失敗 + scope再admission）→ 8件PASS。
- Step15 回帰: VDP系25ファイル **629 passed**（新規202件 + 既存427件）、`tests/unit/engine`+`tests/unit/config` 全体 **1234 passed**、`tests/core/engine` 692 passed / 30 failed / 1 error（**stash差分比較で0421起因0件**、LLM key認証・Caido・bundle等の既存環境依存）。

## 安全性

- 0421のVDP経路は実VDP・外部サイトへの通信なし。fake transport以外のsocket作成0件。
- confirmed生成なし。dependency failure、timeout、scope/budget blockはrefutedへ変換しない。
- M3aのstate change、HITL bypass、scope逸脱、budget超過、hidden retry、silent queue lossは反証testで0件。
- secret値をObservation、spec、Attempt、Evidence、sessionへ平文保存しない。

## 次アクション

- SGK-2026-0422: canonical proof、Evidence Validator、report/gate統合。
- SGK-2026-0423: 実VDP rollout、hidden holdout、M3b/M3c/M4、kill switch演習。
