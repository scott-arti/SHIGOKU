---
task_id: SGK-2026-0436
doc_type: plan
status: deferred
parent_task_id: SGK-2026-0433
related_docs:
- docs/shigoku/reports/2026-08-08_sgk-2026-0433_m3a-gap-closure-capability_work_report.md
- docs/shigoku/plans/done/2026-08-08_sgk-2026-0433_m3a-gap-closure-capability_plan.md
title: timing ライブ取得と封印harness成果物所有権の改善
created_at: '2026-08-08'
updated_at: '2026-08-08'
tags:
- shigoku
target: src/core/engine + tests/fixtures/vdp_juiceshop_sealed
---

# 実装計画: timing ライブ取得と封印harness所有権改善（SGK-2026-0436・deferred）

SGK-2026-0433 の封印実測で確認された2つの未達・改善を追跡する。

## 1. timing ライブ取得（未達）

0433 の実測（session_20260807_174454）では `timing_measurement` 証拠は 0 件。
executor のタイミング基盤（baseline/positive/negative control・`timing_difference_observed`
marker・`timing_measurement` evidence）はユニット実証済み（19 tests）だが、
対象 candidate の next_action は `_queue_vdp_follow_ups` の exact-replay 判定
（観測に param が含まれる場合は skip。payload_request_mismatch と同じ機構）により
follow-up task 化されず、ライブで実行されなかった。

- 実装: queue skip 条件の見直し（param 付き観測でも timing 系 gap は
  `timing_variant_url` 供給 or 匿名 baseline での実行を許可するか、能力不足を明示する
  明示 reason を追加）。
- 完了条件: 封印 run で `timing_measurement` evidence が少なくとも1件生成され、
  `timing_difference_observed` が "true"/"false" のいずれかで honest に記録される。

## 2. 封印harness成果物所有権（改善）

0433 実測では docker runner（root）が書いた report/session が root 所有（0600 の
haddix_report は bbb から読めず §8 consistency gate が Permission denied で blocked）。
実行後に chown で復旧したが恒久対策が必要。

- 実装: run_m5_audit.sh の main runner に phase 6d と同じ `--user "$(id -u):$(id -g)"`
  を付与（または run 後に chown を追加）。
- 完了条件: 次回封印 run の全成果物がホストユーザー所有で生成される。

## NOT in scope

- Evidence Validator / 閾値の緩和。confirmed 件数の指標化。実VDP通信。
- PCR-P1（task_queue.py）の変更。
