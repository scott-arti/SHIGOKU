---
task_id: SGK-2026-0434
doc_type: plan
status: done
parent_task_id: SGK-2026-0432
related_docs:
- docs/shigoku/subtasks/2026-08-08_sgk-2026-0432_gap-closure-causal-diagnosis_subtask_plan.md
title: payload_request_mismatch probe の funnel-truth 改善
created_at: '2026-08-08'
updated_at: '2026-08-09'
tags:
- shigoku
target: src/core/engine
---

# 追跡計画: payload_request_mismatch probe の funnel-truth 改善（SGK-2026-0434・active）

SGK-2026-0432の診断（payload_request_mismatch ×2 = (H)、値破棄による構造的閉塞不能）から派生した任意改善: ペイロード再現不能な payload_request_mismatch gap に対し、**ペイロード無しprobeを実行せず** S07 `exact_request_material_unavailable` で block する（fabricated generic request 禁止契約の強化。誤解を招く S08/S10/S11 到達を防ぎ、funnelを正直にする）。

- 対象: `vdp_follow_up_executor.py` の S07 exact-material 判定（param破棄ケースで spec param が空のため現状probeが通る）＋`vdp_hypothesis_generator` の gap 発行条件（破棄材ありの payload_request_mismatch を m3a で発行しない）。
- 必須テスト: 破棄材ケースで S07 blocked（probe未送信）・healthy ケース回帰0・funnel first-failure が S08→S07 に正直化・安全0・preflight exit 0。
- 完了条件: counterfactual（changed_variable=attempt）で漏斗の正直化を実測。本タスクは deferred（未着手・任意改善）。
