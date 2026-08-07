---
task_id: SGK-2026-0428
doc_type: plan
status: deferred
parent_task_id: SGK-2026-0426
related_docs:
- docs/shigoku/reports/2026-08-06_sgk-2026-0426_vdp-product-independent-improvement_work_report.md
created_at: '2026-08-07'
updated_at: '2026-08-07'
tags:
- shigoku
- test-hygiene
- deferred
target: tests/core/engine,tests/core/security,src/core/engine
---

# SGK-2026-0428: bug-bounty bundle preflight のテスト baseline 失敗の解消

SGK-2026-0426 の裏取り（広域 engine/reporting 回帰）中に観測された既存 baseline 失敗を、独立した追跡タスクとして起票する。**0426 の変更が原因ではない**（0426 面のテストは全 pass）。

## 背景 / 観測

- 広域回帰（`.venv/bin/pytest tests/core/engine tests/unit/engine tests/unit/reporting` 系）で **7 件**が失敗。
- 失敗シグネチャ: `active_bundle_missing` / `_preflight_failed`（bug-bounty bundle の preflight ガードが、テスト環境で active bundle 未設定のため fail-closed）。
- 由来: SGK-2026-0281 / セキュリティ baseline 分離（SGK-2026-0400 系）で導入された bundle preflight ガード。ガード自体は正しく fail-closed しており、**製品挙動のバグではなくテスト fixture の不足**。
- 主な入口: `tests/core/engine/test_master_conductor_bugbounty_bundle_preflight.py`、関連 `tests/core/security/test_bundle_*.py`。

## 完了条件（着手時に確定する）

1. 7 件の失敗テストの正確な node id を確定し、それぞれ「fixture 不足」か「実挙動不整合」かを分類する。
2. fixture 不足のものは、テスト用 active bundle / preflight 状態を提供する fixture を追加して green 化する（製品ガードは緩めない）。
3. 実挙動不整合が混在する場合のみ、別 in_scope として切り出す。
4. 回帰: 対象テスト green ＋ PCR 系・preflight ガードの安全境界を無改変で維持。

## NOT in scope

- bundle preflight ガードそのものの緩和・無効化（安全境界のため禁止）。
- SGK-2026-0429（LLM キー依存テストの隔離）— 別タスク。

## 再現

```
.venv/bin/pytest tests/core/engine/test_master_conductor_bugbounty_bundle_preflight.py -q
```
