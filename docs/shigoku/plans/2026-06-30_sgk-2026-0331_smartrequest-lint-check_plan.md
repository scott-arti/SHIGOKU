---
task_id: SGK-2026-0331
doc_type: plan
status: active
parent_task_id: SGK-2026-0330
related_docs:
  - docs/shigoku/reports/2026-06-30_SGK-2026-0330_work_report.md
created_at: '2026-06-30'
updated_at: '2026-07-02'
---

# SmartRequest直生成の定期チェック自動化

## 概要

CI パイプラインで `SmartRequest(` および `get_request_guard(` の直呼びを検出するアサーションスクリプトを追加し、
共有 `ExecutionSafeguardService` のバイパスを防止する。

## 背景

SGK-2026-0330 で `smart_lfi.py` の未適用箇所を修正したが、
将来的に新規 specialist が `SmartRequest` を独自生成する可能性がある。
lint/grep ベースの定期チェックで予防する。

## スコープ

- CI パイプラインへの lint スクリプト追加
- 対象パターン: `SmartRequest(network_client=...)` (execution_safeguard なし)
- 対象パターン: `get_request_guard(` (get_execution_safeguard 非経由)
