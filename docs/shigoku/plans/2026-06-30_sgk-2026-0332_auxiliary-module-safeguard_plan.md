---
task_id: SGK-2026-0332
doc_type: plan
status: active
parent_task_id: SGK-2026-0330
related_docs:
  - docs/shigoku/reports/2026-06-30_SGK-2026-0330_work_report.md
created_at: '2026-06-30'
updated_at: '2026-07-02'
---

# 補助系モジュールへのshared safeguard段階展開

## 概要

`distributed_sqli.py` や `second_order_assistant.py` などの補助系モジュールは、
直接 HTTP 送信主体でない経路が混在している。
実送信 path が確認できたものから段階的に shared safeguard 配下へ寄せる。

## 背景

SGK-2026-0330 で主要 injection specialist (SQLi/XSS/LFI/CMD-SSRF) への展開は完了したが、
補助系モジュールは未調査。

## スコープ

- 補助系モジュールの実送信 path 棚卸し
- 対象リストの作成
- 段階的な safeguard 注入
