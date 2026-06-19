---
task_id: SGK-2026-0308
doc_type: plan
doc_usage: implementation_plan
status: done
parent_task_id: SGK-2026-0306
related_docs:
  - docs/shigoku/plans/2026-06-17_smart-xss-smart-sqli-split_plan.md
  - docs/shigoku/reports/2026-06-17_SGK-2026-0306_work_report.md
title: '二段分割: SmartXSS/SmartSQLi orchestration logic 抽出 + monkeypatch 継続監視'
created_at: '2026-06-17'
updated_at: '2026-06-18'
tags:
  - shigoku
  - refactor
target: >
  smart_xss.py: 972→400-450, smart_sqli.py: 893→400-450
---

# 二段分割計画: SmartXSS/SmartSQLi orchestration logic 抽出

## 背景
SGK-2026-0306 first pass で pure helper 抽出完了。facade size 削減目標（400行前後）に未達。
`run_as_tool` / `execute` / `_send_request` / `decide` / `act` 等の orchestration logic が残留。

## 完了条件
- [x] `smart_xss.py` が 400-450 行に収まる (現 363 ✓)
- [x] `smart_sqli.py` が 400-450 行に収まる (現 320 ✓)
- [x] 公開 import path (`SmartXSSHunter`, `SmartSQLiHunter`) 維持
- [x] monkeypatch points 互換維持
- [x] targeted pytest: 46 passed / 3 pre-existing

## 実装ステップ

### Step 1: XSS orchestration 抽出 (`smart_xss.py`)
- [x] `execute` 本体 (65 lines) → `smart_xss_orchestration.py` へ `async def xss_execute(...)` として抽出
- [x] `run_as_tool` 本体 (307 lines) → `smart_xss_orchestration.py` へ `async def xss_run_as_tool(...)` として抽出
- [x] `_normalize_name_hints` 内部関数 (23 lines) → `smart_xss_orchestration.py` へモジュールレベル関数として抽出
- [x] `_send_request` 本体 (89 lines) → `smart_xss_dispatch.py` へ `async def xss_send_request(...)` として抽出
- [x] `decide` 本体 (96 lines) → `smart_xss_orchestration.py` へ `async def xss_decide(...)` として抽出
- [x] `act` 本体 (71 lines) → `smart_xss_orchestration.py` へ `async def xss_act(...)` として抽出
- [x] Facade の各メソッドは thin delegation wrapper に置換

### Step 2: SQLi orchestration 抽出 (`smart_sqli.py`)
- [x] `execute` 本体 (85 lines) → `smart_sqli_orchestration.py` へ `async def sqli_execute(...)` として抽出
- [x] `run_as_tool` 本体 (206 lines) → `smart_sqli_orchestration.py` へ `async def sqli_run_as_tool(...)` として抽出
- [x] `_send_request` 本体 (90 lines) → `smart_sqli_dispatch.py` へ `async def sqli_send_request(...)` として抽出
- [x] blind 系メソッド群 (~125 lines) → `smart_sqli_blind.py` へ抽出
- [x] `decide` 本体 (80 lines) → `smart_sqli_orchestration.py` へ `async def sqli_decide(...)` として抽出
- [x] `act` 本体 (43 lines) → `smart_sqli_orchestration.py` へ `async def sqli_act(...)` として抽出
- [x] Facade の各メソッドは thin delegation wrapper に置換

### Step 3: 検証
- [x] `.venv/bin/python -m compileall` 全対象ファイル
- [x] import 確認: `SmartXSSHunter`, `SmartSQLiHunter`
- [x] targeted pytest (plan 記載の 7 ファイル)
- [x] 行数確認: smart_xss.py ≤ 450, smart_sqli.py ≤ 450

### Step 4: ドキュメント更新 (SGK-2026-0306 完了化)
- [x] work_report 更新 (SGK-2026-0306)
- [x] 台帳ステータス更新: SGK-2026-0306 → done
- [x] validate_shigoku_docs.py
