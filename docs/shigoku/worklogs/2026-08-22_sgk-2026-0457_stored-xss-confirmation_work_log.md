---
task_id: SGK-2026-0457
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0457_stored-xss-confirmation.md
- docs/shigoku/reports/2026-08-22_sgk-2026-0457_stored-xss-confirmation_work_report.md
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0458_stored-xss-firing-path.md
title: 保存型(Stored)XSSのreproduction gateにstored分岐を追加 作業ログ
created_at: '2026-08-22'
updated_at: '2026-08-22'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- xss
- stored
- browser
- confirmation
---

# SGK-2026-0457 作業ログ（実装フェーズ・独立検証・実走行）

## 2026-08-22

### 実装（確定側のみ・検出側は触らない）

- `src/core/validation/sealed_reproduction_checker.py`:
  - L241-245 の DOM 分岐条件 `variant=="dom"` を `variant in {"dom","stored"}` に拡張（test_url 条件は従来どおり）。`_check_dom_via_browser`（再訪 test_url を browser 再ロード＝GET 読み取りで dialog 再観測）へ委譲。
  - コメント/docstring を DOM/stored 共用経路として更新のみ（判定ロジック・DOM 経路・反射型 HTTP 経路は無改変・byte-identical）。
- テスト `tests/core/validation/test_sealed_reproduction_checker.py`: `TestStoredBrowserPath` 10 件追加（T1）。検出側スキーマ（smart_xss.py:719-727 `stored_revisit_browser_execution`・variant=stored・test_url=再訪 URL）を再現する fixture を使用。
- 無改変確認: `payout_grade.py`/`poc_judge.md`/`task_queue.py`/`finding_validator.py` 各 `git diff --quiet HEAD` exit0。`smart_xss.py` exit0。

### 検証（独立実施・額面で信用しない）

- ユニット: `test_sealed_reproduction_checker.py` **48 passed**（既存 DOM/HTTP 回帰含む）・`test_t3_hybrid_wiring.py` + `test_poc_judge_browser_evidence.py` **45 passed**・`test_smart_xss_logic.py` **11 passed**。HEAD 既知失敗以外に新規失敗ゼロ。
- バー diff: 4 ファイル exit0。
- 製品非依存: `check_vdp_product_independence.py` verdict=pass / token_hits=0。

### 実走行（Caido 8081・SHIGOKU_T3_HYBRID_ENABLED=1・GET_ONLY 無し＝保存 POST 許可）

- 実行: `.venv/bin/python -m src.main --target http://localhost:3000 --mode vulntest`（Caido=127.0.0.1:8081・診断/ツールコーリング/dedup 有効・Coverage Gate PASS・成功率 91.3%・1458s）。
- 正本: `session_20260822_014604.json` / `haddix_report_20260822_014606.md` → **consistent / rerun_required=false**。
- 結果: `variant="stored"` の finding **0 件**（`browser_execution` 24 件すべて `variant="dom"`・param `q`）。confirmed=1 は DOM 経路。
- 真因（引用特定）: `smart_xss.py:238-246 _detect_xss_variant()` は `xss_s`（DVWA 目印）のみ "stored" を返し Juice Shop は "generic"。deterministic precheck 反射観測（:1120-1127）は `variant=="stored"` のみ stored 検証へ。ThoughtLoop `stored_probe`（:1384・LLM 主導・`reflection_url` 必要）は選択されず。**保存 sink → 再訪レンダー発火を挙動ベース・製品非依存で発見する経路が検出側に存在しない**。

### 分離と ledger 遷移（ユーザー承認 2026-08-22）

- C1（stored 分岐経由 confirmed=1）は検出側発火が無いため未達。**ユーザー承認のもと SGK-2026-0457 を done で閉じ、C1 を SGK-2026-0458（検出側 stored 発火経路・active plan）へ deferred**。計画書の完了契約を更新し done/ へ移動。
- 台帳: task_registry.yaml（0457 plan → done・work_report/work_log 追加・0458 plan 追加）・task_ledger.md（0457 → done・0458 追加）。

## 参考ルール

rules/lessons.md（一ファイルの挙動を仕様と断定しない・sealed run の REAL target 到達検証・スコープ固定）、rules/codingrules.md（局所変更・偽陽性防止）、rules/task-ledger.md、rules/shigoku-docs.md、rules/python-tests.md。
