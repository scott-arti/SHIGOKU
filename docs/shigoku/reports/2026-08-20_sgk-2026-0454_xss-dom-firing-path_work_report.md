---
task_id: SGK-2026-0454
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-18_sgk-2026-0454_xss-dom-runtime-firing-path.md
- docs/shigoku/worklogs/2026-08-20_sgk-2026-0454_xss-dom-firing-path_work_log.md
- docs/shigoku/plans/done/2026-08-20_sgk-2026-0455_dom-xss-confirmation-routing.md
title: XSSの発火経路是正（DOM実行検証の到達性・ブラウザ導入・プロキシ経由の回復）作業完了報告
created_at: '2026-08-20'
updated_at: '2026-08-22'
tags:
- shigoku
- xss
- dom
- browser
- proxy
target: src/core/agents/swarm/injection/smart_xss.py,src/tools/browser/playwright_validator.py,src/core/detection/browser_pool.py,src/core/agents/swarm/injection/manager.py,tests/unit
---

# SGK-2026-0454 作業完了報告 — XSSの発火経路是正

## What（何をしたか）

XSSの発火経路の3つの詰まりを是正し、防御ありの相手（OWASP Juice Shop）に対して DOM XSS が**本物のブラウザで実際に発火する**ところまで到達させた。実装は DeepSeek、独立検証は Claude。

- ①到達性：`smart_xss.py` に挙動ベース判定 `_should_attempt_dom_browser_validation` を追加。DVWA目印に依存せず、反射向き汎用パラメータ（`_REFLECTION_ORIENTED_PARAMS`＝PROFILE_PRIORITY_PARAMS の和集合・製品非依存）で、かつサーバ反射が無い generic/reflected 相手もブラウザDOM実行検証へ escalate。DVWA目印判定は温存。
- ②可用性：`playwright_validator._check_availability` がモジュール import に加えブラウザ実体の存在も確認し、未導入時は明示 WARN でスキップ（spec `phase2_3_headless_browser.md:40` 準拠）。venv に chromium 導入。
- ③プロキシ（デグレ回復）：全 `chromium.launch`/`new_context`（`playwright_validator` 6箇所・`smart_xss` DOM fallback・`browser_pool`）を `settings.get_proxy_url()` 正本の proxy 経由へ統一（`build_playwright_proxy_config`・資格情報分離・未設定時は直結）。
- 記録：`injection/manager.py` に recording-only で `attempt_traces` へ `xss:dom_browser_validation` 段階を1件 mark。
- 付随：SPA hash ルート/fragment param 対応、`impact`/`reproduction_steps` を**実測ブラウザ実行証拠に限定**して供給（証拠が無ければ空＝捏造なし）。

## Why（なぜ）

XSSはSQLiより手前で止まり、DOM XSS は fragment 経由のクライアント側実行のためサーバ反射検出では原理的に不可視。本命の確認手段（ブラウザ実行検証）まで攻撃が到達していなかった。確定バーは緩めず、その門まで攻撃を届かせる方針。

## Validation（検証・Claude 独立実施）

- 実確定（実データ）：Juice Shop `/#/search?q=<img src=x onerror=alert(1)>` で Caido(8081)経由・**実ブラウザ alert 発火を実観測**（`browser_execution.dialog_observed=true`, executor=playwright, observation_logs に dialog=alert message=1）。正本 session `session_20260820_023313.json` / report `haddix_report_20260820_023315.md`、整合チェッカ consistent / rerun_required=false。
- C1：`attempt_traces` に `xss:dom_browser_validation` が実データで9回出現。
- C5：バー5点（payout_grade / sealed_reproduction_checker / poc_judge / finding_validator / task_queue）個別 `git diff --quiet HEAD` = exit0。
- C6：`check_vdp_product_independence.py` verdict=pass / total_token_hits=0 / files_scanned=4。
- C7：新規ユニット 40 pass（test_xss_dom_routing 21 + test_playwright_proxy_availability 16 + test_xss_trace_recording 3）、関連回帰 107 pass。既存2失敗（`test_validate_xss_success` の 'console'!='dialog'、`test_pool_exhaustion_handling` の TimeoutError）は HEAD でも同一失敗＝本変更由来でないことを一時 worktree で確認。
- コミット：`94a083c`（コード＋テスト7ファイル。docの巻き戻しや別セッションの data/learnings は除外）。push はユーザー。

## Risks / 未達（正直な開示）

- **C4（本物のXSSを confirmed に）は未達**：confirmed=0。当該 XSS finding（id 512d98c4bde8）は `finding_funnel_v1` 実測で **F3(phase2) の `phase2_skipped_early_return` / `risk_not_met` / `phase2_on_empty_disabled` で脱落**し、確定判定(F5/F6)へ未到達。Gate は正しく fail-closed。
- 原因は凍結したバー5点ではなく手前の phase2 昇格ロジックにある可能性が高いが**未診断（hypothesis）**。DeepSeek が当初報告した「判定予算枯渇/poc_judge形式拒否」は funnel 実データと矛盾し、Claude 独立検証で否定。
- DeepSeek の STEP4「片付け」で 0454 計画書・台帳・registry を一時ファイルと誤認し削除していたため、`git checkout HEAD --` で復旧のうえ done ライフサイクルへ移行した。

## Next step

C4（ブラウザ実行証拠の確定経路是正）は後続 **SGK-2026-0455**（`plans/2026-08-20_sgk-2026-0455_dom-xss-confirmation-routing.md`）へ分離。まず F3(phase2) 脱落の精密診断から着手（バー無改変・カーブフィッティング禁止を継承）。

## deferred_tasks

```yaml
deferred_tasks:
  - description: DOM XSS のブラウザ実行証拠を phase2 昇格〜確定判定まで運び confirmed=1 にする（バー無改変・製品非依存）
    tracking_task_id: SGK-2026-0455
    tracking_doc: docs/shigoku/plans/done/2026-08-20_sgk-2026-0455_dom-xss-confirmation-routing.md
```
