---
task_id: SGK-2026-0454
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-18_sgk-2026-0454_xss-dom-runtime-firing-path.md
- docs/shigoku/reports/2026-08-20_sgk-2026-0454_xss-dom-firing-path_work_report.md
title: XSSの発火経路是正 作業ログ
created_at: '2026-08-20'
updated_at: '2026-08-20'
tags:
- shigoku
- xss
- dom
---

# SGK-2026-0454 作業ログ

## 2026-08-20

- 環境実測：Juice Shop(3000) 稼働、Caido は **8081**（8080 は SearXNG）。Caido(8081) がパス依存で実転送することを curl で確認（version/search/top が別内容・502でない）。lessons 2026-08 のスタブ握り潰しチェック合格。
- STEP1（②）：venv に chromium 導入（chrome-headless-shell v1223）。`_check_availability` をブラウザ実体確認付きへ是正。launch+navigate OK を実起動確認。
- STEP2（③）：`build_playwright_proxy_config` で proxy 一元化。全 launch/new_context を settings.get_proxy_url 経由に配線。資格情報分離・redact を確認。
- STEP3（①）：`_should_attempt_dom_browser_validation` 追加、958 ゲートを `== "dom"` から挙動ベース判定へ変更。`param_name` は `for param_name in candidate_params` ループ内で常に束縛（未定義リスク無し）を確認。manager.py に recording-only trace mark。
- STEP4（e2e）：`SHIGOKU_CAIDO__URL=http://127.0.0.1:8081` で実走行。`/#/search?q=<img src=x onerror=alert(1)>` で実ブラウザ alert 発火を実観測。attempt_traces に DOM 段階出現。ただし confirmed=0（funnel F3 phase2 で脱落）。
- Claude 独立検証：バー5点 diff0、製品非依存 pass/token0、新規40+回帰107 pass、既存2失敗は HEAD 同一（一時 worktree で確認）。impact/steps は実測発火に条件づけ（捏造なし）を diff で確認。
- 判明した報告の不正確さ（Claude が訂正）：DeepSeek 報告の新規テスト件数（59→実40）、confirmation ブロック理由（予算枯渇/poc_judge→実は F3 phase2 risk_not_met）、環境記述（8080=Caido→実は 8081）。
- コミット `94a083c`（コード＋テストのみ）。方針B で 0454 を done、C4 を SGK-2026-0455 へ分離。DeepSeek が誤削除した 0454 計画書・台帳・registry を復旧のうえ done 移行。
