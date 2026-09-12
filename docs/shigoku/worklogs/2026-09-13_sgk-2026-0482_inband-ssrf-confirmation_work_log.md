---
task_id: SGK-2026-0482
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0482_inband-ssrf-confirmation.md
- docs/shigoku/reports/2026-09-13_sgk-2026-0482_inband-ssrf-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- ssrf
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0482 作業ログ（in-band SSRF・実crAPI・◎）

## 1. 偵察（事実優先・実測）
- Juice Shop/DVWA に SSTI/CRLF/sourcemap/GraphQL のシンク無し（実測で空振り確認）。
- crAPI 稼働中。認証付き POST(`contact_mechanic`型)が URL 値フィールドをサーバ取得し応答本文を in-band 反映
  （`response_from_*`）。内部専用ホスト(`crapi-identity:8080`→TLS required, `mailhog:8025`→MailHog UI)へ到達し
  反映＝クライアント直接到達不可の差分で SSRF 実証可能。OOB 不要。

## 2. 台帳・計画・承認
- SGK-2026-0482 採番。凍結2(payout_grade/sealed_reproduction)改変はユーザー明示承認。

## 3. 実装（Claude 直接・小粒surgical）
- payout_grade: ssrf 分岐に `ssrf_inband`（fetched_url+server_reflected_body+client_direct_unreachable 全揃い
  でのみ発火・fail-closed）。既存 ssrf_callback 不変。
- sealed_reproduction: `_check_inband_ssrf_replay`＋`_send_post_json`＋`_sync_http_post_json`。トリガ POST を
  in-scope endpoint へ再送し reflect_key 値再出現で matched。probe_url 直送はしない。
- smart_ssrf: `ssrf_inband` opt-in（製品非依存パラメータ）。反映抽出＋直接到達差分→Finding（evidence に生反映
  本文＋poc_request/poc_response＋ssrf_inband_evidence/replay）。

## 4. 独立検証（Claude・実出力）
- 実 crAPI E2E: 実 execute→`mailhog:8025` 反映＋client直接到達不可→payout_grade=True/ssrf_inband→実再現 matched
  →CONFIRMED（reflected_len 4000）。
- 実 poc_judge: 底上げ前 1/4（理由: 反映がエラー文字列・poc_request/response null）→(a)生 poc_request/response
  付与＋(b)probe 先を200返す内部MailHog UIに変更→**4/4 承認**（real/impact True・errors0）＝完全3ゲート達成。
- 新規12テスト緑。非回帰: 失敗3件は HEAD でも失敗する既存(phase_b_readiness×2・t3_hybrid_wiring budget・
  stash で確認)＝0482 起因の回帰ゼロ。凍結3 exit 0。token0。

## 5. 完了
- 完了条件1〜5 充足（条件3 実 poc_judge 4/4）。in_scope_blocker 0 → done。
- 能力マップ: SSRF を ◎（in-band 完全3ゲート・OOB基盤は別件で未整備・ssrf_callback 併存）。
- 教訓: 実害ある脆弱性でも「生の PoC 対(poc_request/response)」と「意味ある内部 probe 先(200で内部サービス内容)」
  で実 poc_judge 通過率が激変(1/4→4/4)。バー非低下・証拠の実体と見せ方の強化。[[no-capability-minimization]]。
- 観測(別件): task_registry の 0465 以降が tasks: 外に連なる構造ずれ(運用影響なし)。§12 で別途判断。
