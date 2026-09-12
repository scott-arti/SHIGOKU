---
task_id: SGK-2026-0481
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-10_sgk-2026-0481_stored-xss-via-upload-confirmation.md
- docs/shigoku/reports/2026-09-10_sgk-2026-0481_stored-xss-via-upload-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- file-upload
- stored-xss
created_at: '2026-09-10'
updated_at: '2026-09-11'
---

# SGK-2026-0481 作業ログ（アップロード経由の保存型XSS・実DVWA・◎）

## 1. 事実確認（実測・書き込み承認済み）
- 実 DVWA /vulnerabilities/upload/ に良性 HTML（<img src=x onerror=alert('<nonce>')>）→GET 取得URL が
  text/html 200・本文に nonce→実ブラウザで dialog message == nonce（実行確定）。取得URLは応答 echo＋
  nonce 往復 GET で確定。

## 2. 台帳・計画・凍結方針
- SGK-2026-0481 採番。凍結5ファイルは無改変で ◎ 経路が閉じる（0477 のブラウザ発火バー＋0455/0457 の
  DOM/stored 再現＋0479 の nonce 往復を再利用）。変更は非凍結3ファイル＋tests/のみ。

## 3. 実装
- payload_manager: get_xss_probe_payload(nonce)＝良性 HTML＋nonce alert・text/html。
- file_upload_tester: locate_uploaded＝アップロード→取得URL確定（nonce 往復）。
- file_upload.py: xss_via_upload モード（取得URL確定→実ブラウザ発火→observed==nonce で xss Finding・
  browser_execution variant=stored・fail-closed）。
- 証拠底上げ（追補・file_upload.py のみ）: 発火後に取得URLを GET し生の配信本文を evidence.response_body
  に併記（0479 と同型）。確定バー・発火判定は不変。small surgical のため DeepSeek 儀式は使わず直接編集し
  Claude が独立フル検証。

## 4. 独立検証（Claude・実出力）
- 実 DVWA E2E: 実 execute→dialog==nonce→payout_grade=True/reflected_payload→実 SealedReproduction
  実ブラウザ再ロード matched→CONFIRMED。
- 実 poc_judge: 証拠底上げ前 1/4 → 底上げ後 **4/4 承認（real/impact True・errors 0）**＝完全3ゲート達成。
- 新規16テスト緑。非回帰: 失敗4件は HEAD でも失敗する既存（idor_mass_assignment×2・
  attack/test_file_upload・graphql extract_sensitive）＝0481 起因の回帰ゼロ。
- 凍結5 exit 0。製品非依存 token 0。

## 5. 完了
- 完了条件1〜5 充足（条件3 実 poc_judge 4/4）。in_scope_blocker 0 → done。
- 能力マップ: ファイルアップロードに「アップロード経由の保存型XSS＝◎（完全3ゲート）」を追記。
- 教訓: 実害ある脆弱性でも「証拠の見せ方（生の応答本文）」次第で実 poc_judge の通過率が激変する
  （1/4→4/4）。要約でなく生証拠を渡す＝0479 と同型。[[no-capability-minimization]]。
