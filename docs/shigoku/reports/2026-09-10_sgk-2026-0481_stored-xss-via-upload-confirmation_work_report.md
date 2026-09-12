---
task_id: SGK-2026-0481
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-10_sgk-2026-0481_stored-xss-via-upload-confirmation.md
- docs/shigoku/worklogs/2026-09-10_sgk-2026-0481_stored-xss-via-upload-confirmation_work_log.md
- docs/shigoku/reports/2026-09-10_sgk-2026-0480_file-upload-retrieval-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- file-upload
- stored-xss
- evidence-quality
created_at: '2026-09-10'
updated_at: '2026-09-11'
---

# SGK-2026-0481 作業完了報告 — アップロード経由の保存型XSS（実害）を実DVWAで本物確定（◎）

## 何をしたか / なぜ

SGK-2026-0480 でファイルアップロードは「設置＋Web取得」を機械＋再現で確定（○）したが、本物の
AI 審査（poc_judge）は「良性設置＋取得だけでは実害未証明＝賞金級でない」として非承認だった。本タスクは
**アップロードした HTML がブラウザで実行される＝アップロード経由の保存型XSS**という**実害**を、実対象で
実ブラウザ発火（合言葉 nonce 往復）まで実証し、完全3ゲート（機械フロア＋実再現＋実 poc_judge）で
◎ に到達させた。非破壊（alert のみ・破壊/永続化/データ持出しなし）。

## 実装（すべて非凍結・凍結5ファイルは無改変）

- **payload_manager.py**: `get_xss_probe_payload(nonce)` を追加。良性 HTML
  `<html><body><img src=x onerror=alert('<nonce>')></body></html>`（mime=text/html・サーバ側
  実行コードなし）。nonce を content にそのまま含める（取得確認に使う）。
- **file_upload_tester.py**: `locate_uploaded(...)` を追加。既存 `_execute_upload` /
  `_extract_response_suggested_paths` / `_verify_retrieval` を再利用し「アップロード→取得URLを
  マーカー（nonce）往復で確定」を返す（retrieved でなければ ("","")）。マーカー照合は nonce の
  本文含有でも許容（HTML がラップされても判定できる・既存0480経路の判定は不変）。
- **file_upload.py**: `xss_via_upload` モード（opt-in）。nonce 生成→良性 HTML アップロード→取得URL
  確定→`PlaywrightValidator().validate_xss(retrieval_url, cookies=...)` で実ブラウザ発火確認→
  観測 dialog message == nonce のときだけ vuln_type=XSS の Finding を発行
  （`browser_execution.variant=stored`・`test_url=retrieval_url`・nonce・nonce_match＋impact/repro）。
  dialog 非発火／nonce 不一致／ブラウザ利用不可は Finding なし（fail-closed・偽◎なし）。
- **証拠の見せ方の底上げ（追補・file_upload.py のみ）**: 発火確定後、取得URLを GET し**生の配信本文
  （実際に配信された HTML バイト列＝nonce ペイロードを含む）**を `evidence.response_body` に併記
  （SGK-2026-0479 と同型）。取得失敗でも Finding は止めない（best-effort）。確定バー・発火判定は不変。

## 結果（独立検証・Claude が実測）

- **実 DVWA `/vulnerabilities/upload/`** に実 `FileUploadSpecialist.execute` が良性 HTML を
  アップロード→取得URLを nonce 往復で確定→実ブラウザで dialog message == nonce（実行確定）→
  `payout_grade=True/reflected_payload`→**実 `SealedReproductionChecker` が取得URLを実ブラウザ
  再ロードし dialog 再観測→matched→CONFIRMED**。
- **本物の poc_judge（実LLM）で 4/4 承認（real=True・impact=True・errors=0）**。証拠の底上げ前は
  1/4 だったが、生の配信本文（nonce ペイロードを含む実バイト列）を証拠に載せたことで
  「配信レスポンス本文に注入ペイロードがサニタイズされず HTML 配信＋同一URLで onerror 実行＋nonce 一致」
  という**独立検証可能な生証拠**を審査が評価し全承認。**完全3ゲート達成＝◎**。
- テスト: 新規16テスト緑。`tests/core/agents/swarm/logic/` `tests/core/attack/` の失敗4件は本変更前
  （HEAD）でも失敗する既存（idor_mass_assignment×2・attack/test_file_upload の既存アサーション・
  graphql extract_sensitive）で、**0481 起因の回帰はゼロ**。
- 凍結5ファイル（payout_grade.py / sealed_reproduction_checker.py / poc_judge.md / task_queue.py /
  finding_validator.py）は各 `git diff --quiet HEAD` exit 0。製品非依存 token 0。

## 確度の結論（正直な格付け）

- ファイルアップロードは「設置＋取得のみ」では実害が無く実 poc_judge を通らない（○・0480）。
  **アップロード経由の保存型XSS＝実害あり**では、実ブラウザ発火＋生証拠で実 poc_judge も通り
  **◎（完全3ゲート）**。バーを下げて通す curve-fit は一切していない（生証拠の見せ方の底上げのみ）。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の「実 poc_judge も通す」を 4/4 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §15（台帳ワークフロー）・§17（動的ルールロード）・§19（完了契約の固定・カーブフィット禁止）、
`rules/lessons.md`（再発防止）、メモリ [[no-capability-minimization]]。
