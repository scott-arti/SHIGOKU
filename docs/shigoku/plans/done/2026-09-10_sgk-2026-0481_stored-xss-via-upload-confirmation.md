---
task_id: SGK-2026-0481
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-10_sgk-2026-0480_file-upload-retrieval-confirmation.md
- docs/shigoku/plans/done/2026-09-10_sgk-2026-0479_xss-nonce-roundtrip-evidence.md
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0477_xss-browser-execution-confirmation.md
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

# SGK-2026-0481 計画 — アップロード経由の保存型XSS（実害）を実DVWAで本物確定（◎）

## 目的（何を・なぜ）

SGK-2026-0480 で「良性ファイルの設置＋Web取得」は機械＋再現で確定（○）したが、本物の AI 審査は
「実害未証明」で非承認だった。本タスクは**アップロードした HTML/SVG がブラウザで実行される
（＝アップロード経由の保存型XSS）**という**実害**を、実対象で実ブラウザ発火（合言葉往復）まで実証し
◎ に到達させる。非破壊（alert のみ・破壊/永続化/データ持出しなし）。

## 事実（実測・実コードで確定・2026-09-10・書き込み承認済み）

- 実 DVWA `/vulnerabilities/upload/` に良性 HTML（`<img src=x onerror=alert('<nonce>')>`）を
  アップロード→`GET /hackable/uploads/<name>` が **content-type: text/html・200**・本文にマーカー→
  実ブラウザで開くと **dialog message == nonce**（実行確定）。取得URLは応答 echo＋マーカー往復で確定。
- 既存資産で ◎ 経路が閉じる（**凍結変更不要**）:
  - 確定バー `payout_grade` の xss 分岐は `additional_info.browser_execution.dialog_observed` 真で
    `reflected_payload` を発火（SGK-2026-0477）。
  - 再現 `sealed_reproduction._check_dom_via_browser` は `browser_execution.variant` が dom/stored かつ
    `test_url` があれば test_url を実ブラウザ再ロードし dialog 再観測で matched（SGK-2026-0455/0457）。
  - 一意マーカー（nonce）往復は SGK-2026-0479 と同型（テンプレ捏造不可の実行証拠）。
- 取得URLの特定は製品非依存（応答 echo の汎用抽出＋クロール在庫＋パス予測→**マーカー往復GETで実証確定**）。
  実行可否は**実ブラウザ発火**が唯一の真実（サーバの content-type 依存）。発火しなければ fail-closed。

## 対象（このタスクで触るファイル・すべて非凍結）

- `src/core/attack/payload_manager.py`: `get_xss_probe_payload(nonce)` を追加。良性 HTML（または SVG）に
  `<img src=x onerror=alert('<nonce>')>` を含む content、mime=text/html（svg は image/svg+xml）、
  filename=`probe_<rand>.html`。サーバ側実行コード（PHP 等）は含めない。
- `src/core/attack/file_upload_tester.py`: `upload_and_locate(target, param, payload, extra, auth)` 相当の
  ヘルパー（既存 `_execute_upload`＋`_extract_response_suggested_paths`＋`_verify_retrieval` を再利用）で
  「アップロード→取得URL確定（マーカー往復）」を返す（retrieval_url / retrieval_marker）。
- `src/core/agents/swarm/logic/file_upload.py`: stored-XSS-via-upload モード
  （`task.params.get("xss_via_upload")` 真、または専用メソッド）を追加。上記で取得URLを確定後、
  `PlaywrightValidator().validate_xss(retrieval_url, cookies=...)` で実ブラウザ発火を確認し、
  観測 dialog message == nonce のとき **vuln_type=XSS の Finding** を発行する:
  - `additional_info.browser_execution = {dialog_observed:True, variant:"stored", parameter:"<file field>",
    payload:<html>, test_url:<retrieval_url>, nonce, observed_dialog_message, nonce_match:True}`
  - `impact`（アップロード経由の保存型XSS＝任意スクリプト実行の起点）／`reproduction_steps`
    （HTML をアップロード→取得URLをブラウザで開く→alert 発火）を設定。
  - `evidence`（request_url=retrieval_url・response_status=200・response_body に往復生記録）。
  - dialog 非発火／nonce 不一致は Finding を出さない（fail-closed・偽◎なし）。

## 凍結（本タスクで無改変）

- `payout_grade.py` / `sealed_reproduction_checker.py` / `poc_judge.md` / `task_queue.py` /
  `finding_validator.py` はすべて無改変（`git diff --quiet HEAD` exit 0）。既存 xss ブラウザ発火バー＋
  DOM/stored 再現をそのまま再利用する。

## 完了条件（完了契約）

1. エンジンがアップロード経由の保存型XSSを実対象で自力実行し、`browser_execution.dialog_observed=True`＋
   `nonce_match=True`＋`variant=stored`＋`test_url=retrieval_url` を持つ xss Finding を発行する。
2. その Finding に `evaluate_payout_grade` が `payout_grade=True/reflected_payload` を返す（dialog 非観測は False）。
3. **実対象 ◎**: 実 DVWA で エンジン検出→`payout_grade=True`→実 `SealedReproductionChecker` が
   retrieval_url を実ブラウザ再ロードし dialog 再観測→matched→`CONFIRMED`。**実 poc_judge も通す**
   （実害＝スクリプト実行が示されるため承認される見込み・実測で通過率を示す）。
4. 凍結5ファイルは exit 0。製品非依存 token 0（テストは target.example・汎用 XSS ペイロード・良性 HTML）。
5. **非回帰**: 既存 file_upload（0480 の uploaded_file_retrieved）・XSS・injection/validation スイートが緑。

## 必須テスト（新規・製品非依存 fixture のみ）

- payload_manager: get_xss_probe_payload(nonce) が nonce 入り HTML・mime text/html を返す。
- file_upload_tester: stub サーバでアップロード→取得URL確定（マーカー往復）。
- engine: stub（アップロード＋取得＋ブラウザ発火をモック）で xss Finding＋browser_execution（nonce_match）
  ＋impact/repro を発行。dialog 非発火→Finding なし（fail-closed）。
- 統合: validate_finding が xss(browser_execution)＋AI賞金級スタブ＋再現matched で CONFIRMED。
- 変更後 `python3 scripts/sync_shigoku_updated_at.py`→`python3 scripts/validate_shigoku_docs.py` 0 エラー。

## NOT in scope

- サーバ側 RCE（PHP webshell 実行・.htaccess）＝破壊的・別問題。確定バーの敷居低下・curve-fit。
- 凍結5ファイルの改変（不要）。XSS 以外の実害種別。
- 実行痕跡の永続化・データ持出し（alert のみ・非破壊）。

## リスク

- アップロードするファイルは client-side XSS payload（alert のみ・非破壊・我々のラボ）。サーバ側実行は無し。
- 取得URLに実行させられるかは content-type 依存＝**実ブラウザ発火が唯一の判定**。発火しなければ fail-closed
  （偽◎なし）。発見できない実行経路は取り逃す可能性（カバレッジ限界・偽陽性ではない）。

## 実装・検証の分担

- 実装は DeepSeek/opencode に**テキストで**指示（ドキュメント化しない）。fixer→makora 対策として repo
  opencode.json に一時 agent→deepseek 上書きを入れ起動、完了後復元（[[opencode-fixer-subagent-makora-fallback]]）。
- 完了報告は額面通り信用せず、Claude が独立検証（テスト実出力・diff・凍結5無改変・実 DVWA アップロード経由
  保存型XSS の実ブラウザ発火 E2E・fail-closed 否定側・実 poc_judge 通過率）。
