---
task_id: SGK-2026-0480
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/reports/2026-09-10_sgk-2026-0480_file-upload-retrieval-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-10_sgk-2026-0480_file-upload-retrieval-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0478_command-injection-inband-confirmation.md
- docs/shigoku/plans/done/2026-09-10_sgk-2026-0479_xss-nonce-roundtrip-evidence.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- file-upload
- confirmation-bar
created_at: '2026-09-10'
updated_at: '2026-09-10'
---

# SGK-2026-0480 計画 — ファイルアップロード（任意ファイル設置＋Web取得）を実DVWAで本物確定（◎）

## 目的（何を・なぜ）

検出能力マップ [[sgk-2026-0465]] でファイルアップロードは「△（検出枠あり）」。実対象 DVWA で
**任意ファイルのアップロードと Web からの取得（unrestricted file upload with retrieval）**を
本物確定（◎）へ引き上げる。非破壊（良性・非実行ファイルのみ・PHP/.htaccess/RCE 検証はしない）。

## 事実（実測・実コードで確定・2026-09-10・書き込みはユーザー承認済み）

- 実 DVWA `/vulnerabilities/upload/`（multipart・field `uploaded`＋`MAX_FILE_SIZE`＋`Upload`）に
  良性マーカー入りテキストをアップロード→応答が `../../hackable/uploads/<name>`＋success を返却→
  `GET /hackable/uploads/<name>` で**アップロードした一意マーカーが本文に出現**（実測）。
  `/hackable/uploads/` は静的配信（既定画像も 200）。→ 取得経路は生きている。
- エンジン `FileUploadSpecialist`（`logic/file_upload.py`）＋`FileUploadTester`
  （`attack/file_upload_tester.py`）は既にアップロード＋取得確認を行い、`_verify_retrieval` が
  `marker(=payload.content) in body` で `retrieved=True`/`retrieval_url`/`retrieval_status` を設定。
  Finding は `additional_info.file_upload_evidence`（upload_allowed/retrieved/retrieval_url/…）を持つ。
- **壁（実測で確定）**: (1) 確定バー `payout_grade._MARKER_CATEGORIES` に `file_upload` が無い
  → `unknown_category` で `payout_grade=False`。(2) 取得の**一意マーカー**が Finding に記録されず、
  `impact`/`reproduction_steps` も未設定。(3) 再現チェッカーに file_upload 経路が無い。
- 安全性: `safe_only=True` で `PayloadManager.get_probe_payload()` の**良性・非実行**ファイル
  （現状 content は固定 `SHIGOKU_PROBE_IMAGE_DATA`）を使う経路が既にある。PHP/.htaccess は使わない。

## 対象（このタスクで触るファイル）

- **A（凍結・ユーザー明示承認済み・2026-09-10）** `src/core/agents/swarm/injection/payout_grade.py`
  - `_MARKER_CATEGORIES` に `"file_upload": "uploaded_file_retrieved"` を追加し、`_match_firing_marker`
    に file_upload 分岐を追加。**`file_upload_evidence.upload_allowed` 真＋`retrieved` 真＋
    `retrieval_marker` 非空＋`retrieval_url` 非空**のとき `uploaded_file_retrieved` を返す。
    いずれか欠落は None（fail-closed）。既存マーカーの判定は byte-identical。
- **A（凍結・ユーザー明示承認済み・2026-09-10）** `src/core/validation/sealed_reproduction_checker.py`
  - `uploaded_file_retrieved` を本文観測マーカーとして扱い、`check()` に専用分岐
    `_check_file_upload_retrieval(payload, info)` を追加（cors/jwt/dom と同じ位置）。
    **GET のみ**で `file_upload_evidence.retrieval_url` を読み直し、`retrieval_marker` が本文に
    再出現→matched／応答あり・非出現→mismatched／client None・例外→not_run（fail-closed）。
    **GET-only ガードの緩和は不要**（純 GET 再読）。他マーカー・`_send_get` は byte-identical。
- **B（非凍結）** `src/core/agents/swarm/logic/file_upload.py` / `attack/file_upload_tester.py` /
  `attack/payload_manager.py`
  - `get_probe_payload` の content に**実行毎の一意マーカー**（`SHIGOKU_PROBE_` + 乱数）を埋め込む
    （良性・非実行のまま）。`_verify_retrieval` が使った marker を `UploadResult.retrieval_marker`
    （＋delivery_telemetry）に記録。engine は retrieved＋marker 一致時に `impact`／
    `reproduction_steps`／`file_upload_evidence.retrieval_marker` を設定し、`evidence.response_body`
    に取得本文抜粋（マーカー含む）を入れる。retrieved でない/マーカー無しは従来どおり（付けない）。

## 確定バー（凍結のうち本タスクで無改変）

- `poc_judge.md` / `task_queue.py` / `finding_validator.py` は無改変（`git diff --quiet HEAD` exit 0）。

## 完了条件（完了契約）

1. A: file_upload finding（upload_allowed＋retrieved＋retrieval_marker＋retrieval_url＋impact＋repro）に
   `evaluate_payout_grade` が `payout_grade=True/marker=uploaded_file_retrieved`。retrieved 偽/marker 無しは
   `payout_grade=False`（fail-closed）。他 vuln_type の判定は非回帰。
2. A: `sealed_reproduction._check_file_upload_retrieval` が (a) retrieval_url GET でマーカー再出現→matched、
   (b) 非出現→mismatched、(c) client None→not_run、(d) descriptor 無し→not_run。GET-only・他マーカー非回帰。
3. `validate_finding` が file_upload 本物証拠＋AI賞金級＋再現matched で CONFIRMED。
4. 凍結: 改変は `payout_grade.py`＋`sealed_reproduction_checker.py` のみ。`poc_judge.md`/`task_queue.py`/
   `finding_validator.py` は exit 0。製品非依存 token 0（テストは target.example・良性マーカーのみ）。
5. **実対象 ◎ 実証**: 認可対象 **DVWA** `/vulnerabilities/upload/`（safe_only・良性非実行ファイル）に
   一意マーカーをアップロード→取得 URL GET でマーカー→`payout_grade=True`→再現 GET 再読 matched→
   `CONFIRMED`（可能なら実 poc_judge も通す）。取得不可・マーカー不一致は非確定。
6. **非回帰**: 既存 injection/validation スイート緑。他マーカー（sql/xss/lfi/cmd/cors/jwt/redirect/authz）不変。

## 必須テスト（新規・製品非依存 fixture のみ）

- payout_grade 単体: (a) file_upload_evidence 完備→True/uploaded_file_retrieved、(b) retrieved 偽→False、
  (c) retrieval_marker 空→False、(d) 他 vuln_type 非回帰。
- sealed_reproduction 単体: (a) retrieval_url GET でマーカー再出現→matched、(b) 非出現→mismatched、
  (c) client None→not_run、(d) descriptor/marker 欠落→not_run、(e) 他マーカー・GET-only 非回帰。
- engine 単体: stub サーバでアップロード→retrieved＋一意マーカー→impact/repro/retrieval_marker 設定。
- 統合: `validate_finding` が CONFIRMED。
- 変更後 `python3 scripts/sync_shigoku_updated_at.py`→`python3 scripts/validate_shigoku_docs.py` 0 エラー。

## NOT in scope

- PHP/webshell/.htaccess による RCE 実証（破壊的・非対象）。確定バーの敷居低下・curve-fitting。
- `poc_judge.md`/`task_queue.py`/`finding_validator.py` の改変。file_upload 以外の種別。
- 実行(execution_observed)を伴う確定（本タスクは「設置＋取得」まで。RCE は将来別タスク）。

## リスク

- 凍結2ファイルへのマーカー追加＝能力追加（敷居低下でない）。fail-closed テスト（retrieved 偽/marker 無し
  →False、非出現→mismatched）で担保。
- アップロードは書き込み（良性・非実行・我々のラボ DVWA・ユーザー承認済み）。再現は GET のみ（非破壊）。
- 一意マーカーの往復（アップロード内容の乱数が取得本文に一致）で「本当に自分が置いたファイルが取得できた」
  ことを独立検証可能にする（0479 の nonce 教訓と同型）。

## 実装・検証の分担

- 実装は DeepSeek/opencode に**テキストで**指示（ドキュメント化しない）。fixer→makora 対策として
  repo opencode.json に一時 agent→deepseek 上書きを入れ起動、完了後復元（[[opencode-fixer-subagent-makora-fallback]]）。
- 完了報告は額面通り信用せず、Claude が独立検証（テスト実出力・diff・凍結3無改変・実 DVWA アップロード/取得
  E2E・fail-closed 否定側・実 poc_judge）。
