---
task_id: SGK-2026-0483
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0483_enumerated-secret-exposure-confirmation.md
- docs/shigoku/worklogs/2026-09-13_sgk-2026-0483_enumerated-secret-exposure-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0482_inband-ssrf-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- secret-exposure
- confirmation-bar
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0483 作業完了報告 — 列挙系シークレット露出（公開URLで資格情報配信）を実対象で本物確定（◎）

## 何をしたか / なぜ

能力マップ [[sgk-2026-0465]] で「秘密情報の露出」は △（ソースマップ系のみ・列挙系は確定経路なし）。偵察で
**実 crAPI の `/.env` が認証なしの単一 GET で DB/MongoDB の資格情報を 200 配信する**ことを実測確認。本タスクは
この列挙系シークレット露出を実対象で機械フロア＋実再現＋実 poc_judge の完全3ゲートで ◎ に到達させた。
非破壊（読み取り GET のみ）。**秘密値は一切永続・露出していない**（値は redact・照合はキー側パターン）。

## 実装（承認済み凍結2＋非凍結1・ユーザー明示承認済み）

- **payout_grade.py（凍結・承認）**: `secret_leak` 用の新マーカー `secret_exposed` を追加。
  `additional_info.secret_exposure_evidence` の①`retrieved_url` 非空 ②`response_status==200`
  ③`served_body` に資格情報代入パターン一致（新定数 `_SECRET_EXPOSURE_PATTERNS`＝`*PASSWORD/*SECRET/
  *API_KEY/*ACCESS_KEY/*PRIVATE_KEY/*TOKEN/*CREDENTIAL` のキー側＋PEM 秘密鍵ヘッダ。**値 redact 済みでも
  キー側で一致**）が**全て揃ったときだけ**発火（1つでも欠ければ None＝fail-closed）。
  `_MARKER_CATEGORIES["secret_leak"]="secret_exposed"` を追加。既存マーカー経路は byte-identical で非回帰。
- **sealed_reproduction_checker.py（凍結・承認）**: `_SECRET_EXPOSURE_PATTERNS` を import、`secret_exposed` を
  `_BODY_OBSERVABLE_MARKERS` に追加、`_detect_marker_in_response` に `secret_exposed` 分岐を追加。
  evidence.request_method=GET・request_url=取得元URL のため**専用メソッド不要**で汎用 GET 再現経路に乗る
  （取得元URLへ封印スコープ内で単一 GET 再読→資格情報パターン再観測で matched）。ライブ再取得本文は照合
  するだけで永続しない。
- **manager.py（非凍結）**: `SecretExposure` を確定可能化。配信本文に資格情報代入があるときだけ構造化
  Evidence（request_method=GET/request_url/status=200/**値 redact 済み本文**）＋`secret_exposure_evidence`
  （retrieved_url/response_status/served_body/matched_keys/content_type）＋生の `poc_request`/`poc_response`
  （値 redact 済み）＋impact/repro を持つ Finding を発行。資格情報行の値を決定論的に redact（キーは残す）
  → pii_masker を多層適用。E2E/test seam として `self._client` 注入を追加（smart_* と同型）。既存 SecretFinder
  走査は補助（列挙・非確定）として温存。bare except なし（境界のみ noqa 付き）。

## 結果（独立検証・Claude が実測）

- **実 crAPI** で実 `SecretExposure.execute` が自力で `/.env` の列挙系シークレット露出を検出→200・本文に
  `DB_PASSWORD`/`MONGO_DB_PASSWORD` 等の資格情報代入→`payout_grade=True/secret_exposed`→**実
  `SealedReproductionChecker` が取得元URLへ封印スコープ内で非破壊 GET 再読し資格情報パターンを再観測→matched
  →CONFIRMED**。served_body はパスワード値を redact 済み（`DB_PASSWORD=<redacted len=5>`）。
- **本物の poc_judge（実LLM）で 4/4 承認（is_real=True・has_actual_impact=True・counter_evidence=False）**。
  審査理由は「認証なし単一 GET に 200・本文に DB_PASSWORD/MONGO_DB_PASSWORD 等の資格情報代入が実測・
  poc_request/poc_response 対応が具体的・未認可リソースの資格情報漏洩」。**1 回は「値はマスク」と明記した上で
  real 判定**＝秘密値を出さずに実害を評価。**完全3ゲート達成＝◎**。
- テスト: 新規18テスト緑（payout_grade 発火/fail-closed5種/PEM/既存 ssrf_callback 非回帰・manager 確定発行/
  非資格情報 None/**値非残存**/キー残存/PEM キー抽出・sealed_reproduction matched/mismatched/not_run/スコープ外）。
  非回帰: `validation/` `injection/` `secret/` の失敗3件は本変更前（HEAD）でも失敗する既存
  （phase_b_readiness×2＝環境依存・t3_hybrid_wiring budget・stash で HEAD 比較確認）＝**0483 起因の回帰ゼロ**。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）は各 `git diff --quiet HEAD` exit 0。
  承認済み凍結2は承認範囲の追加のみ。製品非依存 token 0（追加コード・新規テストに juice/dvwa/crapi/mechanic/
  mailhog 等なし。製品固有値は scratchpad E2E のみ）。

## 秘密情報の扱い（監査）

- 偵察時の `/.env` 値はマスクして確認（変数名のみ表示）。Finding の evidence/poc は**資格情報の値を redact**
  （`<redacted len=N>`）してから格納し、キー（変数名）のみ残す＝実害の証拠を保ちつつ秘密値を露出しない。
- 再現チェッカーのライブ再取得本文は照合のみで非永続。テストは合成の偽値を用い、evidence に残らないことを
  明示的にアサート（`test_no_secret_value_persisted_in_finding`）。lessons.md（mask-and-restore／最下層 redaction）準拠。

## 確度の結論（正直な格付け）

- **列挙系シークレット露出（公開URLで資格情報配信）＝実害あり**で、実 poc_judge も通り **◎（完全3ゲート）**。
  バーを下げて通す curve-fit はしていない（新マーカーは fail-closed の追加・証拠は生の poc 対と配信事実・
  意味ある実害＝資格情報）。ソースマップ系は既存対応、.git 完全ダンプ確定は別経路（本タスクは配信ファイル型で ◎）。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の「実 poc_judge も通す」を 4/4 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15（ドキュメント単一正本・台帳ワークフロー）・§17（動的ルールロード）・§19（完了契約の固定・
カーブフィット禁止）、`rules/lessons.md`（mask-and-restore／最下層 redaction／封印実行は実対象到達を証明）、
`rules/codingrules.md`（bare except 禁止・秘密を出さない）、メモリ [[no-capability-minimization]]・
[[poc-judge-raw-evidence]]。

## 非阻害の観測（deferred / 別件）

- 台帳 `task_registry.yaml` の構造ずれ: SGK-2026-0465 以降のエントリが `tasks:` リストではなく
  `status_allowed_values:` 以降に連なる位置にある（validator は配置に関わらず全ブロックを読むため 0 エラー・
  運用影響なし）。本タスクも既存慣習どおり同位置に登録。構造修正は §12 に基づき別途ユーザー判断で実施する
  `non_blocking_observation`。
