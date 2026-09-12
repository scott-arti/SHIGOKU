---
task_id: SGK-2026-0483
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0483_enumerated-secret-exposure-confirmation.md
- docs/shigoku/reports/2026-09-13_sgk-2026-0483_enumerated-secret-exposure-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- secret-exposure
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0483 作業ログ（列挙系シークレット露出・実crAPI・◎）

## 1. 偵察（事実優先・実測）
- 実 crAPI を GET-only 偵察。`/.env` が 200・別個の実ファイル（201B。404=159B/トップ=1207B と別）。
  内容は DB/MongoDB 資格情報（`DB_PASSWORD`・`MONGO_DB_PASSWORD` ほか）。値はマスクして確認。
  `.git/config`・`config.yml` 等は 404。→ 公開URLで資格情報を列挙取得できる本物シンクと確定。

## 2. 確定バーの欠落点（事実）
- `_MARKER_CATEGORIES` に `secret_leak` なし → 列挙系 Finding は未知カテゴリで機械フロア非発火＝CONFIRMED 不可。
- `SecretExposure` は evidence が文字列要約・生 poc 対なし → 実 poc_judge は要約扱いで突き返す。

## 3. 台帳・計画・承認
- SGK-2026-0483 採番。凍結2（payout_grade/sealed_reproduction）改変はユーザー明示承認（「進めて」）。

## 4. 実装（Claude 直接・小粒surgical）
- payout_grade: `_SECRET_EXPOSURE_PATTERNS`（資格情報キー側＋PEM）＋`_MARKER_CATEGORIES["secret_leak"]=
  "secret_exposed"`＋`_match_firing_marker` の secret_leak 分岐（retrieved_url＋status200＋served_body の
  パターン一致で発火・fail-closed）。
- sealed_reproduction: パターン import＋`_BODY_OBSERVABLE_MARKERS` に secret_exposed＋`_detect_marker_in_response`
  の secret_exposed 分岐（汎用 GET 再現経路で取得元URL 再読→パターン再観測）。
- manager: `SecretExposure` 確定可能化（値 redact 済み構造化 Evidence＋secret_exposure_evidence＋生 poc 対＋
  impact/repro）。`_matched_credential_keys`/`_redact_secret_values` ヘルパー。`self._client` 注入 seam。
  既存 SecretFinder 走査は `_secretfinder_scan` に分離（補助・非確定）。

## 5. 独立検証（Claude・実出力）
- 実 crAPI E2E: 実 execute→`/.env` 200・資格情報代入→payout_grade=True/secret_exposed→実再現 matched
  →CONFIRMED。served_body は値 redact 済み（`DB_PASSWORD=<redacted len=5>`）。
- 実 poc_judge: **4/4 承認**（is_real/impact True・counter False。1 回は「値はマスク」と明記した上で real 判定）
  ＝秘密値非露出で完全3ゲート達成。
- 新規18テスト緑。非回帰: 失敗3件は HEAD でも失敗する既存（phase_b_readiness×2・t3_hybrid_wiring budget・
  stash で確認）＝0483 起因の回帰ゼロ。凍結3 exit 0。製品 token0。
- 秘密値監査: Finding evidence/poc に値なし（合成値でアサート）・再取得本文は照合のみ非永続。

## 6. 完了
- 完了条件1〜5 充足（条件3 実 poc_judge 4/4）。in_scope_blocker 0 → done。
- 能力マップ: 秘密情報の露出を ◎（列挙系・公開URL資格情報配信を完全3ゲート。ソースマップ系は既存対応・
  .git 完全ダンプ確定は別経路）。
- 教訓: 秘密露出は「生の配信本文＋生 poc 対＋意味ある実害（資格情報）」で実 poc_judge を通すが、**秘密値を
  出さずとも**キー側パターン＋値 redact で実害判定に十分（審査も「マスク」を認めた）。バー非低下・証拠の実体と
  見せ方の強化。[[no-capability-minimization]]・[[poc-judge-raw-evidence]]。
- 観測(別件): task_registry の 0465 以降が tasks: 外に連なる構造ずれ（運用影響なし・§12 で別途判断）。
