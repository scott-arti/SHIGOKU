---
task_id: SGK-2026-0483
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0482_inband-ssrf-confirmation.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0481_upload-stored-xss-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- secret-exposure
- confirmation-bar
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0483 計画 — 列挙系シークレット露出（公開URLで資格情報配信）を実対象で本物確定（◎）

## 目的（何を・なぜ）

能力マップ [[sgk-2026-0465]] で「秘密情報の露出」は △（ソースマップ系は対応・**列挙系は偵察併用＝確定経路なし**）。
本タスクは**認証なしの単一 GET で、資格情報を含むファイル（.env 等）が公開配信される**タイプの列挙系
シークレット露出を、実対象で実証し ◎（機械フロア＋実再現＋実 poc_judge の完全3ゲート）へ到達させる。
非破壊（読み取り GET のみ）。**秘密値は一切永続・露出しない**（値は redact・照合はキー側）。

## 事実（実測・2026-09-13・実対象で確認）

- 実対象（crAPI・`crapi-web` 稼働中）で `/.env` が **200・別個の実ファイル**として配信される
  （404=159B、トップ=1207B とは別）。内容は **DB / MongoDB の資格情報**（`DB_PASSWORD`・
  `MONGO_DB_PASSWORD` ほか接続情報一式）。値はマスクして確認。`.git/config`・`config.yml` 等は 404。
- → **公開URLで資格情報（パスワード）が列挙取得できる** ＝ 実害ある列挙系シークレット露出の本物シンク。
  公開前提の API キー等ではなくパスワードなので実 poc_judge の「意味ある実害」も満たせる見込み。

## 確定バーの現状（凍結・要設計）

- `payout_grade.py` の `_MARKER_CATEGORIES` に **`secret_leak`（= `VulnType.SECRET_LEAK.value`）が無い** →
  列挙系 Finding は「未知カテゴリ」で機械フロアを発火できず、CONFIRMED に到達できない。
- `SecretExposure`（manager.py）は Finding を出すが evidence が文字列要約で、生の配信本文・poc 対が無い
  → 実 poc_judge は「独立検証不能の要約」として突き返す（0479/0481/0482 と同型）。

## 対象（触るファイル）

### 凍結（★ユーザー明示承認が前提）
- `src/core/agents/swarm/injection/payout_grade.py`: `secret_leak` 用の**新マーカー `secret_exposed`** を追加
  （追加のみ・既存経路は byte-identical）。発火は fail-closed（すべて揃ったときだけ）:
  - `info["secret_exposure_evidence"]` が dict で
    - `retrieved_url` 非空（in-scope で配信された取得元URL）
    - `response_status == 200`（実際に配信された）
    - `served_body` 非空 かつ **資格情報代入パターン一致**（`_SECRET_EXPOSURE_PATTERNS`。値 redact 済みでも
      キー側 `*PASSWORD=/*SECRET=/*KEY=/*TOKEN=/PRIVATE KEY` で一致）
  - 1つでも欠ければ None（資格情報を含まない公開ファイルは確定に上げない）。
  - `_MARKER_CATEGORIES["secret_leak"]="secret_exposed"` を追加。
- `src/core/validation/sealed_reproduction_checker.py`: `secret_exposed` を `_BODY_OBSERVABLE_MARKERS` に追加＋
  `_detect_marker_in_response` に `secret_exposed` 分岐（取得元URLへの単一 GET 再読で資格情報パターン再観測
  →matched）。**専用メソッド不要**（evidence.request_method=GET・request_url=取得元URL のため汎用 GET 経路で再現）。

### 非凍結
- `src/core/agents/swarm/secret/manager.py`: `SecretExposure` を確定可能化。配信本文に資格情報代入が
  あるときのみ構造化 Evidence（request_method=GET/request_url/status=200/**値 redact 済み本文**）＋
  `secret_exposure_evidence`＋生の `poc_request`/`poc_response`（値 redact 済み）＋impact/repro を持つ Finding を発行。
  **秘密値の扱い**: 資格情報行の値を決定論的に redact（キーは残す）→ pii_masker を多層適用。E2E/test 用に
  `self._client` 注入 seam を追加（smart_* と同型）。bare except 禁止。

## 凍結（本タスクで無改変）
- `poc_judge.md` / `task_queue.py` / `finding_validator.py` は無改変（`git diff --quiet HEAD` exit 0）。

## 完了条件（完了契約）
1. エンジンが列挙系シークレット露出を実対象で自力検出し、`secret_exposure_evidence` を持つ
   `secret_leak` Finding を発行する（資格情報を含まない配信は Finding なし＝fail-closed）。
2. その Finding に `evaluate_payout_grade` が `payout_grade=True`＋`secret_exposed` を返す（証拠欠落は False）。
3. **実対象 ◎**: 実対象で エンジン検出→`payout_grade=True`→実 `SealedReproductionChecker` が取得元URLへ
   非破壊 GET 再読→資格情報パターン再観測→matched→`CONFIRMED`。**実 poc_judge も通す**。
4. 凍結3は exit 0。承認済み凍結2は承認範囲の追加のみ・既存経路非回帰。製品非依存 token 0
   （テストは target.example・合成値・値 redact の確認）。**秘密値は evidence/report/log に残らない**。
5. **非回帰**: 既存 injection/validation/secret スイートが緑。

## 必須テスト（新規・製品非依存 fixture のみ）
- payout_grade: `secret_exposure_evidence` 完備で `secret_exposed` 発火／資格情報非一致・空URL・非200・
  本文欠落・dict 欠落で None（fail-closed）／PEM 秘密鍵で発火／既存 ssrf_callback 非回帰。
- manager: 資格情報配信で確定 Finding 発行／非資格情報で None／**値が evidence に残らない（redact）**／
  キーは残る／PEM キー名抽出。
- sealed_reproduction: 取得元URL 再読で資格情報再出現→matched／非出現→mismatched／client None・スコープ外→not_run。
- 統合: validate_finding が secret_leak(secret_exposure_evidence)＋AI 賞金級スタブ＋再現 matched で CONFIRMED。
- 変更後 `python3 scripts/sync_shigoku_updated_at.py`→`python3 scripts/validate_shigoku_docs.py` 0 エラー。

## NOT in scope
- ソースマップ系（既存対応）・クラウドバケット列挙の追加強化。
- .git ダンプの完全復元確定（別経路・本タスクは配信ファイル型の資格情報露出で ◎ 到達）。
- 破壊的操作・漏洩した資格情報を使った実ログイン/横展開（非破壊の露出実証に限定）。
- 既存 SecretFinder 走査（列挙補助）の判定変更・敷居低下（curve-fit 禁止）。

## リスク
- 実対象の生配信本文には実資格情報が含まれる → **値はコード側で redact してから evidence 化**・出力/永続しない
  （lessons.md の mask-and-restore／最下層 redaction を遵守）。再現チェッカーのライブ再取得本文は照合のみで非永続。
- 資格情報を含まない公開ファイルは fail-closed（偽◎なし）。取り逃しはカバレッジ限界であり偽陽性ではない。

## 実装・検証の分担
- 小粒な凍結追加は Claude 直接編集（ユーザー明示承認済み）。完了報告は額面通り信用せず Claude が独立検証
  （テスト実出力・diff・凍結無改変・実対象 E2E・fail-closed 否定側・実 poc_judge 通過率・非回帰・秘密値非残存）。
- **凍結2ファイル（payout_grade.py / sealed_reproduction_checker.py）の改変は、着手前にユーザーの明示承認を得る。**
