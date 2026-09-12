---
task_id: SGK-2026-0482
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0478_command-injection-inband-confirmation.md
- docs/shigoku/plans/done/2026-09-10_sgk-2026-0479_xss-nonce-roundtrip-evidence.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- ssrf
- confirmation-bar
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0482 計画 — in-band SSRF（内部到達・応答本文反映）を実対象で本物確定（◎）

## 目的（何を・なぜ）

能力マップ [[sgk-2026-0465]] で SSRF は △（OOB 基盤未整備・エンジン未接続・到達性未確証）。本タスクは
**認証付きリクエストの URL 値フィールドをサーバが取得し、その応答本文を in-band で返す**タイプの SSRF を、
実対象で実証し ◎（機械フロア＋実再現＋実 poc_judge の完全3ゲート）へ到達させる。**OOB（外部受信）基盤は
不要**であることを実測で確認済み。非破壊（サーバに読み取りの GET を行わせるのみ・書き込み/破壊なし）。

## 事実（実測・2026-09-13・実対象で確認）

- 実対象（crAPI・`crapi-web` 稼働中）の認証付き POST で、リクエスト body 中の **URL 値フィールド**を
  サーバが取得し、応答 JSON に `response_from_<…>` として**取得した本文をそのまま返す**（in-band 反映）。
- URL を **docker 内部専用ホスト**（外部から直接到達できないサービス）に向けると、その**内部サービスの
  応答が反映される**（例: 内部サービスが「TLS required」を返す＝直接叩けない内部ポートへサーバが到達）。
  → **「クライアントが直接到達できない URL を、サーバが取得して本文を返す」差分**が in-band SSRF の実害証拠。
- 確認手順は非破壊（読み取り GET をサーバに行わせるのみ）。認証は signup→login の JWT。

## 確定バーの現状（凍結・要設計）

- `payout_grade.py` の `ssrf` 分岐（現状）は `ssrf_callback` を **(a) `_SSRF_INDICATORS`（aws/metadata/
  169.254/localhost/127.0.0.1）本文一致・(b) `_SSRF_METADATA_PATTERNS`（クラウドメタデータ）・
  (c) `blind_correlation` の OOB/DNS 確認**で発火する。
- (a) は「ペイロードに 127.0.0.1 等を入れたエコー」で誤発火しうるため in-band 差分の正当な証拠にならない。
  (b)(c) は metadata/OOB 前提。**in-band の「内部到達＋本文反映＋直接到達不可の差分」を表す正当なマーカーが
  無い** → 新マーカーが必要。

## 対象（触るファイル）

### 凍結（★ユーザー明示承認が前提・承認まで着手しない）
- `src/core/agents/swarm/injection/payout_grade.py`: `ssrf` 分岐に **in-band 用の新マーカー**を追加（追加のみ・
  既存 `ssrf_callback` 経路は byte-identical で非回帰）。発火条件（fail-closed・すべて揃ったときだけ）:
  - `info["ssrf_inband_evidence"]` が dict で
    - `fetched_url` 非空（サーバに取得させた URL）
    - `server_reflected_body` 非空（サーバが取得本文を in-band 反映）
    - `client_direct_unreachable` True（**スキャナ自身の直接取得は失敗/到達不可**＝サーバ視点でのみ到達＝差分）
  - 上記が揃えば in-band SSRF マーカーを返す。1つでも欠ければ None（偽◎なし）。
  - マーカー名・`_MARKER_CATEGORIES` への追加方法は実装時に確定（`ssrf` vuln_type が複数マーカーを
    許容できる形にする・既存 `ssrf_callback` は残す）。

### 非凍結
- `src/core/attack/ssrf_tester.py` / `src/core/agents/swarm/injection/smart_ssrf.py`: 現状は GET クエリ
  パラメータ走査。**URL 値フィールドを持つ認証付き POST(JSON) 経路**を追加し、in-band 反映検出＋
  「スキャナ直接取得との差分（client_direct_unreachable）」を算出して `ssrf_inband_evidence` を組む。
  **製品非依存**: エンドポイントパス・フィールド名・内部ホストはハードコードしない（task.params で与える・
  汎用の「URL 値フィールド SSRF」検出として実装）。bare except 禁止。
- `src/core/validation/sealed_reproduction_checker.py`（★凍結・承認が前提）: in-band SSRF 用の再現経路
  （記録済みの非破壊リクエストを再送し、応答本文反映＋差分を再観測→matched）。既存経路は非回帰。

## 凍結（本タスクで無改変）
- `poc_judge.md` / `task_queue.py` / `finding_validator.py` は無改変（`git diff --quiet HEAD` exit 0）。

## 完了条件（完了契約）
1. エンジンが in-band SSRF を実対象で自力検出し、`ssrf_inband_evidence`（fetched_url＋server_reflected_body＋
   client_direct_unreachable）を持つ ssrf Finding を発行する。
2. その Finding に `evaluate_payout_grade` が `payout_grade=True`＋in-band マーカーを返す（証拠欠落は False）。
3. **実対象 ◎**: 実対象で エンジン検出→`payout_grade=True`→実 `SealedReproductionChecker` が非破壊再送で
   反映＋差分を再観測→matched→`CONFIRMED`。**実 poc_judge も通す**（内部到達の実害＝承認見込み・実測で通過率）。
4. 凍結（poc_judge/task_queue/finding_validator）は exit 0。承認済み凍結2ファイル（payout_grade/
   sealed_reproduction）は承認範囲の追加のみ・既存経路非回帰。製品非依存 token 0（テストは target.example・
   汎用 URL 値フィールド・内部ホストは fixture）。
5. **非回帰**: 既存 SSRF（ssrf_callback）・他 injection/validation/logic スイートが緑。

## 必須テスト（新規・製品非依存 fixture のみ）
- payout_grade: `ssrf_inband_evidence` 完備で in-band マーカー発火／1項目欠落で None（fail-closed）／
  既存 ssrf_callback 経路が非回帰。
- ssrf_tester/smart_ssrf: stub サーバで URL 値フィールド POST→in-band 反映検出＋client_direct_unreachable
  差分算出→`ssrf_inband_evidence` 構築。反映なし/直接到達可は Finding なし（fail-closed）。
- sealed_reproduction: stub で非破壊再送→反映＋差分再観測→matched／非反映→not matched。
- 統合: validate_finding が ssrf(ssrf_inband_evidence)＋AI 賞金級スタブ＋再現 matched で CONFIRMED。
- 変更後 `python3 scripts/sync_shigoku_updated_at.py`→`python3 scripts/validate_shigoku_docs.py` 0 エラー。

## NOT in scope
- OOB/DNS blind SSRF の新規基盤構築（別タスク・本タスクは in-band で ◎ 到達）。
- 破壊的操作（書き込み・状態変更・データ持出し）。SSRF 先での POST 等の副作用誘発。
- 既存 ssrf_callback（metadata/OOB）判定の変更・敷居低下（curve-fit 禁止）。

## リスク
- サーバに任意 URL を取得させる＝本タスクでは**読み取りのみ・内部到達の差分実証に限定**（非破壊）。
- in-band 反映が無い/直接到達可能な対象では fail-closed（偽◎なし）。発見できない経路は取り逃す
  （カバレッジ限界・偽陽性ではない）。

## 実装・検証の分担
- 実装は DeepSeek/opencode に**テキストで**指示（小粒な凍結追加は Claude 直接編集も可）。完了報告は額面通り
  信用せず Claude が独立検証（テスト実出力・diff・凍結無改変・実対象 in-band SSRF E2E・fail-closed 否定側・
  実 poc_judge 通過率・非回帰）。
- **凍結2ファイル（payout_grade.py / sealed_reproduction_checker.py）の改変は、着手前にユーザーの明示承認を得る。**
