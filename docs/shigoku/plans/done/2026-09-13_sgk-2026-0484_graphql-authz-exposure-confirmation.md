---
task_id: SGK-2026-0484
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-13_sgk-2026-0484_graphql-authz-exposure-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-13_sgk-2026-0484_graphql-authz-exposure-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0483_enumerated-secret-exposure-confirmation.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0482_inband-ssrf-confirmation.md
tags:
- shigoku
- detection
- graphql
- broken-access-control
- confirmation-bar
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0484 計画 — GraphQL 認可欠陥（認証なしで機微データ取得）を実対象で本物確定（◎）

## 背景・事実（偵察で実測）

能力マップ [[sgk-2026-0465]] の残る △ は「SSTI / CRLF / GraphQL」の1行のみ。GET のみで
実測した結果、現行3ラボ（DVWA / Juice Shop / crAPI）には GraphQL の実シンクが無い
（crAPI は `/graphql` 系すべて 404、Juice Shop の `/graphql` は Angular の catch-all HTML で
本物のエンドポイントではない）。

そこで DVWA/Juice Shop/crAPI と同じ posture で、本物の脆弱 GraphQL アプリ
**DVGA（Damn Vulnerable GraphQL Application, `dolevf/dvga`）** を制御対象として1つ立てた
（`127.0.0.1:5013` に閉じる）。実測で以下2つの本物脆弱性を確認（いずれも**認証なし**）：

- **A. 資格情報の越境取得**: `{users{id username password}}` が admin / operator の
  ユーザー名＋パスワードを 200 で返す（値はマスク確認）。GraphQL 経由の認可欠陥＋機微データ露出。
- **B. 非公開ペースト過剰取得**: `pastes(public:false)` が非公開ペースト（`public=False`・
  `ipAddr`・`ownerId`・内容）を返す。

さらに「スキーマから機微スカラーフィールドを持つ root Query フィールドを汎用に特定→認証なしで
実クエリ→実データ取得」がラボ固有ハードコードなしで成立することを scratchpad で実証済み
（`Query.users -> UserObject.password` を発見し `{users{id username password}}` を自動生成→200＋実資格情報）。

## 確定バーの欠落点（事実）

- 既存エンジン `SmartGraphQLHunter`（`injection/smart_graphql.py`）は
  **イントロスペクション/GraphiQL/フィールド示唆の情報開示のみ**検出し、
  vuln_type=`GRAPHQL_INTROSPECTION`・evidence 本文はプレースホルダ。
  **実害クエリ（機微フィールドを認証なしで実行して値を取得）は未実行**。
- `_MARKER_CATEGORIES` の `broken_access_control` / `idor` は `authz_diff`＝
  **2アカウント差分専用**の発火で、「認証なしで機微データが返る」露出型には合わない。

## 対象（この計画の完了契約）

DVGA の GraphQL 認可欠陥（認証なしで機微データ＝資格情報を取得）を実対象で
**機械フロア＋実再現＋実 poc_judge の完全3ゲート**で ◎ に到達させる。
非破壊（読み取りクエリのみ・mutation 非実行）。**秘密値は evidence/report/log に一切残さない**
（値 redact・照合はキー側フィールド名）。

## 実装方針（最小差分）

1. **エンジン `injection/smart_graphql.py`（非凍結）**: イントロスペクション成功時に、
   スキーマから「機微スカラーフィールドを持つ型を返す root Query フィールド」を汎用特定し、
   最小クエリ（`{ <rootField> { <sensitiveScalars…> } }`）を**認証なしで実行**。
   200＋応答 JSON に非空の機微値が含まれれば**第2の Finding** を発行：
   - vuln_type=`GRAPHQL_AUTHZ_EXPOSURE`（新）、severity=CRITICAL
   - Evidence: request_method=POST / request_url=endpoint / request_body=生クエリ JSON /
     response_status=200 / **response_body=値 redact 済み JSON**（機微値のみ `<redacted len=N>`、
     フィールドキー・構造は保持）
   - additional_info: `graphql_exposure_evidence`{endpoint, query, response_status,
     matched_fields, served_body(redacted)} ＋ `graphql_bola_replay`{endpoint, json_body,
     reflect_fields}（再現用・`ssrf_inband_replay` 同型）＋ 生 `poc_request`/`poc_response`（redact）
   - フィールド名/エンドポイントは**スキーマ駆動でハードコードしない**（製品非依存 token 0）。
   - 既存のイントロスペクション情報開示 Finding（`GRAPHQL_INTROSPECTION`）は非回帰で温存。

2. **`models/finding.py`（非凍結）**: `VulnType.GRAPHQL_AUTHZ_EXPOSURE = "graphql_authz_exposure"` を追加。

3. **確定バー `injection/payout_grade.py`（凍結・ユーザー承認済「進めて」）**:
   - `_MARKER_CATEGORIES["graphql_authz_exposure"] = "graphql_sensitive_exposed"`
   - `_match_firing_marker` に `graphql_authz_exposure` 分岐を追加。`graphql_exposure_evidence` の
     ①endpoint 非空 ②response_status==200 ③served_body 非空 ④matched_fields 非空 ⑤query 非空
     が**全て揃い**、かつ served_body に matched_fields のいずれかのキーが実在するときだけ
     `graphql_sensitive_exposed` を発火（1つでも欠ければ None＝fail-closed）。既存経路は byte-identical。

4. **再現チェッカー `validation/sealed_reproduction_checker.py`（凍結・承認済）**:
   `ssrf_inband` と同型の専用パスを追加。`graphql_bola_replay` 記述子に従い、
   封印スコープ内で**トリガ GraphQL クエリを 1 回だけ再 POST**→応答 JSON に
   期待する機微フィールドキーが再出現すれば matched（`reproduction_marker_matched:graphql_sensitive_exposed`）。
   ライブ再取得本文は照合のみで非永続。out-of-scope / client 未注入は not_run（fail-closed）。

5. **秘密情報の扱い**: 応答 JSON の機微値（password/secret/token/key/credential 系キーの値）を
   決定論的に redact（キー・構造は保持）→ pii_masker を多層適用。テストは合成の偽値を使い、
   evidence/poc に値が残らないことを明示アサート。lessons.md（mask-and-restore／最下層 redaction）準拠。

## 完了条件

1. 実 DVGA で実 `SmartGraphQLHunter.execute` が自力で GraphQL 認可欠陥を検出→200＋機微値→
   `payout_grade=True/graphql_sensitive_exposed`。
2. 実 `SealedReproductionChecker` がトリガクエリを封印スコープ内で 1 回再送し機微フィールドを再観測→matched→CONFIRMED。
3. **本物の poc_judge（実 LLM）で承認**（is_real / has_actual_impact True・counter False。秘密値 redact 済み）。
4. 製品非依存 fixture の新規テストが緑（発火／fail-closed 各否定側／再現 matched・mismatched・not_run・スコープ外／秘密値非残存）。
5. 凍結3（poc_judge.md / task_queue.py / finding_validator.py）は `git diff --quiet HEAD` exit 0。
   承認済凍結2（payout_grade / sealed_reproduction）は承認範囲の追加のみ。製品トークン 0・回帰ゼロ。

## NOT in scope

- SSTI / CRLF の確定（別タスク）。
- GraphQL の他ベクトル（バッチング DoS・mutation 悪用・インジェクション）は本タスク対象外
  （情報開示のイントロスペクションは既存 ○ 相当で温存、本タスクは認可欠陥の実害 ◎ に限定）。
- 実バグバウンティ対象への適用。

## 参考にしたルール

CLAUDE.md §14/§15（単一正本・台帳ワークフロー）・§17（動的ルールロード）・§19（完了契約の固定・
カーブフィット禁止）、`rules/lessons.md`（mask-and-restore／最下層 redaction／封印実行は実対象到達を証明）、
`rules/codingrules.md`（bare except 禁止・秘密を出さない）、メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]。
