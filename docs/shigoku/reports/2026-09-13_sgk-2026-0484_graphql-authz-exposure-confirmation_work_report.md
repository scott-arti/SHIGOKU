---
task_id: SGK-2026-0484
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0484_graphql-authz-exposure-confirmation.md
- docs/shigoku/worklogs/2026-09-13_sgk-2026-0484_graphql-authz-exposure-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0483_enumerated-secret-exposure-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- graphql
- broken-access-control
- confirmation-bar
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0484 作業完了報告 — GraphQL 認可欠陥（認証なしで機微データ取得）を実対象で本物確定（◎）

## 何をしたか / なぜ

能力マップ [[sgk-2026-0465]] の残る △ は「SSTI / CRLF / GraphQL」の1行のみ。GET のみの実測で
現行3ラボ（DVWA / Juice Shop / crAPI）に GraphQL の実シンクが無いことを確認したため、
DVWA/Juice Shop/crAPI と同じ posture で本物の脆弱 GraphQL アプリ **DVGA（`dolevf/dvga`）** を
制御対象として1つ立てた（`127.0.0.1:5013` に閉じる）。実測で認証なしの GraphQL クエリが
DB 資格情報（`{users{username password}}`）や非公開データ（`pastes(public:false)`）を 200 で返す
本物の認可欠陥を確認。本タスクはこの **GraphQL 認可欠陥（認証なしで機微データ取得）** を
実対象で機械フロア＋実再現＋実 poc_judge の完全3ゲートで ◎ に到達させた。
非破壊（読み取りクエリのみ・mutation 非実行）。**秘密値は一切永続・露出していない**
（値 redact・照合はキー側フィールド名）。

## 実装（承認済み凍結2＋非凍結2・ユーザー明示承認済「進めて」）

- **smart_graphql.py（非凍結・エンジン）**: 既存 `SmartGraphQLHunter` はイントロスペクション
  情報開示のみ検出で実害クエリ未実行だった。**スキーマ駆動で「機微スカラーフィールドを持つ型を
  返す root Query フィールド」を汎用特定**（`_craft_sensitive_query`。引数必須の root は回避）し、
  **認証なしで実クエリを実行**（`_gql_post`。`self._client` 注入 seam・auth ヘッダ非送出）、
  200＋応答 JSON に非空の機微値が含まれれば第2の Finding を発行（`_build_exposure_finding`）。
  vuln_type=`GRAPHQL_AUTHZ_EXPOSURE`・severity=CRITICAL。Evidence は POST/endpoint/200/
  **値 redact 済み JSON**、additional_info に `graphql_exposure_evidence`（endpoint/query/
  response_status/matched_fields/served_body）＋`graphql_bola_replay`（再現記述子・`ssrf_inband_replay`
  同型）＋生 `poc_request`/`poc_response`（redact）。フィールド名/エンドポイントはハードコードせず
  スキーマ駆動（製品非依存 token 0）。既存イントロスペクション情報開示 Finding は非回帰で温存。
- **finding.py（非凍結）**: `VulnType.GRAPHQL_AUTHZ_EXPOSURE = "graphql_authz_exposure"` を追加
  （情報開示専用の `GRAPHQL_INTROSPECTION` と分離＝実害を別 vuln_type で確定バーに載せる）。
- **payout_grade.py（凍結・承認）**: `broken_access_control`/`idor` の `authz_diff` は2アカウント
  差分専用で「認証なしで機微データが返る」露出型に合わないため、**新 vuln_type 用の新マーカー
  `graphql_sensitive_exposed`** を追加。`_MARKER_CATEGORIES["graphql_authz_exposure"]=
  "graphql_sensitive_exposed"`＋`_match_firing_marker` の分岐（①endpoint 非空 ②response_status==200
  ③served_body 非空 ④matched_fields 非空 ⑤query 非空、かつ served_body に matched_fields の
  いずれかのキーが実在、が**全て揃ったときだけ**発火。1つでも欠ければ None＝fail-closed）。
  既存マーカー経路は byte-identical で非回帰。
- **sealed_reproduction_checker.py（凍結・承認）**: `ssrf_inband` と同型の専用パス
  `_check_graphql_exposure_replay` を追加。`graphql_bola_replay` 記述子に従い封印スコープ内で
  **トリガ GraphQL クエリ(JSON POST)を 1 回だけ再送**→応答 JSON に期待する機微フィールドキーが
  再出現すれば matched（構造照合＋文字列包含フォールバック）。ライブ再取得本文は照合のみで非永続。
  client None / スコープ外 / fingerprint 不一致 / 記述子不正 は not_run（fail-closed）。

## 結果（独立検証・Claude が実測）

- **実 DVGA** で実 `SmartGraphQLHunter.execute` が自力でスキーマ駆動クラフト
  `{users{id username password}}` を認証なし実行→200・本文に `password` 等の機微値→
  `payout_grade=True/graphql_sensitive_exposed`→**実 `SealedReproductionChecker` がトリガクエリを
  封印スコープ内で再 POST し `password` フィールドを再観測→matched→CONFIRMED**。
  served_body はパスワード値を redact 済み（`password: <redacted len=6>`）。
- **本物の poc_judge（実 LLM）で 4/4 承認**（is_real=True・has_actual_impact=True・
  counter_evidence=False）。審査理由は「認証ヘッダを一切付与していない POST /graphql に HTTP 200・
  data.users に username と本来保護されるべき password フィールドが実測・poc_request/poc_response
  一致・無認証での資格情報相当データ取得＝境界越えアクセス」。**値 redact 済み**（1 回は
  「len=6 の秘匿値」と明記した上で real 判定）＝秘密値を出さずに実害評価。**完全3ゲート達成＝◎**。
- テスト: 新規21テスト緑（payout_grade 発火/fail-closed7種/legacy secret_leak 非回帰・
  engine 確定発行/非機微 None/データ空 None/非200 None/**値非残存**/キー残存・
  sealed_reproduction matched/mismatched/not_run×3/スコープ外）。
  非回帰: `validation/` `injection/` の失敗3件は本変更前（HEAD）でも失敗する既存
  （phase_b_readiness×2＝環境依存・t3_hybrid_wiring budget・stash で HEAD 比較確認）＝
  **0484 起因の回帰ゼロ**（1094 passed）。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）は各 `git diff --quiet HEAD` exit 0。
  承認済凍結2は承認範囲の追加のみ。製品非依存 token 0（追加コード・新規テストは target.example/
  evil.example のみ。DVGA/127.0.0.1/5013 は scratchpad E2E のみ）。trailing whitespace 0。

## 秘密情報の扱い（監査）

- 偵察時の資格情報値はマスクして確認（変数名/フィールド名のみ表示）。Finding の evidence/poc は
  応答 JSON の機微値（password/secret/token/key/credential 系キーの値）を**決定論的に redact**
  （`<redacted len=N>`）してから格納し、キー（フィールド名）・構造のみ残す＝実害の証拠を保ちつつ
  秘密値を露出しない。再現チェッカーのライブ再取得本文は照合のみで非永続。テストは合成の偽値
  （`PLAINTEXT_FAKE_PW_9f3`）を用い evidence/poc に残らないことを明示アサート。
  lessons.md（mask-and-restore／最下層 redaction）準拠。

## 確度の結論（正直な格付け）

- **GraphQL 認可欠陥（認証なしで機微データ＝資格情報を取得）＝実害あり**で、実 poc_judge も通り
  **◎（完全3ゲート）**。バーを下げて通す curve-fit はしていない（新マーカーは fail-closed の追加・
  証拠は生の poc 対と配信事実・意味ある実害＝資格情報・エンジンはスキーマ駆動で製品固有ハードコード
  なし）。情報開示のイントロスペクション（既存 `GRAPHQL_INTROSPECTION`）は ○ 相当で温存。
- **対象の正当性**: DVGA は DVWA/Juice Shop/crAPI と同じく意図的脆弱アプリ（本物の脆弱シンク）。
  「対象が無い」ギャップは、推測でシンクを捏造せず本物ラボを1つ立てることで解消した。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の「実 poc_judge も通す」を 4/4 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15（ドキュメント単一正本・台帳ワークフロー）・§17（動的ルールロード）・§19（完了契約の
固定・カーブフィット禁止）、`rules/lessons.md`（mask-and-restore／最下層 redaction／封印実行は実対象
到達を証明）、`rules/codingrules.md`（bare except 禁止・秘密を出さない・境界のみ noqa 付き broad catch）、
メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]。

## 非阻害の観測（deferred / 別件）

- `GraphQLAnalyzer.analyze_async`（`src/core/attack/graphql_analyzer.py`）が DVGA のスキーマで
  `object of type 'NoneType' has no len()` を送出し、既存イントロスペクション情報開示 Finding が
  DVGA では出ない（本タスクの実害 Finding はエンジンが自前でイントロスペクションするため非依存で
  ◎ 到達）。本変更起因ではない**既存バグ**（`non_blocking_observation`）。修正は別途ユーザー判断。
- 台帳 `task_registry.yaml` の構造ずれ（SGK-2026-0465 以降が `tasks:` 外に連なる・validator 0 エラー・
  運用影響なし）は既存慣習どおり同位置に登録。構造修正は §12 に基づき別途判断（`non_blocking_observation`）。
