---
task_id: SGK-2026-0484
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0484_graphql-authz-exposure-confirmation.md
- docs/shigoku/reports/2026-09-13_sgk-2026-0484_graphql-authz-exposure-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- graphql
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0484 作業ログ（GraphQL 認可欠陥・実 DVGA・◎）

## 1. 偵察（事実優先・実測）
- GET のみで現行3ラボに GraphQL 実シンクが無いことを確認（crAPI `/graphql` 系 404・Juice Shop
  `/graphql` は Angular catch-all HTML）。→ 本物ラボ **DVGA(`dolevf/dvga`)** を `127.0.0.1:5013` に起動。
- 実測: 認証なし `{users{id username password}}` が admin/operator の資格情報を 200 で返す（値マスク）。
  `pastes(public:false)` が非公開データを返す。イントロスペクション開放も確認。
- scratchpad で「スキーマだけから機微 root フィールドを汎用発見→自動クラフト→認証なし取得」が
  ラボ固有ハードコードなしで成立することを実証（`Query.users -> UserObject.password`）。

## 2. 確定バーの欠落点（事実）
- `SmartGraphQLHunter` はイントロスペクション情報開示のみ（実害クエリ未実行）。
- `broken_access_control`/`idor`→`authz_diff` は2アカウント差分専用で「認証なしで機微データが返る」
  露出型に合わない → GraphQL 専用の新 vuln_type＋新マーカーが必要。

## 3. 台帳・計画・承認
- SGK-2026-0484 採番（registry.yaml・DOC-0554）。凍結2（payout_grade/sealed_reproduction）改変は
  ユーザー明示承認（DVGA 起動含め「進めて」）。

## 4. 実装（Claude 直接・小粒surgical）
- smart_graphql: スキーマ駆動クラフト（`_craft_sensitive_query`・引数必須 root 回避）＋認証なし実クエリ
  （`_gql_post`・`self._client` 注入 seam）＋値 redact（`_redact_graphql_body`・キー側照合
  `_collect_sensitive_keys`）＋実害 Finding（`_build_exposure_finding`・vuln_type=GRAPHQL_AUTHZ_EXPOSURE・
  graphql_exposure_evidence＋graphql_bola_replay＋生 poc 対）。probe は自前イントロスペクションで
  fail-closed 自己ガードのため run_as_tool 非依存で常時試行。
- finding: VulnType.GRAPHQL_AUTHZ_EXPOSURE 追加。
- payout_grade: `_MARKER_CATEGORIES["graphql_authz_exposure"]="graphql_sensitive_exposed"`＋
  `_match_firing_marker` の graphql 分岐（5条件＋キー実在で発火・fail-closed）。
- sealed_reproduction: `_check_graphql_exposure_replay`（ssrf_inband 同型・JSON POST 再送→機微フィールド
  再観測）＋`_graphql_fields_present`（構造照合＋文字列包含フォールバック）。dispatch 分岐を追加。

## 5. 独立検証（Claude・実出力）
- 実 DVGA E2E: 実 execute→`{users{id username password}}` 認証なし 200・機微値→payout_grade=True/
  graphql_sensitive_exposed→実再現 matched→CONFIRMED。served_body は値 redact 済み。
- 実 poc_judge: **4/4 承認**（is_real/impact True・counter False・値 redact 済み。1 回は「len=6 の
  秘匿値」と明記した上で real 判定）＝秘密値非露出で完全3ゲート達成。
- 新規21テスト緑。非回帰: 失敗3件は HEAD でも失敗する既存（phase_b_readiness×2・t3_hybrid budget・
  stash で確認・1094 passed）＝0484 起因の回帰ゼロ。凍結3 exit 0。製品 token0・whitespace0。
- 秘密値監査: Finding evidence/poc に値なし（合成偽値でアサート）・再取得本文は照合のみ非永続。

## 6. 完了
- 完了条件1〜5 充足（条件3 実 poc_judge 4/4）。in_scope_blocker 0 → done。
- 能力マップ: SSTI/CRLF/GraphQL 行を分割し **GraphQL を ◎**（DVGA・認証なし機微データ取得を完全3ゲート）。
  SSTI/CRLF は △ のまま（実シンク/制御対象が別途必要）。
- 教訓: 「対象が無い」ギャップは推測でシンクを捏造せず**本物ラボを1つ立てる**ことで解消（DVWA/JuiceShop/
  crAPI と同じ posture）。GraphQL 認可欠陥は「スキーマ駆動クラフト＋認証なし実クエリ＋生 poc 対＋
  意味ある実害（資格情報）」で実 poc_judge を通す。秘密値は redact でも実害判定に十分（[[poc-judge-raw-evidence]]）。
  バー非低下・証拠の実体と見せ方の強化。[[no-capability-minimization]]。
- 観測(別件): GraphQLAnalyzer の既存バグ（DVGA スキーマで NoneType len・本変更外）。task_registry 構造ずれ（運用影響なし）。
