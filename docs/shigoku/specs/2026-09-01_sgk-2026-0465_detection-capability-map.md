---
task_id: SGK-2026-0465
doc_type: spec
status: active
parent_task_id: null
related_docs:
- docs/shigoku/plans/done/2026-08-30_sgk-2026-0463_stored-stage2-redirect-marker-fix.md
- docs/shigoku/plans/done/2026-09-01_sgk-2026-0464_candidate-xss-dedup-url-normalization.md
- docs/shigoku/plans/done/2026-09-01_sgk-2026-0466_sqli-confirmed-reverification.md
- docs/shigoku/plans/done/2026-09-02_sgk-2026-0468_unauth-probe-custom-header-scheme.md
- docs/shigoku/plans/done/2026-09-03_sgk-2026-0469_authenticated-scan-token-refresh.md
- docs/shigoku/plans/2026-09-03_sgk-2026-0470_llm-in-loop-latency-reduction.md
created_at: '2026-09-01'
updated_at: '2026-09-13'
---

# SHIGOKU 検出能力マップ（脆弱性の種類 × 対応状況）

## 目的と前提

- 「AI バグバウンティハンターとして SHIGOKU が実際に何を検出できるか」を、実装済みエージェントに基づいて一覧化する。
- Juice Shop はあくまで入り口の具体例として使う。**対象固有の正解リスト（期待検知マトリクス）は意図的に持たない**（SGK-2026-0417 で撤回。特定アプリへの当てはめ最適化＝カーブフィッティングを避けるため）。ここに書くのは「脆弱性の種類ごとの汎用能力」である。
- 確度表記: ◎ = 本物の証拠付きで確定まで実証済み / ○ = エンジンあり・確定経路が整備済み / △ = エンジンはあるが決め手の証拠づくりが未整備。

## SHIGOKU が持つ検出エンジン（`src/core/agents/swarm/` 実在）

- `injection/`: XSS(`smart_xss`, `stored_xss_detector`)・SQL(`smart_sqli`)・コマンド/SSRF(`smart_cmd_ssrf`, `smart_ssrf`)・LFI(`smart_lfi`)・CORS(`smart_cors`)・CRLF(`smart_crlf`)・SSTI(`smart_ssti`)・オープンリダイレクト(`open_redirect`)・GraphQL(`smart_graphql`)
- `logic/`: IDOR(`idor`)・ファイルアップロード(`file_upload`)・応答比較(`response_comparator`)・ボディ改変(`body_mutator`)
- `auth/`: 認証突破(`auth_ninja`)・再認証(`reauth_specialist`)
- `secret/`: 秘密露出/ソースマップ(`sourcemap`)
- `discovery/`: GraphQL・サブドメイン乗っ取り(`takeover`)・GitHub偵察・視覚偵察

## 能力マップ

| 脆弱性の種類 | Juice Shop での代表例 | SHIGOKU の担当 | 現状の確度 |
|---|---|---|---|
| 保存型XSS | コメント/フィードバックに保存し閲覧者で発火 | `smart_xss` + `stored_xss_detector` | ◎ 本物のブラウザ警告まで実証済み（確定1・variant=stored） |
| 反射型/DOM型XSS | 検索欄・URLパラメータ経由 | `smart_xss` | ◎ 本物の対象で確定まで実証（**実 Juice Shop** の search DOM XSS(innerHTML sink)を実ブラウザで alert 発火→確定バーが実ブラウザ発火(browser_execution.dialog_observed)を発火信号に採用→再現チェッカーが Juice Shop へ再ナビゲートし alert 再観測→CONFIRMED。SGK-2026-0477。dialog 非観測は fail-closed で非確定）。**実エンジン自走＋実 AI 審査(poc_judge)まで通した完全3ゲートで CONFIRMED を実証（SGK-2026-0479）**。実行証拠を「合言葉往復」（注入 alert に実行毎ランダム nonce→ブラウザ dialog message が nonce と一致=テンプレ捏造不可の実行証拠）に強化し、実 poc_judge の通過率を 1/3→5/6 に改善（バー非低下・証拠の見せ方を底上げ） |
| SQLインジェクション | ログインの `' OR 1=1--`・商品検索 | `smart_sqli`（エラーベース＋影響実証） | ◎ 本物の証拠付きで確定まで実証済み（現行コードベースで確定2件・param q/data・error(500)＋boolean差分＋非機微`sqlite_version()`抽出・GET-only・機微抽出0。SGK-2026-0466 で再実証） |
| アクセス制御欠陥 / IDOR | 他人のカゴ・他人の注文の閲覧 | `logic/idor` + `response_comparator` + API probe authB マトリクス | ◎ 本物の対象で cross-account BOLA を確定まで実証（**実 Juice Shop・実2アカウント・実コード・実 HTTP** で「Aのログインで Bのかごが見えた」→ payout_grade=True・SGK-2026-0468 part-2）。狙い撃ちの高速確定が実戦経路。**注**: フル自律走行での自動発見は速度（AI逐次判断）＋認証トークン失効の制約あり → SGK-2026-0469/0470 で追跡（確定の実力とは別問題） |
| 認証の弱さ / JWT | 弱いパスワード・admin ログイン・トークン細工 | `auth/auth_ninja` + 再認証 | ◎ 本物の対象で確定まで実証（**実 Juice Shop** で JWT alg=none 無署名偽造トークンをサーバが受理＝完全な認証バイパスを確定。fabricated identity を GET のみで反映・トークン無しとの差分で証明・確定バー新マーカー jwt_forgery_accepted・SGK-2026-0476）。署名検証サーバでは fail-closed で正しく非確定。弱い admin パスワード（admin123）もログイン成功を実測 |
| CORS 設定ミス | 任意オリジンからの読み取り | `smart_cors` | ○ 本物確定能力あり（**認証付きオリジン反映＋ACAC:true＋機微データ越境読み取り**を確定バーの新マーカー cors_credentialed_reflection で確定・制御対象でフル判定 CONFIRMED を実証・SGK-2026-0475）。**実 Juice Shop は `ACAO:*`（反映なし・認証なし）＝公開データのみのため fail-closed で正しく非確定**（偽◎を出さない。`*` を確定に上げるのは禁止 curve-fit） |
| オープンリダイレクト | `?to=` で外部へ誘導 | `open_redirect` | ◎ 本物の対象で確定まで実証（**実 Juice Shop `/redirect?to=`** の許可リスト回避で攻撃者ホストへ 302→payout_grade=True/external_redirect→再現 matched→CONFIRMED。SGK-2026-0471）。クロール由来の正規値取得も実装（許可リスト付き対象で名前該当パラメータ空値ケースをフル判定 CONFIRMED・SGK-2026-0472）。名前非該当パラメータ（`to` 等）のクロール由来回避は実利低のため deferred（SGK-2026-0473） |
| コマンドインジェクション | `ping` 等のOSコマンド実行 | `smart_cmd_ssrf` | ◎ 本物の対象で確定まで実証（**実 DVWA** `/vulnerabilities/exec/`(POST) に読み取り専用コマンド注入→本文 `uid=33(www-data)` in-band→payout_grade=True/command_execution→再現チェッカーが DVWA へ非破壊コマンドを再POSTし uid= 再観測→CONFIRMED。SGK-2026-0478。指標なしは fail-closed で非確定）。**実エンジン自走＋実 AI 審査(poc_judge)まで通した完全3ゲートで CONFIRMED を実証**（実 poc_judge 通過率 7/8＝有効回答は全承認・生の `uid=` 証拠を評価。まれな非承認は「教育用ターゲット」判断による外れ値でありターゲット正当性の話＝本物対象では非該当・SGK-2026-0479 の検証で確認） |
| SSRF | サーバに外部アクセスさせる | `smart_ssrf` / `smart_cmd_ssrf` | ◎ **in-band SSRF（内部到達・応答本文反映）を実対象で完全3ゲート確定**（**実 crAPI** の認証付き POST でリクエスト内の URL 値フィールドをサーバが取得し応答本文を in-band 反映→内部専用サービス MailHog(`mailhog:8025`) の UI を反映（クライアントはこの内部ホスト名を解決できず直接到達不可＝サーバ視点到達の差分）→payout_grade=True/新マーカー `ssrf_inband`→再現チェッカーがトリガ POST を封印スコープ内で再送し反映を再観測→matched→CONFIRMED、かつ**実 poc_judge 4/4 承認**（生の poc_request/poc_response＋内部サービス到達を評価）。SGK-2026-0482。OOB 基盤は不要。反映なし/クライアント直接到達可は fail-closed）。**OOB/DNS blind SSRF の外部受信基盤は未整備**（別タスク・in-band で ◎ 到達済み）。既存 `ssrf_callback`（OOB/クラウドメタデータ）は非回帰で併存 |
| LFI / パストラバーサル | `/ftp` 配下のファイル取得 | `smart_lfi` | ◎ 本物の対象で確定まで実証（**実 Juice Shop** のパス方式ヌルバイト漏洩でクリーン403→バイパス200→file_content_leak→再現matched→CONFIRMED。パラメータ方式に加えパス方式検出＋差分成功判定を追加・SGK-2026-0474） |
| 秘密情報の露出 | ソースマップ・機密ファイル・暗号鍵 | `secret/sourcemap` + `secret/manager` | ◎ **列挙系シークレット露出（公開URLで資格情報配信）を実対象で完全3ゲート確定**（**実 crAPI** の `/.env` が認証なしの単一 GET で DB/MongoDB 資格情報を 200 配信→本文に `DB_PASSWORD`/`MONGO_DB_PASSWORD` 等の資格情報代入→確定バー新マーカー `secret_exposed`（retrieved_url 非空＋status=200＋served_body に資格情報代入パターン一致。**値 redact 済みでもキー側で一致**）で payout_grade=True→再現チェッカーが取得元URLへ封印スコープ内で非破壊 GET 再読し資格情報パターンを再観測→matched→CONFIRMED、かつ**実 poc_judge 4/4 承認**（生の poc_request/poc_response＋配信事実＋意味ある実害＝資格情報。1 回は「値はマスク」と明記した上で real 判定＝秘密値非露出で実害評価）。SGK-2026-0483。資格情報を含まない公開ファイル/非200/取得元URL空は fail-closed）。**秘密値は evidence/report/log に一切残さない**（値 redact・照合はキー側・再取得本文は照合のみ非永続）。ソースマップ系は既存対応、.git 完全ダンプ確定は別経路（配信ファイル型で ◎ 到達済み） |
| ファイルアップロード悪用 | 不正な種類/サイズのファイル | `logic/file_upload` | ◎ **アップロード経由の保存型XSS（実害）を実対象で完全3ゲート確定**（**実 DVWA** に良性 HTML（`<img src=x onerror=alert('<nonce>')>`）をアップロード→取得URLを nonce 往復GETで確定→実ブラウザで dialog message==nonce（実行確定）→payout_grade=True/reflected_payload→再現チェッカーが取得URLを実ブラウザ再ロードし dialog 再観測→matched→CONFIRMED、かつ**実 poc_judge 4/4 承認**。証拠を「生の配信応答本文（nonce ペイロードを含む実バイト列）」で見せる底上げ（SGK-2026-0479 と同型）で通過率 1/4→4/4・バー非低下。SGK-2026-0481。dialog 非発火/nonce 不一致は fail-closed）。**設置＋取得のみ**（良性・非実行ファイルの unrestricted upload with retrieval）は機械フロア＋実対象再現で確定するが、それ単体は実害未証明のため実 poc_judge 非承認＝○（SGK-2026-0480・uploaded_file_retrieved マーカー・取得不可は fail-closed） |
| GraphQL悪用 | 認可欠陥・過剰取得・イントロスペクション | `injection/smart_graphql` + `discovery/graphql` | ◎ **GraphQL 認可欠陥（認証なしで機微データ取得）を実対象で完全3ゲート確定**（現行3ラボに GraphQL 実シンクが無いため DVWA/Juice Shop/crAPI と同じ posture で本物の脆弱 GraphQL アプリ **DVGA** を制御対象として起動。実測で認証なしの `{users{username password}}` が DB 資格情報を、`pastes(public:false)` が非公開データを 200 で返す本物の認可欠陥を確認。エンジンは**スキーマ駆動で機微スカラーフィールドを持つ root Query フィールドを汎用特定→認証なしで実クエリ→実データ取得**（製品固有ハードコードなし）。確定バー新 vuln_type `graphql_authz_exposure`＋新マーカー `graphql_sensitive_exposed`（endpoint 非空＋status=200＋served_body 非空＋matched_fields 非空＋query 非空、かつ served_body に matched_fields のキーが実在。**値 redact 済みでもキー側フィールド名で照合**）で payout_grade=True→再現チェッカーが `ssrf_inband` 同型の専用パスでトリガクエリを封印スコープ内で再 POST し機微フィールドを再観測→matched→CONFIRMED、かつ**実 poc_judge 4/4 承認**（生の poc_request/poc_response＋認証なし 200＋意味ある実害＝資格情報。1 回は「len=6 の秘匿値」と明記した上で real 判定＝秘密値非露出で実害評価）。SGK-2026-0484。機微フィールド非取得/非200/データ空は fail-closed）。**秘密値は evidence/report/log に一切残さない**（値 redact・照合はキー側・再取得本文は照合のみ非永続）。イントロスペクション情報開示（`GRAPHQL_INTROSPECTION`）は既存 ○ 相当で温存 |
| SSTI（テンプレ注入） | サーバサイドテンプレートの式評価 | `injection/smart_ssti` + `attack/ssti_scanner` | ◎ **サーバサイドテンプレートインジェクションを実対象で完全3ゲート確定**（現行4ラボ（DVWA/Juice Shop/crAPI/DVGA）に SSTI 実シンクが無いため DVGA と同じ posture で本物の脆弱アプリ **OWASP SKF ラボ `blabla1337/owasp-skf-lab:ssti`**（Flask/Jinja2）を制御対象として起動。実測で 404 ハンドラが `render_template_string` に `request.url` を埋め込むため、任意クエリ param（`?q={{7*7}}`）が Jinja2 で評価され `49` になる本物の SSTI を確認。エンジン `SmartSSTIHunter`（`SSTIScanner` の算術確認ペア方式）が自走検出→確定済み payload を再送し算術積 `expected`（`49`＋**一意マーカー**＝自然混入・テンプレ捏造不可）を含む生本文＋実 status を捕捉→確定バー新マーカー `template_evaluated`（request_url 非空＋status>0＋payload 非空＋expected 非空＋served_body に expected 実在）で payout_grade=True→再現チェッカーが payload を封印スコープ内で 1 回再送し expected を再観測→matched→CONFIRMED、かつ**実 poc_judge 5/5 承認**（「反射でなくサーバ側テンプレート評価・一意マーカーで偶然/捏造を排除・RCE 隣接の実害」）。SGK-2026-0485。未評価/積非再出現は fail-closed）。非破壊（読み取りクエリのみ・テンプレ評価は状態変更なし） |
| CRLF悪用 | ヘッダ注入（レスポンス分割） | `injection/smart_crlf` + `attack/crlf_tester` | △ エンジンあり・実証は今後（現行ラボに実シンク無し・SKF `http-response-splitting` 等の制御対象で ◎ 化予定） |

## SHIGOKU に武器がないギャップ（Juice Shop にはある）

専用エンジンが見当たらず、伸ばすなら次の候補になる領域:

- XXE（XML外部実体）— 専用検出なし
- NoSQLインジェクション — SQL前提のため MongoDB 系は弱い
- ビジネスロジック系（クーポン悪用・数量マイナス・値引き細工）— 汎用化が難しく、ほぼ未対応
- 既知の脆弱な部品 / 暗号の弱さ — 別枠で現状ほぼ対象外

## 実証の推奨順（証拠を残して確定に上げやすい順）

1. ~~**SQLi（ログイン回避）**~~ — ✅ 実証済み（SGK-2026-0466・現行コードベースで確定2件）
2. ~~**IDOR（他人のカゴ）**~~ — ✅ 実証済み（SGK-2026-0467/0468・**本物の Juice Shop・実2アカウントで cross-account BOLA を payout_grade 確定まで到達**。フル自律走行の速度/トークン失効は SGK-2026-0469/0470 で追跡）
3. ~~**オープンリダイレクト**~~ — ✅ 実証済み（SGK-2026-0471 実 Juice Shop `/redirect?to=` で ◎・SGK-2026-0472 クロール由来値取得追加。`to` 等の名前非該当は実利低で SGK-2026-0473 に deferred）
4. ~~**LFI / パストラバーサル**~~ — ✅ 実証済み（SGK-2026-0474・**実 Juice Shop `/ftp` パス方式ヌルバイト漏洩で ◎**。パス方式検出＋差分成功判定＋誤検知ガードを追加）
5. ~~**CORS 設定ミス**~~ — ✅ 本物確定能力を構築（SGK-2026-0475・制御対象で認証付きオリジン反映を ◎ 実証。**実 Juice Shop は `ACAO:*` のため fail-closed で正しく非確定**＝偽◎を出さない）
6. ~~**認証/JWT（alg=none 偽造）**~~ — ✅ 実証済み（SGK-2026-0476・**実 Juice Shop で無署名偽造トークン受理＝認証バイパスを ◎**。署名検証サーバでは正しく非確定）
7. ~~**反射型/DOM型XSS**~~ — ✅ 実証済み（SGK-2026-0477・**実 Juice Shop の DOM XSS を実ブラウザ発火＋再現で ◎**。dialog 非観測は fail-closed で非確定）。さらに SGK-2026-0479 で**実エンジン自走＋実 poc_judge まで通した完全3ゲート CONFIRMED**を実証し、実行証拠を合言葉往復（nonce）に強化して実 AI 審査の通過率を 1/3→5/6 へ改善（バー非低下）
8. ~~**コマンドインジェクション**~~ — ✅ 実証済み（SGK-2026-0478・**実 DVWA `/vulnerabilities/exec/` の in-band OS コマンド実行を ◎**。読み取り専用コマンド限定の POST 再送で再現・指標なしは非確定）

いずれも「試して当てる」だけでなく、XSS と同じく「証拠を残して確定に上げる」経路の整備が中心課題となる。
