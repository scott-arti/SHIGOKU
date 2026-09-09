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
updated_at: '2026-09-10'
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
| SSRF | サーバに外部アクセスさせる | `smart_ssrf` / `smart_cmd_ssrf` | △ 確証には外部受信(OOB)経路の整備が要る（エンジン未接続・Juice Shop 到達性未確証・crAPI が有力候補） |
| LFI / パストラバーサル | `/ftp` 配下のファイル取得 | `smart_lfi` | ◎ 本物の対象で確定まで実証（**実 Juice Shop** のパス方式ヌルバイト漏洩でクリーン403→バイパス200→file_content_leak→再現matched→CONFIRMED。パラメータ方式に加えパス方式検出＋差分成功判定を追加・SGK-2026-0474） |
| 秘密情報の露出 | ソースマップ・機密ファイル・暗号鍵 | `secret/sourcemap` | △ ソースマップ系は対応・列挙系は偵察併用 |
| ファイルアップロード悪用 | 不正な種類/サイズのファイル | `logic/file_upload` | △ 検出枠あり |
| SSTI / CRLF / GraphQL悪用 | テンプレ注入・ヘッダ注入・過剰取得 | 各 `smart_*` | △ エンジンあり・実証は今後 |

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
