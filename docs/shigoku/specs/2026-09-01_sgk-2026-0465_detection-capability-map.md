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
updated_at: '2026-09-08'
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
| 反射型/DOM型XSS | 検索欄・URLパラメータ経由 | `smart_xss` | ○ 配線済み・発火経路は保存型と共通 |
| SQLインジェクション | ログインの `' OR 1=1--`・商品検索 | `smart_sqli`（エラーベース＋影響実証） | ◎ 本物の証拠付きで確定まで実証済み（現行コードベースで確定2件・param q/data・error(500)＋boolean差分＋非機微`sqlite_version()`抽出・GET-only・機微抽出0。SGK-2026-0466 で再実証） |
| アクセス制御欠陥 / IDOR | 他人のカゴ・他人の注文の閲覧 | `logic/idor` + `response_comparator` + API probe authB マトリクス | ◎ 本物の対象で cross-account BOLA を確定まで実証（**実 Juice Shop・実2アカウント・実コード・実 HTTP** で「Aのログインで Bのかごが見えた」→ payout_grade=True・SGK-2026-0468 part-2）。狙い撃ちの高速確定が実戦経路。**注**: フル自律走行での自動発見は速度（AI逐次判断）＋認証トークン失効の制約あり → SGK-2026-0469/0470 で追跡（確定の実力とは別問題） |
| 認証の弱さ / JWT | 弱いパスワード・admin ログイン・トークン細工 | `auth/auth_ninja` + 再認証 | △〜○ 突破試行は可・決め手の証拠は今後 |
| CORS 設定ミス | 任意オリジンからの読み取り | `smart_cors` | △ 検出はする・機微データ漏えいまで示さないと確定に上げない |
| オープンリダイレクト | `?to=` で外部へ誘導 | `open_redirect` | ◎ 本物の対象で確定まで実証（**実 Juice Shop `/redirect?to=`** の許可リスト回避で攻撃者ホストへ 302→payout_grade=True/external_redirect→再現 matched→CONFIRMED。SGK-2026-0471）。クロール由来の正規値取得も実装（許可リスト付き対象で名前該当パラメータ空値ケースをフル判定 CONFIRMED・SGK-2026-0472）。名前非該当パラメータ（`to` 等）のクロール由来回避は実利低のため deferred（SGK-2026-0473） |
| SSRF / コマンド系 | サーバに外部アクセスさせる | `smart_ssrf` / `smart_cmd_ssrf` | △ 確証には外部受信(OOB)経路の整備が要る |
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

いずれも「試して当てる」だけでなく、XSS と同じく「証拠を残して確定に上げる」経路の整備が中心課題となる。
