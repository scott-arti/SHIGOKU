---
task_id: SGK-2026-0487
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0487_nosql-injection-confirmation.md
- docs/shigoku/worklogs/2026-09-13_sgk-2026-0487_nosql-injection-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0486_xxe-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- nosql-injection
- confirmation-bar
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0487 作業完了報告 — NoSQL(MongoDB) 演算子注入を実対象で本物確定（◎）

## 何をしたか / なぜ

能力マップ [[sgk-2026-0465]] の「エンジンが無いギャップ領域」の NoSQLi を ◎ 化。既存
`attack/nosql_tester.py` と `VulnType.NOSQL_INJECTION` は在るが specialist・確定バーに未配線
（長さ差ヒューリスティックのみ）だった。実測で **crAPI クーポン検証
`/community/api/v2/coupon/validate-coupon`（MongoDB・要認証）** が NoSQL 演算子注入に脆弱と確認：
無効リテラル → HTTP 500、`{"$ne": null}`/`{"$regex":".*"}` → HTTP 200＋有効クーポン `TRAC075`。
有効コードを知らなくても演算子で有効レコードを抽出できる本物の NoSQL 注入（実害：クーポン詐取・
検証バイパス・データ抽出）を、機械フロア＋実再現＋実 poc_judge の完全3ゲートで ◎ に到達させた。
非破壊（検証の読み取りのみ）。

## 実装（新設・非凍結1＋承認済み凍結2）

- **smart_nosql.py（非凍結・新規エンジン）**: `SmartNoSQLHunter`。候補 JSON フィールド（task 由来＋
  coupon_code/username/email/… の汎用名）に①負のコントロール（無効リテラル）と②MongoDB 演算子
  （`$ne`/`$regex`/`$gt`）を送り、**①失敗（非2xx/データなし）かつ②成功（2xx＋実データ）の決定論的
  差分**で確定（IDOR authz_diff 同型）。`self._client` 注入 seam。構造化 `nosql_evidence`（operator＋
  control 両方）＋`nosql_replay`＋**差分を示す2ステップ poc**（Step1 リテラル失敗／Step2 演算子成功）
  ＋impact/repro を付与。製品固有のエンドポイント/フィールド名はハードコードしない。
- **payout_grade.py（凍結・承認）**: `_NOSQL_OPERATOR_PATTERN`＋`_nosql_body_has_data` を追加。
  `_MARKER_CATEGORIES["nosql_injection"]="nosql_operator_injection"`。`_match_firing_marker` の分岐は
  ①request_url 非空 ②operator_payload に演算子 ③演算子成功（2xx+データ）④コントロール失敗が
  **全て揃ったときだけ**発火（fail-closed）。演算子成功×リテラル失敗の差分が「クエリ演算子として
  解釈された」決定的証拠。既存マーカー経路は byte-identical で非回帰。
- **sealed_reproduction_checker.py（凍結・承認）**: `_check_nosql_replay` を追加。演算子ペイロード
  （JSON body）を封印スコープ内へ 1 回再送し 2xx+データで再び成功→matched。認証は
  evidence.request_headers を使用（ssrf_inband/0482 同型）。演算子なし記述子は not_run（fail-closed）。

## 秘密情報の扱い（監査）

- crAPI はテスト用に自分で作成したアカウントの JWT を使用（ユーザーの秘密ではない）。それでも
  トークンは秘密として扱う：**poc_request は `Authorization: Bearer <redacted>` にマスク**、封印再現に
  必要なため evidence.request_headers にのみ実値を保持（ssrf_inband/0482 と同型・内部状態）。
- **poc_judge（実 LLM）に送られるのは vuln_type/evidence(method,url,status,response_body)/poc_request
  (マスク済)/poc_response/impact/reproduction_steps のみ**（`_build_user_payload`）＝request_headers は
  送られず、**生トークンは LLM に届かない**（テストで判定可視フィールドに生トークンが無いことを
  アサート）。クーポンデータは秘密ではない。

## 結果（独立検証・Claude が実測）

- **実 crAPI** で実 `SmartNoSQLHunter.execute` が差分確認で自走検出（field `coupon_code`・
  `{"$ne": null}`→HTTP 200＋`TRAC075`／無効リテラル→HTTP 500）→`payout_grade=True/
  nosql_operator_injection`→**実 `SealedReproductionChecker` が演算子を封印スコープ内で再送し 2xx+データを
  再観測→matched→CONFIRMED**。
- **本物の poc_judge（実 LLM）で 5/5 承認**（is_real=True・has_actual_impact=True・
  counter_evidence=False）。審査理由は「Step1 無効リテラル→HTTP 500、Step2 演算子 `{"$ne": null}`→
  HTTP 200＋有効クーポンの差分が実測記録＝coupon_code がクエリ演算子として解釈される NoSQL 注入」。
  **完全3ゲート達成＝◎**。（注: 差分の片側=無効リテラル失敗を poc に含めなかった初回試行は 2/5 で、
  judge が「差分証拠が不足」と正しく指摘。**証拠の見せ方を2ステップ差分 poc に底上げして 5/5**＝
  poc-judge-raw-evidence の教訓・バー非低下。）
- テスト: 新規19テスト緑（payout_grade 発火/fail-closed6種/regex 演算子・engine 差分確定/トークン
  マスク/replay 記述子/コントロール成功時 None/judge 可視に生トークンなし・sealed_reproduction
  matched/mismatched/not_run/スコープ外/演算子なし）。非回帰: 失敗3件は本変更前（HEAD）でも失敗する
  既存（phase_b_readiness×2＝環境依存・t3_hybrid_wiring budget・本セッションで stash 比較確認済み）＝
  **0487 起因の回帰ゼロ**。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）は各 `git diff --quiet HEAD` exit 0。
  承認済凍結2は承認範囲の追加のみ。製品非依存 token 0（追加コード・新規テストは target.example/
  evil.example のみ。crAPI/8888/TRAC075 は scratchpad E2E のみ）。trailing whitespace 0。

## 確度の結論（正直な格付け）

- **NoSQL 演算子注入（認可/検証バイパス・データ抽出）＝実害あり**で、実 poc_judge も通り
  **◎（完全3ゲート）**。バーを下げて通す curve-fit はしていない（新マーカーは fail-closed の追加・
  証拠は「演算子成功×無効リテラル失敗」の決定論的差分・エンジンは製品固有ハードコードなし）。
- **対象の正当性**: crAPI は意図的脆弱アプリ（本物の脆弱シンク）。既存テスターを配線＋差分確定＋
  実対象で「エンジンが無い」ギャップを埋めた。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の実 poc_judge を 5/5 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（封印実行は実対象到達を証明・mask-and-restore）、
`rules/codingrules.md`（bare except 禁止・秘密を出さない・境界のみ noqa 付き broad catch）、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]。

## 非阻害の観測（deferred / 別件）

- blind/time-based NoSQLi（`$where` sleep 等）・破壊的 NoSQL 更新は対象外（`non_blocking_observation`）。
- 台帳 `task_registry.yaml` の構造ずれ（0465 以降が `tasks:` 外・validator 0 エラー・運用影響なし）は
  既存慣習どおり同位置に登録。構造修正は §12 に基づき別途判断（`non_blocking_observation`）。
