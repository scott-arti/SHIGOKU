---
task_id: SGK-2026-0487
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-13_sgk-2026-0487_nosql-injection-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-13_sgk-2026-0487_nosql-injection-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0486_xxe-confirmation.md
tags:
- shigoku
- detection
- nosql-injection
- confirmation-bar
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0487 計画 — NoSQL(MongoDB) 演算子注入を実対象で本物確定（◎）

## 背景・事実（偵察で実測）

能力マップ [[sgk-2026-0465]] の「エンジンが無いギャップ領域」のうち NoSQLi。既存 `attack/nosql_tester.py`
（`NoSQLInjectionTester`・`$ne`/`$gt`/`$regex` 等）と `VulnType.NOSQL_INJECTION` は在るが、
swarm の specialist にも確定バーにも**未配線**（長さ差/レコード増のヒューリスティック検出のみ）。
実測で **crAPI のクーポン検証 `/community/api/v2/coupon/validate-coupon`（MongoDB・要認証）** が
NoSQL 演算子注入に脆弱と確認：無効リテラル `ZZZ_NOPE` → HTTP 500、`{"$ne": null}` / `{"$regex":".*"}`
→ HTTP 200＋有効クーポン `TRAC075`。＝有効コードを知らなくても演算子で有効レコードを抽出できる
本物の NoSQL 注入（実害：クーポン詐取・検証バイパス・データ抽出）。非破壊（検証の読み取り）。

## 確定バーの欠落点（事実）

- specialist 未配線・確定バーに `nosql_injection` マーカーなし。
- 既存テスターの検出は長さ差ヒューリスティックで payout-grade 証拠に不足。

## 対象（完了契約）

crAPI クーポン検証の NoSQL 演算子注入を実対象で **機械フロア＋実再現＋実 poc_judge の完全3ゲート**で
◎ に到達。確定は**決定論的差分**（演算子成功×無効リテラル失敗）で行う（IDOR authz_diff 同型）。
認証トークンは秘密として扱う（poc・judge 入力ではマスク、封印再現用に evidence.request_headers に
のみ保持＝ssrf_inband/0482 同型）。

## 実装方針（新設・最小差分）

1. **新エンジン `smart_nosql.py`（非凍結・新規）**: `SmartNoSQLHunter`。候補 JSON フィールド
   （task 由来＋coupon_code/username/email/… の汎用名）に、①負のコントロール（無効リテラル）と
   ②MongoDB 演算子（`$ne`/`$regex`/`$gt`）を送り、①失敗（非2xx/データなし）かつ②成功（2xx＋実データ）
   の差分で確定。`self._client` 注入 seam。構造化 `nosql_evidence`（operator/control 両方）＋
   `nosql_replay`＋差分を示す2ステップ poc（Step1 リテラル失敗／Step2 演算子成功）を付与。認証は
   poc でマスク・evidence.request_headers に実値保持。製品固有ハードコードなし。
2. **確定バー `payout_grade.py`（凍結・承認）**: `_NOSQL_OPERATOR_PATTERN`＋`_nosql_body_has_data`
   ヘルパ追加。`_MARKER_CATEGORIES["nosql_injection"]="nosql_operator_injection"`。`_match_firing_marker`
   の分岐は request_url 非空＋operator_payload に演算子＋演算子成功（2xx+データ）＋コントロール失敗が
   全て揃ったときだけ発火（fail-closed）。
3. **再現チェッカー `sealed_reproduction_checker.py`（凍結・承認）**: `_check_nosql_replay`。演算子
   ペイロード（JSON body）を封印スコープ内へ 1 回再送し 2xx+データで再び成功→matched。認証は
   evidence.request_headers を使用。演算子なし記述子は not_run（fail-closed）。

## 完了条件

1. 実 crAPI で実 `SmartNoSQLHunter.execute` が差分確認で自走検出→payout_grade=True/nosql_operator_injection。
2. 実 `SealedReproductionChecker` が演算子を再送し成功を再観測→matched→CONFIRMED。
3. 本物の poc_judge（実 LLM）で承認（差分の両ステップを poc に提示）。
4. 製品非依存 fixture の新規テスト緑（発火／fail-closed 各否定側／トークンマスク／再現 matched・
   mismatched・not_run・スコープ外・演算子なし）。
5. 凍結3 exit 0。製品トークン 0・秘密値非露出（judge 入力に生トークンなし）・回帰ゼロ。

## NOT in scope

- blind/time-based NoSQLi（`$where` sleep 等）・破壊的な NoSQL 更新（Juice Shop review 一括更新等）。
- crAPI 以外の NoSQLi 対象への一般化（本タスクは実対象1件で ◎ 到達）。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（封印実行は実対象到達を証明・mask-and-restore）、
`rules/codingrules.md`（bare except 禁止・秘密を出さない・境界のみ noqa）、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]。
