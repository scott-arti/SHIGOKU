---
task_id: SGK-2026-0485
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-13_sgk-2026-0485_ssti-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-13_sgk-2026-0485_ssti-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0484_graphql-authz-exposure-confirmation.md
tags:
- shigoku
- detection
- ssti
- confirmation-bar
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0485 計画 — SSTI（サーバサイドテンプレートインジェクション）を実対象で本物確定（◎）

## 背景・事実（偵察で実測）

能力マップ [[sgk-2026-0465]] の残る △ は「SSTI / CRLF」。GET のみの実測で現行4ラボ
（DVWA / Juice Shop / crAPI / DVGA）に SSTI/CRLF の実シンクが無いことを確認したため、
DVGA と同じ posture で本物の脆弱アプリ **OWASP SKF ラボ `blabla1337/owasp-skf-lab:ssti`**
（Python/Flask・Jinja2）を制御対象として起動（`127.0.0.1:5085`）。実測で **404 ハンドラが
`render_template_string` に `request.url` を埋め込む**ため、任意クエリ param（`?q={{7*7}}`）が
Jinja2 で評価され `49` になる本物の SSTI を確認。`{{9999*9999}}`→99980001 も評価。

## 確定バーの欠落点（事実）

- 既存エンジン `SmartSSTIHunter`（`SSTIScanner` の算術確認ペア方式）は SSTI を自走検出するが、
  Finding の evidence が `response_status=0`・生証拠不足で `payout_grade=missing_evidence`。
- `_MARKER_CATEGORIES` に `ssti` が無く機械フロア非発火。再現経路も未整備。

## 対象（完了契約）

SKF SSTI ラボの Jinja2 SSTI を実対象で **機械フロア＋実再現＋実 poc_judge の完全3ゲート**で
◎ に到達。非破壊（読み取りクエリのみ・テンプレート評価は状態変更なし）。秘密情報は扱わない
（算術ペイロードのみ）。

## 実装方針（最小差分）

1. **エンジン `smart_ssti.py`（非凍結）**: 確定済み payload を `self._client` 注入 seam で 1 回
   再送し、算術積 `expected`（例 `49<hex marker>`・一意マーカー付きで自然混入・捏造不可）を含む
   生応答本文＋実 status を捕捉（`_capture_ssti`。GET は params で 1 回だけエンコード＝事前
   エンコード URL の二重エンコード回避）。`expected` 中心のスニペット（`_evidence_snippet`。反映が
   本文後方でも証拠保持）で Evidence（method/url/status/response_body）＋`ssti_evidence`
   ＋`ssti_replay`（再現記述子）＋生 poc 対＋impact/repro を付与。
2. **確定バー `payout_grade.py`（凍結・承認）**: `_MARKER_CATEGORIES["ssti"]="template_evaluated"`
   ＋`_match_firing_marker` の分岐（request_url 非空＋response_status>0＋payload 非空＋expected 非空
   ＋served_body に expected 実在で発火・1つでも欠ければ None＝fail-closed）。
3. **再現チェッカー `sealed_reproduction_checker.py`（凍結・承認）**: `ssti_replay` に従い確定済み
   payload を封印スコープ内へ 1 回再送（GET＝読み取り）→応答本文に expected 再出現で matched。
   client None / スコープ外 / fingerprint 不一致 / 記述子不正 は not_run（fail-closed）。

## 完了条件

1. 実 SKF ラボで実 `SmartSSTIHunter.execute` が SSTI を自走検出→payout_grade=True/template_evaluated。
2. 実 `SealedReproductionChecker` が payload を再送し expected を再観測→matched→CONFIRMED。
3. 本物の poc_judge（実 LLM）で承認。
4. 製品非依存 fixture の新規テスト緑（発火／fail-closed 各否定側／スニペット／capture／再現 matched・
   mismatched・not_run・スコープ外）。
5. 凍結3（poc_judge.md / task_queue.py / finding_validator.py）exit 0。製品トークン 0・回帰ゼロ。

## NOT in scope

- CRLF の確定（次タスク・SKF `http-response-splitting` を予定）。
- SSTI の RCE 実行まで（算術評価で ◎ 到達・破壊的 RCE 実証は非対象）。
- 実バグバウンティ対象への適用。

## 参考にしたルール

CLAUDE.md §14/§15/§17/§19、`rules/lessons.md`（封印実行は実対象到達を証明）、
`rules/codingrules.md`（bare except 禁止・境界のみ noqa）、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]。
