---
task_id: SGK-2026-0499
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0499_ldap-injection.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0499_ldap-injection_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0487_nosql-injection-confirmation.md
tags:
- shigoku
- detection
- ldap-injection
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-15'
---

# SGK-2026-0499 作業完了報告 — LDAP インジェクション（認証バイパス）を実対象で本物確定（◎）

## 何をしたか / なぜ

能力マップの LDAP インジェクションを ◎ 化。既存 `ldap_tester.py` は**完全なプレースホルダ**
（リクエストを送らず空結果を返す）で未配線だったため、in-band 差分で確定する新エンジンを新設。

実対象（実測）：**SKF `ldap-injection`**（Flask・:5000・実 LDAP バックエンド。`POST /login` が
`(&(cn=<username>)(sn=<password>))` を文字列連結して検索）。コントロール（ランダムリテラル）は
"Wrong identity provided."、`username=*&password=*` は "You are now admin user!" を返す
＝正当な資格情報なしの認証バイパス。

## 実装（新設1＋承認済み凍結2）

- **smart_ldap_injection.py（非凍結・新規）**: `SmartLDAPInjectionHunter`。①負のコントロール
  （メタ文字なしランダムリテラル×2）②LDAP メタ文字ペイロード（`*`/`*` 他）で成功印の差分を確定。
  成功印は task 由来（`ldap_success_marker`）優先、無ければ**2 コントロールで安定するベースラインに対し
  注入応答にだけ現れる特徴行を自動導出**（製品固有文字列なし）。**マーカー中心スニペット**＋コントロールは
  同一バイト領域切り出し（差分は同じ領域の両側）。`self._client` seam・auth は poc マスク／evidence 保持。
- **payout_grade.py（凍結・承認）**: `_LDAP_METACHAR_PATTERN`（`*`／`)(`／`(|`／`(&`）＋
  `_MARKER_CATEGORIES["ldap_injection"]="ldap_injection_confirmed"`＋発火分岐（request_url 非空＋payload に
  メタ文字＋success_marker 非空＋injection 2xx＋marker が injected_served_body 実在＋control_served_body
  非実在が**全て揃ったときだけ**発火・fail-closed）。finding.py に `VulnType.LDAP_INJECTION`。
- **sealed_reproduction_checker.py（凍結・承認）**: `_check_ldap_replay`（fresh リテラルのコントロール×
  確定済みメタ文字ペイロードを form 再送し、成功印が注入応答に再出現＋コントロールに非出現→matched）。

## 結果（独立検証・Claude が実測）

- **実 SKF `ldap-injection` ラボ**で実 `SmartLDAPInjectionHunter.execute` が差分で自走検出
  （`username=*&password=*`・成功印 "You are now admin user!" を自動導出・コントロールは失敗）
  →**GATE1 `payout_grade=True/ldap_injection_confirmed`**。
- **GATE2**: 実 `SealedReproductionChecker` が fresh リテラルのコントロール×メタ文字ペイロードを form 再送し
  差分を再観測→**matched**（`reproduction_marker_matched:ldap_injection_confirmed`）。
- **GATE3**: 本物の poc_judge（実 LLM）で **is_real=True・has_actual_impact=True・counter_evidence=False・
  needs_human=False**（初回一発）。審査理由は「メソッド・URL・Content-Type が同一で差分はメタ文字の有無のみ、
  リテラルは失敗しメタ文字で管理者ログイン成功印が出る＝入力が LDAP フィルタとして解釈された認証バイパス」。
  **完全3ゲート達成＝◎**。差分の両側を同じ領域で見せる教訓（[[poc-judge-raw-evidence]]）を先取りし初回一発。
- テスト: 新規12テスト（engine 差分確定・両側 poc・非脆弱で不確定・コントロールはメタ文字なし・provided
  marker 使用・payout_grade fail-closed（メタ文字なし／marker が control 出現）／sealed matched・mismatched・
  not_run（client なし／スコープ外／メタ文字なし replay））緑。非回帰: 失敗3件は本変更前でも失敗する既存
  （phase_b×2・t3_hybrid budget）＝**0499 起因の回帰ゼロ**（1382 passed）。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）exit 0（無改変）。承認済凍結2は承認範囲の追加のみ。
  製品非依存トークン 0・trailing whitespace 0・秘密値非露出。

## 確度の結論（正直な格付け）

- **LDAP インジェクション（認証バイパス）＝正当な資格情報なしの管理者成りすまし・ディレクトリ抽出で実害**、
  実 poc_judge も通り **◎（完全3ゲート）**。curve-fit なし（発火は fail-closed・成功印は自動導出/ task 由来・
  差分は同一領域の両側）。**高度化 中(L2)**（フォーム認証バイパスの in-band 差分・SKF 単一・ブラインド
  （真偽/時間）・属性開示・GET/JSON 注入点は別途）。非破壊（読み取り専用の検索）。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の実 poc_judge を初回一発で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（実対象到達の証明・一ファイルの挙動を仕様とし
ない・マーカー中心スニペット）、`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa・
明示タイムアウト）、メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]・
[[detection-capability-wiring-map]]・[[skf-labs-ssti-crlf]]。

## 非阻害の観測（deferred / 別件）

- ブラインド LDAP 注入（真偽ベース・時間ベース）・属性開示の網羅・AD 固有・非フォーム（GET/JSON）注入点の
  一般化・パイプライン統合は `deferred_followup`。
