---
task_id: SGK-2026-0497
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0497_prototype-pollution_work_report.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0497_prototype-pollution_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0496_oob-deserialization.md
tags:
- shigoku
- detection
- prototype-pollution
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0497 計画 — プロトタイプ汚染（サーバサイド Node.js）を実対象で本物確定（◎）

## 背景・事実（偵察で実測）

既存 `attack/prototype_pollution_tester.py`（`__proto__`/constructor.prototype ベクタ）は在るが未配線。
in-band 差分で確定する新エンジンを新設。実対象：**SKF `js-prototype-pollution`**（Node/Express・
`POST /message` が `_.merge({}, req.body, {ipAddress})`＝lodash.merge の PP sink）。実測で `__proto__.admin`
に一意マーカーを送ると、以降 `/create` で作る **admin を設定しない新ユーザー**の `/login` 応答（Admin 欄）に
マーカーが継承・出現（汚染前は空）。entrypoint の app.js は不在で実体は index.js（`node index.js` で起動）。

## 対象（完了契約）

SKF PP ラボを実対象で **機械フロア＋実再現＋実 poc_judge の完全3ゲート**で ◎。確定は**in-band 差分＋
一意マーカー**（汚染後に別オブジェクトへマーカー出現×汚染前は不在）。シナリオ（sink/setup/observe）は
task 由来（製品固有ハードコードなし）。

## 実装方針（新設1＋承認済み凍結2）

1. **`injection/smart_prototype_pollution.py`（非凍結・新規）**: `SmartPrototypePollutionHunter`。task 由来の
   sink（`__proto__.<prop>={marker}` マージ要求）／setup（新オブジェクト生成・{uniq}）／observe（反映）で駆動。
   ①control（汚染前 setup+observe→マーカー非出現）②pollute（sink 送信）③observe（別 setup+observe→マーカー
   出現）の差分で確定。`self._client` seam・marker 中心スニペット・prototype_pollution_evidence／replay／
   差分3ステップ poc。
2. **`payout_grade.py`（凍結・承認）**: `_MARKER_CATEGORIES["prototype_pollution"]=
   "prototype_pollution_confirmed"`＋発火分岐（sink_url／observe_url／property／marker 非空＋observe 2xx＋
   marker が polluted_body 実在＋control_body 非実在・fail-closed）。
3. **`sealed_reproduction_checker.py`（凍結・承認）**: `_check_pp_replay`（新マーカーで pollute→setup→observe を
   封印内で再実行し新オブジェクトへの再出現→matched。json sink は Content-Type: application/json を明示）。

## 完了条件

1. 実 SKF PP ラボで実 `SmartPrototypePollutionHunter.execute` が差分で自走検出→payout_grade=True/
   prototype_pollution_confirmed。
2. 実 `SealedReproductionChecker` が新マーカーで再実行し再出現→matched→CONFIRMED。
3. 本物の poc_judge（実 LLM）で承認（汚染前/後の差分＋一意マーカーを提示）。
4. 製品非依存 fixture の新規テスト緑（engine 差分確定・非脆弱で不確定・poc/replay 記述子／payout_grade
   fail-closed 各否定側／sealed matched・mismatched・not_run）。
5. 凍結3 exit 0。製品トークン 0・秘密値非露出・回帰ゼロ。

## NOT in scope

- クライアント側 PP（DOM）・特定ガジェットチェーン（RCE/DoS への連鎖）・非 lodash マージ実装の網羅・
  SKF 以外への一般化。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`、`rules/codingrules.md`、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。
