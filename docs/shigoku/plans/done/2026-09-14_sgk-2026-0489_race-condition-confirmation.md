---
task_id: SGK-2026-0489
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0489_race-condition-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0489_race-condition-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0488_mass-assignment-confirmation.md
tags:
- shigoku
- detection
- race-condition
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0489 計画 — Race Condition（TOCTOU）を実対象で本物確定（◎）

## 背景・事実（偵察で実測）

能力マップ [[sgk-2026-0465]] の Race Condition。既存 `RaceConditionSpecialist`
（`swarm/logic/manager.py`）→ `RaceConditionTester`（`attack/`）は在るが、「N 並列で 2xx を数え
成功数 > 期待(1) なら True」の**並列側のみ**（逐次コントロールなし・確定バーに未接続）。

実対象探し（実測）:
- **crAPI クーポン適用 `/workshop/api/shop/apply_coupon` は race に脆弱でない**（並列 6/30 とも成功は
  常に 1・残りは "already claimed"＝原子的にロック済み）。想定対象は不成立（事実優先で棄却）。
- DVGA/SKF と同じ posture で **OWASP SKF ラボ `blabla1337/owasp-skf-lab:racecondition`**（Flask・
  `race.py`）を制御対象として 127.0.0.1:5091 に起動。実測で本物の TOCTOU を確認：
  `?action=validate&person=X` は先に `hello.sh`（`echo "X" > hello.txt`）を書き、その後 sed 正規表現
  `[A-Za-z0-9 ]` で検証→不正なら `boot_clean()`（削除）。`/`（`action=run`）は `bash hello.sh` を実行し
  hello.txt を反映。**不正ペイロード（シェルメタ文字＋一意マーカー）を書いた直後〜削除の窓**で `/` が
  `bash hello.sh` を実行すると注入コマンドが走る。逐次（validate→run）ではマーカー非反映（検証で削除）、
  **並列バーストではマーカーが反映**（実測 round1 で出現）＝レース経由のコマンド注入。ラボは `?action=reset`
  で戻せる＝**再現可能**（消費されない）。非破壊（ラボ自身の表示ファイルへ良性マーカー書き込みのみ）。

## 確定バーの欠落点（事実）

- specialist は並列側のみで逐次コントロール差分がなく、確定バーに `race_condition` マーカーが無い。
- 「N 並列で 2xx 多発」だけでは、単なる冪等な複数成功と race を区別できない（偽陽性リスク）。

## 対象（完了契約）

SKF レースラボの TOCTOU を実対象で **機械フロア＋実再現＋実 poc_judge の完全3ゲート**で ◎ に到達。
確定は**決定論的差分＋一意マーカー**で行う：逐次コントロール（検証で弾かれマーカー非反映）× 並列バースト
（TOCTOU 窓でマーカー反映）。マーカーは我々が選ぶ乱数トークンで、反映に出現すれば注入コマンドが窓で
実行された決定的証拠（偶然混入・捏造不可）。

## 実装方針（新設・最小差分）

1. **新エンジン `smart_race_condition.py`（非凍結・新規）**: `SmartRaceConditionHunter`。task 由来の
   シナリオ記述子（trigger 要求＝`{marker}` 置換可能な racy アクション、observe 要求＝反映/実行、
   任意 reset、concurrency/rounds）で駆動。①逐次コントロール（reset→trigger(marker)→observe→
   マーカー非反映を確認）②並列バースト（reset→trigger+observe を並列で R ラウンド→observe 応答に
   マーカー出現）の差分で確定。`self._client` 注入 seam。構造化 `race_evidence`（race/control 両方）＋
   `race_replay`（再現用テンプレ）＋差分2ステップ poc（Step1 逐次＝非反映／Step2 並列＝反映）を付与。
   製品固有ハードコードなし（payload/URL はすべて task 由来）。
2. **確定バー `payout_grade.py`（凍結・承認）**: `_MARKER_CATEGORIES["race_condition"]="race_condition_toctou"`。
   `_match_firing_marker` の分岐は request_url 非空＋marker 非空＋race_status 2xx＋marker が
   race_served_body に実在＋marker が control_served_body に**非**実在が**全て揃ったときだけ**発火
   （fail-closed）。並列で出て逐次で出ない差分が「TOCTOU 窓で実行された」決定的証拠。
3. **再現チェッカー `sealed_reproduction_checker.py`（凍結・承認）**: `_check_race_replay`。race_replay
   記述子に従い、**新しいマーカー**を trigger テンプレに埋めて封印スコープ内で**並列バーストを1シーケンス
   再実行**（trigger/observe URL 両方をスコープ再検証・concurrency/rounds は上限クランプ）、observe 応答に
   新マーカーが出現すれば matched。race は単発再送では再現不可のため burst 再現が正当（fail-closed・
   記述子不正/新マーカー非出現は not_run/mismatched）。

## 完了条件

1. 実 SKF ラボで実 `SmartRaceConditionHunter.execute` が差分確認で自走検出→
   payout_grade=True/race_condition_toctou。
2. 実 `SealedReproductionChecker` が新マーカーで burst を再実行しマーカー再出現→matched→CONFIRMED。
3. 本物の poc_judge（実 LLM）で承認（差分の両ステップ＝逐次非反映/並列反映を poc に提示）。
4. 製品非依存 fixture の新規テスト緑（発火／fail-closed 各否定側＝マーカー欠落・control にも出現・
   非2xx・非反映／engine 差分確定・control 非反映・replay 記述子／sealed_reproduction matched・
   mismatched・not_run・スコープ外）。
5. 凍結3 exit 0。製品トークン 0・秘密値非露出・回帰ゼロ。

## NOT in scope

- crAPI/実運用アプリの race 一般化（本タスクは実対象1件で ◎ 到達・幅優先）。
- クロールによる race シナリオ自動発見（trigger/observe テンプレは task 由来）。
- 破壊的な race（残高破壊・データ削除）は対象外。良性マーカー書き込みのみ。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（封印実行は実対象到達を証明・mask-and-restore・
一ファイルの挙動を仕様とみなさない）、`rules/codingrules.md`（bare except 禁止・秘密非露出・
境界のみ noqa・明示タイムアウト）、メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]・
[[detection-capability-wiring-map]]・[[skf-labs-ssti-crlf]]。
