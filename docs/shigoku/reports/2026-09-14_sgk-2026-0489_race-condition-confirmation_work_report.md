---
task_id: SGK-2026-0489
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0489_race-condition-confirmation.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0489_race-condition-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0488_mass-assignment-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- race-condition
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0489 作業完了報告 — Race Condition（TOCTOU）を実対象で本物確定（◎）

## 何をしたか / なぜ

能力マップ [[sgk-2026-0465]] の Race Condition を ◎ 化。既存 `RaceConditionSpecialist`→
`RaceConditionTester` は「N 並列で 2xx を数え成功>期待(1)なら True」の**並列側のみ**で、逐次
コントロール差分がなく（単なる冪等な複数成功と race を区別できず偽陽性リスク）、確定バーに
`race_condition` マーカーも無かった。逐次/並列差分＋一意マーカーの新エンジンを新設し、実対象で
機械フロア＋実再現＋実 poc_judge の完全3ゲートで ◎ に到達させた。

**対象探索（事実優先）**: 想定していた **crAPI クーポン適用 `/workshop/api/shop/apply_coupon` は
並列 6/30 とも成功 1＝原子ロック済みで race 非脆弱**と実測で判明し棄却。DVGA/SKF と同じ posture で
**OWASP SKF ラボ `blabla1337/owasp-skf-lab:racecondition`**（Flask・`race.py`）を 127.0.0.1:5091 に
起動。`?action=validate` が `hello.sh`（`echo "person" > hello.txt`）を書いた直後〜sed 検証で不正
判定→削除するまでの窓で、`/`（`action=run`＝`bash hello.sh`）が並列に走ると注入コマンドが実行される
本物の TOCTOU を確認。逐次ではマーカー非反映（検証で削除）、並列バーストでは observe 応答に
マーカー反映＝レース経由のコマンド注入。ラボは `?action=reset` で戻せる＝再現可能・非破壊（表示
ファイルへ良性マーカー書き込みのみ）。

## 実装（新設・非凍結1＋承認済み凍結2）

- **smart_race_condition.py（非凍結・新規エンジン）**: `SmartRaceConditionHunter`。task 由来の
  シナリオ（trigger／observe／任意 reset／concurrency／rounds）で駆動。①逐次コントロール
  （reset→trigger(marker)→observe→マーカー非反映を確認・出たら TOCTOU 差分でないと棄却）②並列
  バースト（trigger と observe を並列で複数ラウンド→observe 応答にマーカー出現）の差分で確定。
  `self._client` 注入 seam。**control と race を同一オフセット窓で切り出し反映領域を双方に含める**
  （別領域だと差分が審査で不成立＝poc_judge の指摘への対応）。構造化 `race_evidence`（race/control
  両方）＋`race_replay`（再現用テンプレ）＋差分2ステップ poc を付与。製品固有ハードコードなし
  （payload/URL はすべて task 由来）。
- **payout_grade.py（凍結・承認）**: `_MARKER_CATEGORIES["race_condition"]="race_condition_toctou"`。
  `_match_firing_marker` の分岐は request_url 非空＋marker 非空＋race_status 2xx＋marker が
  race_served_body に実在＋marker が control_served_body に**非**実在が**全て揃ったときだけ**発火
  （fail-closed）。並列で出て逐次で出ない差分が「TOCTOU 窓で実行された」決定的証拠（marker は乱数
  トークンで偶然混入・捏造不可）。
- **sealed_reproduction_checker.py（凍結・承認）**: `_check_race_replay` を追加。race_replay 記述子に
  従い**新しいマーカー**を trigger に埋め、封印スコープ内で**並列バーストを1シーケンス再実行**
  （ThreadPoolExecutor・trigger/observe/reset の各 URL をスコープ再検証・concurrency/rounds は上限
  クランプ・GET 限定）、observe 応答に新マーカー再出現で matched。race は単発再送では再現不可のため
  burst 再現が正当（記述子不正/GET 以外/新マーカー非出現は not_run/mismatched・fail-closed）。

## 結果（独立検証・Claude が実測）

- **実 SKF ラボ**で実 `SmartRaceConditionHunter.execute` が差分確認で自走検出（逐次＝マーカー非反映／
  並列バースト＝marker 反映・HTTP 200）→`payout_grade=True/race_condition_toctou`→**実
  `SealedReproductionChecker` が新マーカーで並列バーストを封印スコープ内で再実行しマーカー再出現→
  matched→CONFIRMED**。
- **本物の poc_judge（実 LLM）で 5/5 承認**（is_real=True・has_actual_impact=True・
  counter_evidence=False）。審査理由は「Step1 逐次＝検証/ロックで弾かれ 'Important hello file is
  missing'（マーカー無し）、Step2 並列バースト＝system-message に注入コマンドが echo した一意マーカー
  出現の差分＝TOCTOU」。**完全3ゲート達成＝◎**。（注: 初回は control スニペットが `<head>`/ロゴ領域
  のみで差分が審査で不成立と正しく 0/5 で却下された。**control と race を同一オフセット窓で見せる
  底上げ**で 5/5＝poc-judge-raw-evidence の拡張・バー非低下。）
- テスト: 新規22テスト緑（payout_grade 発火/fail-closed 各否定側＝欠落・空URL・空marker・非反映・
  control にも出現・非2xx・bool status・impact 欠落／engine 差分確定・2ステップ poc・replay 記述子・
  非反映で不確定・逐次でも反映で不確定・シナリオ無しで不確定／sealed_reproduction matched・mismatched・
  not_run(client なし/スコープ外/trigger 欠落/GET 以外)）。非回帰: 失敗3件は本変更前でも失敗する既存
  （phase_b_readiness×2＝環境依存・t3_hybrid_wiring budget＝candidate lifecycle・SGK-2026-0488 で
  stash 比較確認済み・私が触っていない領域）＝**0489 起因の回帰ゼロ**（1201 passed）。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）は各 `git diff --quiet HEAD` exit 0。
  承認済凍結2は承認範囲の追加のみ。製品非依存 token 0（追加コード・新規テストは target.example のみ。
  SKF/5091/racecondition は scratchpad E2E のみ）。trailing whitespace 0。

## 確度の結論（正直な格付け）

- **Race Condition（TOCTOU・レース経由のコマンド注入/検証バイパス）＝実害あり**で、実 poc_judge も
  通り **◎（完全3ゲート）**。バーを下げて通す curve-fit はしていない（新マーカーは fail-closed・
  逐次/並列差分＋乱数マーカー・エンジンは製品固有ハードコードなし）。**高度化は 低(L1)**（SKF ラボ
  単一・逐次/並列差分1形態・パイプライン未統合・実運用アプリ対象は別途）＝幅優先方針どおり。
- **対象の正当性**: crAPI クーポンは実測で race 非脆弱と判明し棄却（事実優先）。SSTI/XXE と同じ
  purpose-built vulnerable lab posture（ユーザー承認済み前例）で本物の TOCTOU シンクを確定した。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の実 poc_judge を 5/5 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（封印実行は実対象到達を証明・一ファイルの挙動を
仕様とみなさない）、`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa・明示
タイムアウト）、メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]・
[[detection-capability-wiring-map]]・[[skf-labs-ssti-crlf]]。

## 非阻害の観測（deferred / 別件）

- 実運用アプリ（crAPI/Juice Shop 等）での race 検証・POST trigger の race・クロールによる race
  シナリオ自動発見・パイプライン統合は本タスク対象外（`deferred_followup`・高度化フェーズ）。
- crAPI apply_coupon は原子ロック済みで race 非脆弱（`non_blocking_observation`・事実記録）。
