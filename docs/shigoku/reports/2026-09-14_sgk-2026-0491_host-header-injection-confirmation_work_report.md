---
task_id: SGK-2026-0491
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0491_host-header-injection-confirmation.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0491_host-header-injection-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0490_jwt-key-confusion-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- host-header-injection
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0491 作業完了報告 — Host Header Injection（認証バイパス）を実対象で本物確定（◎）

## 何をしたか / なぜ

能力マップ [[sgk-2026-0465]] の Host Header Injection を ◎ 化。既存 `HostHeaderInjectionTester` は
reflection パターン一致のヒューリスティックのみで swarm specialist・確定バーに未接続だった。差分確認の
新エンジンを新設し、実対象で機械フロア＋実再現＋実 poc_judge の完全3ゲートで ◎ に到達させた。

実対象（実測・非破壊）：DVGA/SKF と同じ posture で **OWASP SKF ラボ
`host-header-authentication-bypass`**（Flask）を 127.0.0.1:5092 に起動。`/dashboard` が受信 Host を
認可判定に使い、Host が localhost/127.0.0.1 だと未ログインで admin panel（従業員給与データ）を返す欠陥。
実測で **Host: localhost → HTTP 200＋制限データ（"Mr Mark Oney"/"1000000"）を未ログイン取得**、
**非バイパスホスト → 302 リダイレクト（データ無し）** ＝ Host ヘッダ注入による認証バイパス（制限データ
漏洩）。非破壊（読み取り GET のみ・破壊系エンドポイントは使わない）。

## 実装（新設・非凍結1＋承認済み凍結2）

- **smart_host_header.py（非凍結・新規エンジン）**: `SmartHostHeaderHunter`。task 由来の observe
  エンドポイント＋制限署名で駆動。候補ホストヘッダ（Host/X-Forwarded-Host/X-Host/X-Forwarded-Server/
  Forwarded）× 候補バイパス値（localhost/127.0.0.1＋task 由来）を注入し、①control（非バイパスホスト）
  ②injection の応答を比較、**署名が injection に出て control に出ない**差分で確定。**注入ヘッダが Host
  以外のときは Host を control 値に固定**し、バイパスの原因を当該ヘッダに厳密帰属（誤検知防止）。
  `allow_redirects=False` で即時応答を評価。**injected スニペットは署名中心**で切り出し（署名が本文後方
  でも証拠を落とさない）。`self._client` 注入 seam。構造化 `host_header_evidence`（injection/control 両方）
  ＋`host_header_replay`＋差分2ステップ poc を付与。製品固有ハードコードなし。
- **payout_grade.py（凍結・承認）**: `_MARKER_CATEGORIES["host_header_injection"]="host_header_auth_bypass"`。
  `_match_firing_marker` の分岐は request_url／injected_header／injected_host_value／restricted_signature
  非空＋injection 2xx＋署名が injected_served_body に実在＋control_served_body に非実在が**全て揃った
  ときだけ**発火（fail-closed）。
- **sealed_reproduction_checker.py（凍結・承認）**: `_check_host_header_replay` を追加。host_header_replay
  記述子（url/header/value/signature）に従い、注入ヘッダ付き GET を封印スコープ内へ 1 回再送し、署名が
  2xx 応答に再出現→matched（GET＋任意ヘッダ送信は既存 `_send_get_jwt` の汎用ヘッダ GET 経路を流用・
  jwt 固有処理は無い）。記述子不正/署名非再出現は not_run/mismatched（fail-closed）。

## 結果（独立検証・Claude が実測）

- **実 SKF ラボ**で実 `SmartHostHeaderHunter.execute` が差分確認で自走検出（Host: localhost→200＋署名／
  非バイパス→302）→`payout_grade=True/host_header_auth_bypass`→**実 `SealedReproductionChecker` が注入
  ヘッダ付き GET を封印スコープ内で再送し署名を再観測→matched→CONFIRMED**。
- **本物の poc_judge（実 LLM）で 5/5 承認**（is_real=True・has_actual_impact=True・counter=False・
  初回から）。審査理由は「同一 URL・同一メソッドで Host のみを control から localhost に差し替えると、
  応答が '/' リダイレクト（拒否）から HTTP 200＋従業員給与データ（Mr Mark Oney/1000000）へ変化＝Host
  ヘッダを認可に信頼している」。**完全3ゲート達成＝◎**。（注: 初回 E2E は署名が本文 offset>1500 に
  あり先頭切り詰めで証拠が落ちて payout_grade=False→**署名中心スニペット**に底上げして通過＝
  poc-judge-raw-evidence の教訓・バー非低下。）
- テスト: 新規21テスト緑（payout_grade 発火/fail-closed 各否定側＝欠落・空URL・空header・空署名・非反映・
  control にも署名・非2xx・impact 欠落／engine 差分確定・中心スニペット(署名 offset>1500)・2ステップ poc・
  replay 記述子・非アクセス制御で不確定・常時拒否で不確定・署名無しで不確定／sealed_reproduction matched・
  mismatched・not_run(client なし/スコープ外/記述子不備)）。非回帰: 失敗3件は本変更前でも失敗する既存
  （phase_b×2・t3_hybrid budget・SGK-2026-0488/0489 で stash 確認済み）＝**0491 起因の回帰ゼロ**
  （1241 passed）。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）exit 0。承認済凍結2は承認範囲の追加のみ。
  製品非依存 token 0（追加コード・新規テストは target.example のみ。SKF/5092/host-header は scratchpad
  E2E のみ）。trailing whitespace 0。

## 確度の結論（正直な格付け）

- **Host ヘッダ注入（認証/認可バイパス・制限データ漏洩）＝実害あり**で、実 poc_judge も通り
  **◎（完全3ゲート）**。curve-fit なし（新マーカーは fail-closed・注入ヘッダ isolate で誤検知防止・
  署名は task 由来でエンジンに製品固有値なし）。**高度化は 低(L1)**（SKF ラボ単一・認可バイパス1形態・
  reflection/リセットポイズニングは別途・未統合）＝幅優先方針どおり。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の実 poc_judge を 5/5 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（封印実行は実対象到達を証明・一ファイルの挙動を
仕様としない）、`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa・明示タイムアウト）、
メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。

## 非阻害の観測（deferred / 別件）

- Host reflection 型（X-Forwarded-Host がリンク/Location に反映）・パスワードリセットポイズニング
  （メールリンク観測が必要）・実運用アプリ対象・パイプライン統合は本タスク対象外（`deferred_followup`）。
