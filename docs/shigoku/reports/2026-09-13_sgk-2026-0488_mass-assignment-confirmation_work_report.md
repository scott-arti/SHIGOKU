---
task_id: SGK-2026-0488
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0488_mass-assignment-confirmation.md
- docs/shigoku/worklogs/2026-09-13_sgk-2026-0488_mass-assignment-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0487_nosql-injection-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- mass-assignment
- confirmation-bar
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0488 作業完了報告 — Mass Assignment（特権フィールド昇格）を実対象で本物確定（◎）

## 何をしたか / なぜ

能力マップ [[sgk-2026-0465]] の Mass Assignment を ◎ 化。既存 `MassAssignmentSpecialist`→
`MassAssignmentTester` は「2xx なら success」の status ヒューリスティックで、注入した特権
フィールドが実際に受理・反映されたかを検証せず（偽陽性リスク・◎の証拠に不足）、確定バーの
`_MARKER_CATEGORIES["mass_assignment"]="authz_diff"` は IDOR/BAC の「認証有無で差が出る」
意味論で mass assignment（特権フィールドの一括代入受理）と不整合だった（相乗り不正・依存
テストは皆無）。実測で **Juice Shop `POST /api/Users`（登録・認証不要）** が `role` 特権昇格に
脆弱と確認：`role` を送らない control → サーバ既定 `role="customer"`、`"role":"admin"` 注入 →
応答（永続レコード）に `role="admin"`。本来サーバ側でしか設定できないフィールドを client が
攻撃者値で上書きできる本物の Mass Assignment（権限昇格）を、機械フロア＋実再現＋実 poc_judge の
完全3ゲートで ◎ に到達させた。非破壊（登録＝追加系・使い捨てアカウント）。

## 実装（新設・非凍結1＋承認済み凍結2）

- **smart_mass_assignment.py（非凍結・新規エンジン）**: `SmartMassAssignmentHunter`。base body
  （task 由来）に特権フィールド候補（role/is_admin/isAdmin/verified/email_verified/credit/
  available_credit/balance…と対応する攻撃者値）を1つずつ注入し、①control（当該フィールド無し）
  ②injection（当該フィールド有り）を送信、応答本文から同名フィールドを**再帰読取**して
  **injection 反映値==攻撃者値 かつ control 反映値==非空でかつ攻撃者値と異なる**（サーバが既定値を
  入れる server-controlled フィールドを client が上書きした）差分で確定。`self._client` 注入 seam。
  一意制約フィールド（email/username 等）は送信毎に uuid で更新（create の重複回避）、**封印再現用に
  未使用の fresh body を1つ予約**（単発再送で 201 を再観測可能）。構造化 `mass_assignment_evidence`
  （injection/control 両方）＋`mass_assignment_replay`＋**差分2ステップ poc**（Step1 control 既定値／
  Step2 injection 攻撃者値）＋impact/repro。製品固有のエンドポイント/フィールドはハードコードしない。
- **payout_grade.py（凍結・承認）**: `_MARKER_CATEGORIES["mass_assignment"]` を `authz_diff` から
  専用 `privileged_field_assigned` に変更（authz_diff 分岐の集合からも除去）。`_match_firing_marker` の
  新分岐は request_url 非空＋field 非空＋injected_value 非空＋injected_status 2xx＋
  injected_field_value==injected_value＋control_field_value 非空かつ≠injected_value が**全て揃った
  ときだけ**発火（fail-closed）。**echo だけの応答は control_field_value が空になり不発火**。既存
  authz_diff 経路（api/idor/broken_access_control）は byte-identical で非回帰。
- **sealed_reproduction_checker.py（凍結・承認）**: `_check_mass_assignment_replay` を追加。予約済み
  injection body（fresh 値・JSON body）を封印スコープ内へ 1 回再送し、応答の同名フィールドが再び
  攻撃者値になる→matched（フィールド読取・正規化はエンジンの `_read_field`/`_norm` を再利用し確定時と
  一貫）。認証は evidence.request_headers を使用（ssrf_inband/0482 同型）。記述子不正/非2xx は not_run/
  mismatched（fail-closed）。

## 秘密情報の扱い（監査）

- 実対象（Juice Shop 登録）は認証不要のため本タスクの実証に秘密は無い（作成する使い捨てアカウントの
  値も target.example の合成値）。
- エンジンは authed 対象への一般性のため任意 auth を扱うが、**poc_request は `Authorization: Bearer
  <redacted>` にマスク**、封印再現に必要な実値は evidence.request_headers にのみ保持し、**poc_judge
  （実 LLM）に送られるのは vuln_type/evidence(method,url,status,response_body)/poc_request(マスク済)/
  poc_response/impact/reproduction_steps のみ**（`_build_user_payload`）＝request_headers は送られず
  生トークンは LLM に届かない（テストで judge 可視入力に生トークンが無いことをアサート）。

## 結果（独立検証・Claude が実測）

- **実 Juice Shop** で実 `SmartMassAssignmentHunter.execute` が差分確認で自走検出（field `role`・
  control→`customer`／injection→`admin`・HTTP 201）→`payout_grade=True/privileged_field_assigned`
  →**実 `SealedReproductionChecker` が予約 injection body（fresh email）を封印スコープ内で再送し
  role=admin を再観測→matched→CONFIRMED**。
- **本物の poc_judge（実 LLM）で 5/5 承認**（is_real=True・has_actual_impact=True・
  counter_evidence=False・初回から）。審査理由は「control（role 非送信）→既定 customer／injection
  （role:admin）→201 応答の永続レコードに admin 反映、profileImage も default.svg→defaultAdmin.png と
  差分＝mass assignment による権限昇格」。**完全3ゲート達成＝◎**。
- テスト: 新規27テスト緑（payout_grade 発火/bool 既定 false 昇格/fail-closed 各否定側＝欠落・空URL・
  空field・非反映・echo・control 同値・非2xx・bool status・impact 欠落／engine 差分確定・2ステップ poc・
  fresh replay 記述子・echo で不確定・control 既に特権で不確定・base 無しで不確定・任意 auth マスク・
  judge 入力に生トークンなし／sealed_reproduction matched・mismatched(既定値/非2xx)・not_run(client
  なし/スコープ外/expected 空/body 非dict)）。非回帰: 失敗3件は本変更前（HEAD）でも失敗する既存
  （phase_b_readiness×2＝環境依存・t3_hybrid_wiring budget＝candidate lifecycle）を **stash 比較で
  再確認**＝**0488 起因の回帰ゼロ**（1179 passed）。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）は各 `git diff --quiet HEAD` exit 0。
  承認済凍結2は承認範囲の追加/分離のみ。製品非依存 token 0（追加コード・新規テストは target.example/
  evil.example のみ。Juice Shop/3000/role=admin は scratchpad E2E のみ）。trailing whitespace 0。

## 確度の結論（正直な格付け）

- **Mass Assignment（特権フィールド昇格・権限昇格）＝実害あり**で、実 poc_judge も通り
  **◎（完全3ゲート）**。バーを下げて通す curve-fit はしていない（新マーカーは fail-closed の分離・
  echo 排除を含む差分・エンジンは製品固有ハードコードなし）。**高度化は 低(L1)**（Juice Shop 単一・
  登録 role 昇格1形態・パイプライン未統合・第2対象/更新系未検証）＝幅優先方針どおり。
- **対象の正当性**: Juice Shop は意図的脆弱アプリの本物シンク（"Admin Registration" 相当）。既存の
  status ヒューリスティック検出を差分確認に置き換え、確定バーの意味論的不整合を専用マーカーで解消した。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の実 poc_judge を 5/5 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（封印実行は実対象到達を証明・mask-and-restore・
一ファイルの挙動を仕様とみなさない）、`rules/codingrules.md`（bare except 禁止・秘密を出さない・
境界のみ noqa 付き broad catch）、メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]・
[[detection-capability-wiring-map]]。

## 非阻害の観測（deferred / 別件）

- 更新系（PUT/PATCH で自リソースの特権フィールド昇格）・作成後に別 GET が必要な2段階 mass assignment・
  第2対象での再検証・パイプライン統合は本タスク対象外（`deferred_followup`・高度化フェーズで実施）。
- Juice Shop `PUT /api/Users/{id}` は JWT 検証（DECODER）エラーで昇格不成立＝当該経路は非該当
  （`non_blocking_observation`）。
