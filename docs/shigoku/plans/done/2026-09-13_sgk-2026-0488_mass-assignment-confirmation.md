---
task_id: SGK-2026-0488
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-13_sgk-2026-0488_mass-assignment-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-13_sgk-2026-0488_mass-assignment-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0487_nosql-injection-confirmation.md
tags:
- shigoku
- detection
- mass-assignment
- confirmation-bar
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0488 計画 — Mass Assignment（特権フィールド昇格）を実対象で本物確定（◎）

## 背景・事実（偵察で実測）

能力マップ [[sgk-2026-0465]] で Mass Assignment は「tester・swarm 配線・確定バー経路(`authz_diff`)
が既にある」最短候補。だが実測で **既存経路は◎に届かない**ことを確認した：

- `MassAssignmentSpecialist`（`swarm/logic/manager.py`）→ `MassAssignmentTester`（`attack/`）は、
  ペイロード送信後 **2xx なら success** と判定する status ヒューリスティックで、注入した特権
  フィールドが実際に受理・反映されたかを検証しない（＝◎の証拠に不足・偽陽性リスク）。
- `_MARKER_CATEGORIES["mass_assignment"]="authz_diff"` は IDOR/BAC の「認証有無で差が出る」意味論
  （signals: auth_success＋unauth_success / status_improved_with_auth）で、mass assignment の
  「送ってはいけない特権フィールドが攻撃者値で受理される」とは**意味論がずれる**。相乗りは不正。
- `mass_assignment→authz_diff` に依存するテスト/コードは皆無（マッピング行のみ）＝専用マーカー化は安全。

実対象（実測・非破壊）：**Juice Shop `POST /api/Users`（登録・認証不要）**。
- control（`role` 無し）→ サーバが `role="customer"`（サーバ既定）。
- injection（`"role":"admin"` を追加）→ 応答（永続化されたユーザーレコード）に `role="admin"`。
→ 送ってはいけない特権フィールドを攻撃者値でサーバが受理＝本物の Mass Assignment（権限昇格）。

## 対象（完了契約）

Juice Shop 登録の `role` 特権昇格を実対象で **機械フロア＋実再現＋実 poc_judge の完全3ゲート**で
◎ に到達。確定は**決定論的差分**（control=特権フィールド無し→サーバ既定値 ／ injection=特権フィールド
有り→攻撃者値が反映）で行う。エンジンは製品固有のエンドポイント/フィールドをハードコードしない。

## 実装方針（新設・最小差分）

1. **新エンジン `smart_mass_assignment.py`（非凍結・新規）**: `SmartMassAssignmentHunter`。
   base body（task 由来）に対し、特権フィールド候補（role/is_admin/isAdmin/admin/is_active/verified/
   email_verified/credit/available_credit/balance/id/user_id…と対応する攻撃者値）を1つずつ注入し、
   ①control（当該フィールド無し）②injection（当該フィールド有り）を送信、応答本文から同名フィールドを
   再帰読取して **injection の反映値＝攻撃者値 かつ control の反映値＝非空でかつ攻撃者値と異なる**（＝
   サーバが既定値を入れる server-controlled フィールドを client が上書きした）差分で確定。
   `self._client` 注入 seam。一意制約フィールド（email/username 等）は送信毎に uuid で更新（create
   エンドポイントの重複回避）。**封印再現用に未使用の新規 body（fresh email）を1つ予約**（単発再送で
   201 を再観測できる）。構造化 `mass_assignment_evidence`（injection/control 両方）＋
   `mass_assignment_replay`＋差分2ステップ poc（Step1 control→既定値／Step2 injection→攻撃者値）を付与。
   任意 auth は poc マスク・evidence.request_headers に実値保持（authed 対象への一般性・ssrf_inband 同型）。
2. **確定バー `payout_grade.py`（凍結・承認）**: `_MARKER_CATEGORIES["mass_assignment"]` を
   `authz_diff` から専用 `privileged_field_assigned` に変更。`_match_firing_marker` に分岐追加：
   request_url 非空＋field 非空＋injected_value 非空＋injected_status 2xx＋
   injected_field_value==injected_value＋control_field_value 非空かつ≠injected_value が
   **全て揃ったときだけ**発火（fail-closed・echo だけの応答は control_field_value が空になり不発火）。
3. **再現チェッカー `sealed_reproduction_checker.py`（凍結・承認）**: `_check_mass_assignment_replay`。
   予約済み injection body（fresh email）を封印スコープ内へ 1 回再送し、応答の同名フィールドが再び
   攻撃者値になる→matched。認証は evidence.request_headers を使用。記述子不正は not_run（fail-closed）。

## 完了条件

1. 実 Juice Shop で実 `SmartMassAssignmentHunter.execute` が差分確認で自走検出→
   payout_grade=True/privileged_field_assigned。
2. 実 `SealedReproductionChecker` が injection を再送し攻撃者値を再観測→matched→CONFIRMED。
3. 本物の poc_judge（実 LLM）で承認（差分の両ステップを poc に提示）。
4. 製品非依存 fixture の新規テスト緑（発火／fail-closed 各否定側＝echo/control同値/非2xx/フィールド欠落／
   再現 matched・mismatched・not_run・スコープ外／任意 auth マスク）。
5. 凍結3（poc_judge.md / task_queue.py / finding_validator.py）exit 0。製品トークン 0・秘密値非露出・回帰ゼロ。

## NOT in scope

- 破壊的な更新（既存リソースの改変・削除）や状態を壊す mass assignment。本タスクは追加系（登録）で非破壊。
- blind/2段階（作成後に別 GET で確認が必須）な mass assignment の一般化。本タスクは応答反映で確定できる
  実対象1件で ◎ 到達。
- Juice Shop 以外への一般化（エンジンは汎用だが ◎ 到達は実対象1件）。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（封印実行は実対象到達を証明・mask-and-restore・
一ファイルの挙動を仕様とみなさない）、`rules/codingrules.md`（bare except 禁止・秘密を出さない・
境界のみ noqa）、メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]・
[[detection-capability-wiring-map]]。
