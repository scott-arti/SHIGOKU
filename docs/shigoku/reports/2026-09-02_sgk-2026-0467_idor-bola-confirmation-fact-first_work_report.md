---
task_id: SGK-2026-0467
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-01_sgk-2026-0467_idor-bola-confirmation-fact-first.md
- docs/shigoku/worklogs/2026-09-02_sgk-2026-0467_idor-bola-confirmation-fact-first_work_log.md
- docs/shigoku/plans/2026-09-02_sgk-2026-0468_unauth-probe-custom-header-scheme.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
created_at: '2026-09-02'
updated_at: '2026-09-03'
tags:
- shigoku
- vdp
- detection
- confirmation
- idor
- bola
- authz
---

# SGK-2026-0467 作業完了報告 — 真のクロスユーザーBOLA確定（authB配線＋cross-account確定）

## 何をしたか / なぜ

着手前コード精読と fixture 実挙動確認により、SHIGOKU が「別アカウントで他人の資源が見えた」BOLA を confirmed にできなかった真因は 2 つと確定済み: (1) authB（第2アカウント）が端から端まで未配線（`_auth` は auth_headers+cookies のみ、`resolve_auth_b_context` の呼び出し元で `auth_b_headers` 供給が皆無）、(2) 確定バー `payout_grade` の IDOR firing marker（`authz_diff`）は `auth_success`+`unauth_success` 語彙を要求し、object_ab 既存ブロックは impact を意図的に付けず candidate 止まり。本タスクでは確定バー 5 ファイルを無改変のまま、authB を配線し、3-way マトリクスで cross-account を真実に証明できた時のみ IDOR finding を confirmed 級（payout_grade 到達）で発火する最小実装を行った。

## 結果（確定）

- **実装は additive のみ・settings フラグ `idor_cross_account_confirm_enabled`（既定 False / env `SHIGOKU_IDOR_CROSS_ACCOUNT_CONFIRM_ENABLED`）で gate**。authB 不在時は完全 no-op（既存走行は byte-identical）。
- 新規発火ブロック（`manager.py` `_run_api_minimal_check` 内、auth マトリクス確定直後・既存未認証ブロック前に独立配置）の発火条件はすべて真実ベース:
  - フラグ ON ＋ `auth_b_headers` 非空
  - マトリクス signals に `authA_authB_both_success` かつ `auth_boundary_observed`（authA・authB とも 2xx、未認証は非 2xx＝保護されている）
  - `ResponseComparator` による authA/authB 応答本体の構造相関（`is_vulnerable` または `json_structure_match`）
- 発火時の finding は `VulnType.IDOR` / `Severity.HIGH` / `detection_class="cross_account_bola"`、impact・reproduction_steps は cross-account の実挙動を正直に記述（「未認証アクセス許可」の捏造文言は使わない。`build_authz_impact_and_reproduction_steps` は呼ばない）。`additional_info` に `second_account_compared=True` / `cross_account_compared=True`（VDP impact marker。確定バーの impact 条件を、確定バー側の語彙のまま満たす）と `authz_differential`（`build_authz_differential`、extra_signals `cross_account_read` 等）を格納。
- authB 配線: (a) `manager.py` の base_params `_auth` builder が `task.params["auth_b_headers"]`/`auth_b_role` を透過、(b) `master_conductor.py` に `_resolve_second_account_auth()` ヘルパ（workspace `user_sessions` が 2 件以上のときのみ非プライマリ 1 件を返す・既存単一セッション走行は no-op）を追加し、API/Injection backfill タスク生成箇所で `auth_b_headers`/`auth_b_role` を additive 設定。

## 検証（実行したコマンドと観測結果）

- 新規テスト（`tests/core/agents/swarm/injection/test_cross_account_bola.py`、6 件）: `.venv/bin/pytest tests/core/agents/swarm/injection/test_cross_account_bola.py -q` → **6 passed**。cross-account 確定テストでは `evaluate_payout_grade(finding_payload(finding))` が **payout_grade=True / reason=payout_grade_satisfied / marker=authz_diff** を観測（確定バー無改変のまま確定到達を実証）。
- 回帰: `.venv/bin/pytest tests/core/agents/swarm/test_injection_manager.py tests/core/agents/swarm/injection/ -q` → **683 passed**（非回帰）。関連 `tests/unit/test_sqli_impact_probe.py` / `tests/unit/test_injection_evidence_fields_impact.py` → 30 passed。
- 確定バー 5 ファイル: `git diff --quiet HEAD -- <5ファイル>` → **exit 0（無改変）**。注: 指示の `src/core/agents/swarm/injection/task_queue.py` は存在せず、実パスは `src/core/engine/task_queue.py`（これも exit 0 で確認）。
- denylist（`config/diagnostics/sealed_product_denylist.txt`）: 変更 3 ファイルの追加行＋新規テストファイル全体を case-insensitive grep → **0 件**。
- テストは `tests/fixtures/vdp_authz_multiuser_app/app.py` の実挙動（token-a→200(user-b の資源)・no-token→401・token-b→200／ENFORCE で token-a→403）を recording fake client で忠実に再現し、既存 `_run_api_minimal_check` テストのモックパターン（`test_injection_manager.py`）と settings フラグ上書きパターン（`test_sqli_impact_probe.py`）に倣った。
- ドキュメント: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` 0 エラー（本報告時点で実施）。

## リスク

- 低。新機能は全て flag gate ＋ authB 不在時 no-op で、既存 finding 経路・数値の非回帰を 683 テストで確認済み。authB 配線は `user_sessions` に 2 件以上登録された場合のみ追加の GET probe 1 本（read-only）を発生させる。
- 製品トークン 0 を新規コード／テストで維持（denylist grep 0）。

## 次の一手

- 能力マップ SGK-2026-0465 の IDOR を △→○ に昇格（本タスクで実施）。
- 実走行（マルチセッション設定 authA/authB 登録＋`SHIGOKU_IDOR_CROSS_ACCOUNT_CONFIRM_ENABLED=1`）での E2E 再確認は運用タスクとして追跡（下記 deferred）。

## deferred_tasks

```yaml
deferred_tasks:
  - summary: "unauth probe が Authorization/Cookie のみ剥離する現設計では、X-Auth-Token 等のカスタムヘッダ認証スキームでは未認証プローブが token を保持し auth_boundary_observed が立たない（fail-closed でサイレント・誤検知なし）。カスタムヘッダスキーム対応は unauth ストリップ集合の拡張検討が必要。"
    tracking_task_id: SGK-2026-0468
    blocking: false
  - summary: "実走行（multi_session.enabled＋authA/authB 登録）での cross-account 確定 E2E 再確認（本タスクはモックベース unit で確定経路を実証）。"
    tracking_task_id: SGK-2026-0468
    blocking: false
```
