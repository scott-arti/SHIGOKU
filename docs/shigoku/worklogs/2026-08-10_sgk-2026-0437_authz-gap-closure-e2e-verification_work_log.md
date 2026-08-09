---
task_id: SGK-2026-0437
doc_type: work_log
status: done
parent_task_id: SGK-2026-0433
related_docs:
- docs/shigoku/plans/done/2026-08-10_sgk-2026-0437_authz-gap-closure-e2e-verification_plan.md
- docs/shigoku/reports/2026-08-10_sgk-2026-0437_authz-gap-closure-e2e-verification_work_report.md
created_at: '2026-08-10'
updated_at: '2026-08-10'
tags:
- shigoku
- anti-curve-fitting
---

# 作業ログ: SGK-2026-0437（authz gap-closure エンドツーエンド実証）

## 実施内容

1. **preflight**: env file（0600・名前のみ確認）/ ターゲット稼働 / marker 不在 /
   PCR-P1（task_queue.py diff 0）を確認。
2. **所有権 fix**: 最初に main runner へ `--user` を適用 → 実測で
   `PermissionError: /.shigoku`（非rootユーザーで FindingsRepository の
   Path.home() が / に解決）により起動失敗。`--user` を revert し、
   0436 の代替案である **run 後 chown** を採用。find ベース chown は
   root 所有ファイルに権限不足で効かず、恒久対策として phase 8b を
   **docker コンテナ経由 chown（alpine・root 実行）** に置き換え。
3. **run 実行**: 封印 m3a harness を1回実行（exit 0・session
   session_20260809_212541.json 生成）。auth-setup（A/B register/login）
   は成功（digest のみログ出力）。
4. **phase 9 リプレイ**: バックグラウンド実行の都合で phase 9 が run 内で
   完了しなかったため evaluate_m5.py を手動実行（rc=0・first_failure /
   external_audit 生成）。
5. **判定**: (II) 能力は動いたが越境なし。ev-87cbedb909e33a28 で
   cross_account_compared=true / second_account_compared=true /
   request_count=2 だが owner_record_accessible_to_non_owner=false →
   authz_impact_proven なし → 正しく hold。
6. **検証**: consistency gate consistent / preflight pass exit 0 /
   PCR-P1 diff 0 / redaction 0件 / docs validator 0 / 成果物 bbb 読取可。
7. **ハーネス修正**: phase 8b の chown 対象に haddix_report/haddix_gate/
   haddix_deferred を追加（初回 run では haddix_report が root 所有のままで
   読めず、docker 経由 chown で復旧した穴を恒久化）。

## 観測メモ

- run_stdout に `PCR-P1: VDP follow-up drain (task_queue mutation) must be on
  main thread` の critical failure が task_002 で1件。authz 比較 follow-up
  は別経路で実行され evidence 記録済み（判定に影響なし）。SGK-2026-0431 へ追跡。
- gate check fail（confirmed 0 の honest 結果）。閾値・Validator は不変。

## 成果物

- session: workspace/projects/localhost:3000/sessions/session_20260809_212541.json
- report: workspace/projects/localhost:3000/reports/haddix_report_20260809_212541.md
- evaluator: /tmp/opencode/m5-out/first_failure_juiceshop_v1.json
- session env: /tmp/opencode/m5-out/session_env.txt（0600 bbb）
