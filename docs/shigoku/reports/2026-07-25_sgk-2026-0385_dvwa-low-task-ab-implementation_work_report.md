---
task_id: SGK-2026-0385
doc_type: work_report
status: active
parent_task_id: SGK-2026-0379
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
- docs/shigoku/subtasks/done/2026-07-25_dvwa-low-expected-detection-matrix_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-25_dvwa-low-regression-finding-restoration_subtask_plan.md
- docs/shigoku/worklogs/2026-07-25_sgk-2026-0385_dvwa-low-task-ab-implementation_work_log.md
created_at: '2026-07-25'
updated_at: '2026-07-28'
title: DVWA low Task A/B implementation work report
---

# 作業報告書：DVWA low Task A/B implementation

## 実装内容

- Task A として、DVWA low の期待検知マトリクスを `src/reporting/expected_detection_matrix.py` にコード化した。
- マトリクスには `実アプリ妥当性`、`期待レベル`、`必要 evidence`、`confirmed 条件`、`DVWA 固有なら対象外にできる条件` を持たせた。
- Task B として、canonical extractor 由来の finding set を `vuln_type + title + normalized target URL` で比較する機能を追加した。
- `shigoku-ops report expected-detections` を追加し、整合性確認済み report/session だけを期待検知表と比較できるようにした。
- `shigoku-ops report compare-findings` を追加し、過去 run と現在 run の finding 漏れを report/session 整合性確認後に比較できるようにした。
- Task B の復旧実装として、signal-first / history replay で戻った authz URL を BizLogic の `AuthZ Differential Check` companion にも流すようにした。
- AuthSwarm の SCN07 手動方針は維持し、IDOR/BAC として自動検査できる対象だけを BizLogic に分けた。
- Open Redirect は `redirect_param` の per-target 展開が維持されることを regression test で固定した。
- `shigoku-ops report expected-detections` の JSON に、整合性確認で解決した session path を表示するようにした。
- 既存の authbypass / weak_id / open_redirect / SQLi 関連テストを実行し、既存復旧経路が壊れていないことを確認した。

## 判断理由

- ユーザー方針として、DVWA 固有の教材機能へ合わせるカーブフィッティングは避ける必要がある。
- そのため、スキャナ本体へ DVWA path special case を増やすのではなく、まず report-side の評価ロジックとして「実アプリにもありえる検知が足りているか」を判断できる形にした。
- weak_id は `?id=2` という DVWA 固有の形だけで必須判定せず、予測可能 ID や ID 改ざんがセッション・権限・データ露出へ繋がるかで評価する。
- authbypass と open_redirect は実アプリでも成立する脆弱性なので、直近 run で不足している場合に不足として見える化する。
- 107 tasks run の authbypass は、当日の signal bundle から欠け、history replay 後の fallback auth タスクが token trust boundary として手動 deferred されていた。これは「人手方針」ではなく、自動でよい authz 差分検査の経路落ちなので修正対象とした。
- Open Redirect は、redirect パラメータ付き URL が検出器へ渡るなら成立確認できる。現在ソースでは per-target 展開が有効なため、再発防止テストで固定した。

## 実レポートでの確認

- `haddix_report_20260717_222441.md`, `haddix_report_20260723_162936.md`, `haddix_report_20260724_164750.md` は `verify_report_session_consistency.py` で `consistent`。
- `haddix_report_20260724_164750.md` に対する `expected-detections` では、現時点で次が不足として見える。
  - required: `authbypass_idor`, `file_upload`
  - conditional: `open_redirect_control`, `brute_force_controls`, `captcha_validation`, `csp_policy`
- `haddix_report_20260723_162936.md` と `haddix_report_20260724_164750.md` の `compare-findings` では、open_redirect と authbypass 系の漏れを検出できる。
- 修正後の小型再現では、当日 signal が `weak_id` のみで、前日 history に `authbypass/` がある場合でも、`http://localhost:4280/vulnerabilities/authbypass/get_user_data.php?id=2` の BizLogic companion task が生成されることを確認した。

## 検証

- `.venv/bin/pytest tests/unit/reporting/test_expected_detection_matrix.py -q`
  - RED: `src.reporting.expected_detection_matrix` 未実装で import error
  - GREEN: `4 passed`
- `.venv/bin/pytest tests/unit/scripts/test_shigoku_ops_expected_detection_cli.py -q`
  - RED: `expected-detections` / `compare-findings` サブコマンド未実装
  - GREEN: `2 passed`
- `.venv/bin/pytest tests/unit/reporting/test_expected_detection_matrix.py tests/unit/scripts/test_shigoku_ops_expected_detection_cli.py -q`
  - `6 passed`
- `.venv/bin/pytest tests/recon/test_authbypass_replay_enrichment.py tests/core/agents/swarm/test_auth_manager.py -q`
  - `10 passed`
- `.venv/bin/pytest tests/core/agents/swarm/test_injection_manager.py -q`
  - `52 passed`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_signal_recipe_routing.py::test_create_attack_tasks_from_recon_replays_authz_history_as_bizlogic_companion -q`
  - RED: BizLogic companion が生成されず失敗
  - GREEN: `1 passed`
- `.venv/bin/pytest tests/unit/reporting/test_expected_detection_matrix.py tests/unit/scripts/test_shigoku_ops_expected_detection_cli.py tests/core/engine/test_master_conductor_signal_recipe_routing.py::test_create_attack_tasks_from_recon_replays_authz_history_as_bizlogic_companion tests/core/engine/test_master_conductor_signal_recipe_routing.py::test_create_attack_tasks_from_recon_uses_context_mode_for_legacy_supplement_guard -q`
  - `8 passed`
- `.venv/bin/pytest tests/recon/test_authbypass_replay_enrichment.py tests/core/agents/swarm/test_auth_manager.py tests/core/agents/swarm/test_injection_manager.py tests/core/engine/test_master_conductor_signal_recipe_routing.py -q`
  - `89 passed`
- `.venv/bin/python scripts/shigoku_ops_cli.py --json report expected-detections --report workspace/projects/localhost:4280/reports/haddix_report_20260724_164750.md`
  - `status=ok`, `source.session=workspace/projects/localhost:4280/sessions/session_20260724_164750.json`
- `.venv/bin/python scripts/shigoku_ops_cli.py --json report compare-findings --baseline-report workspace/projects/localhost:4280/reports/haddix_report_20260723_162936.md --report workspace/projects/localhost:4280/reports/haddix_report_20260724_164750.md`
  - `status=ok`, `missing_in_current_count=3`

## リスク

- 直近の既存 session の finding 内容そのものは変わらない。次回 DVWA low run で `authbypass_idor` と `open_redirect_control` が戻るか確認が必要。
- `file_upload` は Task D の範囲であり、本作業では復旧対象外。
- `brute_force_controls`, `captcha_validation`, `csp_policy` は Task E の範囲であり、実アプリ妥当性が低い場合は reason-coded non-finding / 対象外でよい。
- 既存の docs validation には、今回とは無関係な `task_268_missing_file:docs/shigoku/subtasks/2026-06-03_sgk-2026-0258_temporal-followup_subtask_plan.md` が残っている。
