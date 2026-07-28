---
task_id: SGK-2026-0384
doc_type: work_report
status: done
parent_task_id: SGK-2026-0383
related_docs:
- docs/shigoku/plans/done/2026-07-24_sgk-2026-0384_runtime-no-waste-guards-for-localhost-scanner-and-cors-phase2_plan.md
- docs/shigoku/worklogs/2026-07-24_sgk-2026-0384_runtime-no-waste-guards-for-localhost-scanner-and-cors-phase2_work_log.md
created_at: '2026-07-24'
updated_at: '2026-07-28'
title: Runtime no-waste guards for localhost scanner and CORS Phase2 work report
---

# 作業報告書：Runtime no-waste guards for localhost scanner and CORS Phase2

## 実装内容

- `MasterConductor._resolve_asset_scan_url()` を追加し、発見assetが現在のtargetと同じホストなら、targetのschemeとportを引き継ぐようにした。
- `MasterConductor._expand_plan_for_assets()` の `web_scanner.params["url"]` を固定の `https://{asset}` から、解決済みscan URLへ変更した。
- `InjectionManagerAgent.dispatch()` に `cors_no_signal_safe_skip` を追加し、CORSのみのPhase1結果が無信号なら、APIパス由来のhigh-risk Phase2強制を解除するようにした。
- 上記2件の赤テストを追加し、修正後に緑になることを確認した。

## 判断理由

- `session_20260723_162936.json` では `scan_localhost_51` が `https://localhost` を対象に約192秒消費し、結果は `No response.` だった。実行targetは `http://localhost:4280/` なので、同一ホストassetではtargetのscheme/portを使う方が正しい。
- 同じセッションで CORS scan はPhase1の実チェックが0.844秒で完了し、findingなし・weak signalなし・tool errorなしだったが、その後Phase2 timeoutで約125秒消費していた。CORSはヘッダー検査で成立有無を判断するため、無信号時にLLM Phase2へ進む根拠が薄い。
- XSSは今回未実装。時間ではなく、入力欄・URLパラメータ・fragment/hash参照・DOM/HTML到達経路の有無を判断軸にする必要があるため、別設計に分けた。

## 検証

- `.venv/bin/pytest tests/core/agents/swarm/test_injection_manager.py::test_phase2_safe_skip_quiet_cors_on_api_endpoint tests/core/engine/test_master_conductor_api_candidate_routing.py::test_expand_plan_for_localhost_asset_reuses_context_target_scheme_and_port`
  - RED: 修正前は2件失敗
  - GREEN: 修正後 `2 passed`
- `.venv/bin/pytest tests/core/agents/swarm/test_injection_manager.py::test_phase2_safe_skip_quiet_xss tests/core/agents/swarm/test_injection_manager.py::test_phase2_safe_skip_quiet_cors_on_api_endpoint tests/core/agents/swarm/test_injection_manager.py::test_phase2_proceed_xss_with_post tests/core/agents/swarm/test_injection_manager.py::test_phase2_proceed_api_candidate tests/core/agents/swarm/test_injection_manager.py::test_phase2_shadow_only_proceeds tests/core/engine/test_master_conductor_api_candidate_routing.py::test_expand_plan_for_localhost_asset_reuses_context_target_scheme_and_port tests/core/engine/test_master_conductor_api_candidate_routing.py::test_create_attack_tasks_routes_api_candidate_to_injection_swarm`
  - `7 passed`
- `PYTHONPYCACHEPREFIX=<tmp> .venv/bin/python -m py_compile src/core/engine/master_conductor.py src/core/agents/swarm/injection/manager.py`
  - 成功
- `python3 scripts/shigoku_ops_cli.py --json report consistency --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260723_162936.md`
  - `status: consistent`, `rerun_required: false`
- `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260723_162936.md`
  - `status: consistent`, `rerun_required: false`

## リスク

- CORSのPhase2抑止は、CORS専用チェックがfindingなし・weak signalなし・tool errorなしの場合だけに限定した。CORS検査自体がエラーや弱い兆候を出した場合は従来通り深掘り余地が残る。
- `https://localhost` 抑止は、asset hostが現在のtarget hostと一致する場合だけscheme/portを引き継ぐ。別ホストassetは従来通り `https://` defaultを維持する。
- `graphify update .` と `graphify update . --no-cluster` はAST抽出後、既存グラフの比較/クラスタ処理で長時間停止したため中断した。
- 既存のdocs validationには、今回とは無関係な `task_268_missing_file:docs/shigoku/subtasks/2026-06-03_sgk-2026-0258_temporal-followup_subtask_plan.md` が残っている。

## deferred_tasks

deferred_tasks: []
