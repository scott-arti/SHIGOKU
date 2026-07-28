---
task_id: SGK-2026-0379
doc_type: work_report
status: done
parent_task_id: SGK-2026-0378
related_docs:
- docs/shigoku/plans/done/2026-07-23_sgk-2026-0379_dvwa-low-finding-regression-recovery_plan.md
- docs/shigoku/worklogs/2026-07-23_sgk-2026-0379_dvwa-low-finding-regression-recovery_work_log.md
title: DVWA low finding regression recovery work report
created_at: '2026-07-23'
updated_at: '2026-07-28'
---

# 作業報告書：DVWA low finding regression recovery

## 実装内容
- 旧83件runと最新55件runを `extract_all_findings()` で比較し、SCN08〜12の手動停止を除外した検知退行候補を特定した。
- `src/core/engine/master_conductor.py` で `cors_candidate` を InjectionSwarm の攻撃カテゴリとして扱うようにした。
- Signal-first task生成時に `/vulnerabilities/exec/` 系URLを見た場合、`Command Injection Focused Scan` companion task を追加するようにした。
- Signal-first / legacy supplement task生成時に `/vulnerabilities/weak_id/` 系URLを見た場合、`Session Weak-ID Analysis` companion task を追加するようにした。
- Signal-first / legacy supplement の Stored XSS候補に対して、DVWA `xss_s` の `txtName` / `mtxMessage` を `_context.candidate_params` として渡すようにした。
- 回帰テストを `tests/core/engine/test_master_conductor_signal_recipe_routing.py` に追加した。

## 判断理由
- 最新55件では `cors_candidate` が DiscoverySwarm fallback に落ち、CORS specialist が起動していなかった。
- 最新55件では `/exec/` が汎用Injectionタスクにだけ流れ、旧83件でfindingを出した `Command Injection Focused Scan` が作られていなかった。
- 最新55件では `/weak_id/` がAuth系タスクに流れ、旧83件でfindingを出した SessionHijacker task が作られていなかった。
- 最新55件の `/xss_s/` タスクは実行されていたが、試行パラメータが `page` / `redirect` / `id` / `doc` になっており、旧83件で有効だったStored XSS用フォーム名が渡っていなかった。

## 検証
- RED:
  - `.venv/bin/pytest tests/core/engine/test_master_conductor_signal_recipe_routing.py -q -k "cors_supplement or signal_companions or stored_xss_param_hints"`
  - 結果: 3 failed。CORSがDiscoverySwarm、companion taskなし、`_context`なしで期待どおり失敗。
- GREEN:
  - `.venv/bin/pytest tests/core/engine/test_master_conductor_signal_recipe_routing.py -q -k "cors_supplement or signal_companions or stored_xss_param_hints"`
  - 結果: 3 passed。
- 関連テスト:
  - `.venv/bin/pytest tests/core/engine/test_master_conductor_signal_recipe_routing.py -q`
  - 結果: 26 passed。
  - `.venv/bin/pytest tests/core/engine/test_master_conductor_signal_recipe_routing.py tests/core/engine/test_injection_ownership_dedup.py tests/core/agents/swarm/injection/test_target_classifier.py tests/core/agents/swarm/injection/test_manager_classification_character.py -q`
  - 結果: 65 passed。
- 構文チェック:
  - `PYTHONPYCACHEPREFIX=<tmp> .venv/bin/python -m py_compile src/core/engine/master_conductor.py tests/core/engine/test_master_conductor_signal_recipe_routing.py`
  - 結果: pass。
- 実アーティファクト確認:
  - `.venv/bin/shigoku-ops --json report consistency --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260717_222441.md`
  - 結果: consistent。
  - `.venv/bin/shigoku-ops --json report consistency --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260723_043315.md`
  - 結果: consistent。
  - `python3 scripts/verify_report_session_consistency.py --report ...` でも両方 consistent。

## 残っているリスク
- 実DVWA再実行は未実施。次回 `docker compose run --rm` のrunでfinding復元を確認する必要がある。
- `tests/core/engine/test_master_conductor_api_candidate_routing.py -q` は4件失敗したが、失敗理由は今回の修正対象ではない既存の compiled guard `policy_unavailable` ブロックだった。
- Graphify update はAST抽出後、質問生成処理が長時間化したため中断した。
- 既存のdocs検証には `SGK-2026-0258` の欠落ファイルによる台帳不整合が残っている。

## 次のステップ
- 次回DVWA low runで、以下のfinding種別が戻るか確認する。
  - `os_command_injection` on `/vulnerabilities/exec/`
  - `cors_misconfiguration` on `/vulnerabilities/api/v2/user/`
  - `session_fixation` on `/vulnerabilities/weak_id/`
  - `xss` on `/vulnerabilities/xss_s/`

deferred_tasks: []
