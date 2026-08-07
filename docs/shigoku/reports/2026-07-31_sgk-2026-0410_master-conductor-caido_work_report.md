---
task_id: SGK-2026-0410
doc_type: work_report
status: done
parent_task_id: SGK-2026-0409
related_docs:
- docs/shigoku/subtasks/done/2026-07-31_master-conductor-caido_subtask_plan.md
- src/core/engine/master_conductor.py
- tests/core/engine/test_master_conductor_caido_preflight.py
- workspace/projects/localhost:3000/reports/haddix_report_20260731_141807.md
- workspace/projects/localhost:3000/sessions/session_interrupted_20260731_141807.json
- docs/shigoku/worklogs/2026-07-31_sgk-2026-0410_master-conductor-caido_work_log.md
created_at: '2026-07-31'
updated_at: '2026-08-07'
---

# 作業報告：Master Conductor 内部事前チェックへの Caido 設定伝播修正

## 実施内容

- Master Conductor 内部の通常実行とresumeで重複していた `PreflightContext` 生成を共通化した。
- 共通生成処理から `settings.caido.url` と `settings.caido.token` を必ず渡すようにした。
- tokenは `target_info` やsessionへ保存せず、実行時設定からだけ取得する設計を維持した。
- 通常生成、resume、`execute_with_replan()` の実呼び出しを確認する回帰テストを追加した。

## 判断理由

外側の事前チェックは `127.0.0.1:8081` とtokenで成功していましたが、Master Conductor内部がCaido設定を渡さず、`PreflightContext` の既定値 `8080`・tokenなしへ戻っていたためです。

## 検証

- 修正前: 新規回帰テスト2件が `AttributeError` で失敗し、未実装状態を確認した。
- `docker compose run --rm --no-deps -w /app --entrypoint python3 shigoku -m pytest tests/core/engine/test_master_conductor_caido_preflight.py tests/unit/preflight/test_caido_check.py tests/core/engine/test_mc_injection_parallel_dispatch.py tests/core/engine/test_master_conductor_recipe_contracts.py -q`
- 結果: 60 passed。
- `/usr/bin/python3 scripts/shigoku_ops_cli.py report consistency --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:3000/reports/haddix_report_20260731_141807.md`
- 結果: `status=consistent`、`rerun_required=False`、`reason_codes=[]`。

## 残るリスク

- 修正後の実Caido接続を使った全スキャン再実行は、利用者側の新しいtokenで確認する必要がある。
- 広めの既存テストでは、今回と無関係な `tests/core/engine/test_mc_strategic_upgrade.py` の古い設定モックと事前チェック未モックにより2件失敗した。
- 文書全体の検証には、今回と無関係な既存台帳の参照切れ2件が残る。

## 次のステップ

同じDockerコマンドを再実行し、Master Conductor起動後の事前チェックも `127.0.0.1:8081` とtokenありになることを確認する。
