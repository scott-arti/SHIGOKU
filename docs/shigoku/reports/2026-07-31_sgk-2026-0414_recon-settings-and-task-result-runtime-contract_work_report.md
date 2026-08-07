---
task_id: SGK-2026-0414
doc_type: work_report
status: done
parent_task_id: null
related_docs:
- docs/shigoku/plans/done/2026-07-31_sgk-2026-0414_recon-settings-and-task-result-runtime-contract_plan.md
- src/recon/pipeline.py
- src/core/engine/master_conductor.py
- src/core/config/settings.py
- tests/recon/test_recon_pipeline_proxy_gate.py
- tests/core/engine/test_master_conductor_phase5_parallelism.py
- docs/shigoku/worklogs/2026-07-31_sgk-2026-0414_recon-settings-and-task-result-runtime-contract_work_log.md
created_at: '2026-07-31'
updated_at: '2026-08-07'
deferred_tasks: []
---

# 作業報告：Recon設定型と並列結果正規化の実行時例外修正

## 実施内容

- 偵察開始時のプロキシ解決を、Pydantic設定を辞書として読む方法から、設定の正本である `Settings.get_proxy_url()` の呼び出しへ置き換えた。
- 並列実行後の後処理で、`ParallelOrchestrator.TaskResult.result`、従来の辞書結果、旧互換用の `data` 辞書を明示的に正規化してから保留後処理を読むようにした。
- `ScanSettings` と実際の `TaskResult` を使った回帰テストを追加した。修正前は利用者の実行ログと同じ二つの `AttributeError` で失敗することを確認した。

## 判断理由

これは Juice Shop や `/#/` のURL形式に固有の問題ではない。設定と実行結果を「辞書」と仮定していたのに、実行時にはそれぞれPydanticモデルとデータクラスが渡されていたことが原因である。

プロキシの優先順位、プロキシ必須時の到達性確認、従来の辞書結果の扱いは変更していない。アプリ名・URL・検出結果を条件にする例外処理も追加していない。

## 検証

- `venv/bin/pytest -q tests/recon/test_recon_pipeline_proxy_gate.py tests/core/engine/test_master_conductor_phase5_parallelism.py`
  - 結果: 32件成功。
- `venv/bin/pytest -q tests/recon/test_recon_pipeline_proxy_gate.py tests/recon/test_parallel_base.py tests/recon/test_step3b_hybrid_url.py tests/core/engine/test_master_conductor_phase5_parallelism.py tests/core/engine/test_master_conductor_recon_nonblocking.py tests/core/engine/test_master_conductor_recon_step_range.py tests/core/engine/test_master_conductor_caido_preflight.py tests/unit/config/test_caido_proxy_resolution.py`
  - 結果: 62件成功、既存の無関係な失敗が2件。
  - `tests/recon/test_parallel_base.py::TestReconPipeline::test_semaphore_custom`: テストは `recon.max_concurrent_tasks` を設定するが、既存実装は `scan.max_concurrent_tasks` を読むため不一致。
  - `tests/core/engine/test_master_conductor_recon_nonblocking.py::test_recon_master_dispatch_uses_to_thread_for_isolated_pipeline`: テストがプログラム・バンドル未設定で事前検査に入り、`active_bundle_missing` で停止。
- `graphify update .`
  - 結果: コード関係図を更新。既存グラフデータの `source_file` 欠落警告が1件あるが、変更した実行経路には影響しない。
- `venv/bin/python -m compileall -q ...`
  - 結果: 既存の `__pycache__` 書込権限により実行できなかった。テスト実行時のPython読込みと対象テストは成功している。
- 実ターゲットへの通信・再実行は、利用者から今回明示的な依頼がないため行っていない。

## 残るリスク

- 実アプリでの再実行は未実施である。次回は、偵察の開始後にこの二つの型エラーが出ず、偵察結果を後処理できることを確認する。
- 周辺テストの2失敗は今回の差分より前からある別件であり、今回の変更では修正していない。
- 台帳全体には、今回と無関係な古い欠落参照が2件あるため、全体文書検証が完全成功にならない可能性がある。

## 次のステップ

利用者が対象の再実行を行う場合は、同じ設定で実行し、`ScanSettings object has no attribute get` と `TaskResult object has no attribute get` が出ないことを確認する。
