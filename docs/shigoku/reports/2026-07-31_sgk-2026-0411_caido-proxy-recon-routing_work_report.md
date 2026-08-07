---
task_id: SGK-2026-0411
doc_type: work_report
status: done
parent_task_id: SGK-2026-0410
related_docs:
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0411_caido-proxy-recon-routing_subtask_plan.md
- src/core/swarm/worker/recon_workers.py
- docker-compose.yml
- tests/core/swarm/worker/test_recon_workers.py
- docs/shigoku/manuals/manual_legacy/2026-07-02_sgk-2026-0338_operator-user-manual.md
- docs/shigoku/worklogs/2026-07-31_sgk-2026-0411_caido-proxy-recon-routing_work_log.md
created_at: '2026-07-31'
updated_at: '2026-08-07'
deferred_tasks: []
---

# 作業報告：Caidoプロキシへの初回偵察通信伝播修正

## 実施内容

- 初回偵察の `DiscoveryWorker` が Katana へ `settings.scan.proxy` を渡すようにした。
- `LiveCheckWorker` も HTTPX へ同じプロキシ設定を渡すようにした。
- Docker Compose がホストの `SHIGOKU_SCAN__PROXY` をコンテナへ引き継ぐようにした。
- Caido API用URLと、HTTP History記録用プロキシが別設定であることを運用マニュアルへ明記した。

## 判断理由

`SHIGOKU_CAIDO__URL` はGraphQL APIの接続確認にしか使われません。さらに初回偵察Workerは、別途設定できる `scan.proxy` をKatana/HTTPXへ渡していなかったため、対象へのHTTP通信がCaidoを迂回していました。

## 検証

- 修正前: 新規回帰テスト2件が、Workerにプロキシ設定参照が存在しない理由で失敗した。
- `docker compose run --rm --no-deps --workdir /app --entrypoint python3 shigoku -m pytest -q tests/core/swarm/worker/test_recon_workers.py tests/core/recon/test_recon_orchestrator.py`
- 結果: 4 passed。
- `SHIGOKU_SCAN__PROXY=http://127.0.0.1:8081 docker compose run --rm --no-deps --workdir /app --entrypoint python3 shigoku -c 'from src.core.config.settings import settings; print(settings.scan.proxy)'`
- 結果: コンテナ内で `http://127.0.0.1:8081` を確認した。

## 残るリスク

- 実際のCaidoプロキシリスナーのポートは利用者のCaido設定に依存する。
- NaabuはTCPポート探索であり、CaidoのHTTP Historyには表示されない。
- 実Caidoの履歴表示は、利用者側でスキャンを再実行して確認する必要がある。

## 次のステップ

`SHIGOKU_CAIDO__URL` と `SHIGOKU_SCAN__PROXY` の両方を `http://127.0.0.1:8081` に設定して、同じDockerコマンドを再実行する。
