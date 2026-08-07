---
task_id: SGK-2026-0412
doc_type: work_report
status: done
parent_task_id: SGK-2026-0411
related_docs:
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0412_caido-url-proxy-fallback_subtask_plan.md
- src/core/config/settings.py
- src/core/intel/caido_crawler.py
- tests/unit/config/test_caido_proxy_resolution.py
- docs/shigoku/manuals/manual_legacy/2026-07-02_sgk-2026-0338_operator-user-manual.md
- docs/shigoku/worklogs/2026-07-31_sgk-2026-0412_caido-url-proxy-fallback_work_log.md
created_at: '2026-07-31'
updated_at: '2026-08-07'
deferred_tasks: []
---

# 作業報告：Caido明示URLの実通信プロキシ適用修正

## 実施内容

- `SHIGOKU_SCAN__PROXY` が未設定でも、明示された `SHIGOKU_CAIDO__URL` を実通信プロキシとして使うようにした。
- 明示的な `SHIGOKU_SCAN__PROXY` がある場合は、従来どおり最優先する。
- `CaidoCrawler` も共通のプロキシ解決結果を使うようにした。
- マニュアルから不要になった二重設定を削除した。

## 判断理由

Caidoログでは `127.0.0.1:8081 (Proxy, UI)` と確認できた。一方、SHIGOKUはPreflightだけが `caido.url` を読み、実通信は空の `scan.proxy` を読んでいたため、Preflight成功後のHTTP通信が直接接続になっていた。

## 検証

- 修正前: Caido URLのフォールバックとCaidoCrawlerのテスト2件が失敗した。
- `docker compose run --rm --no-deps --workdir /app --entrypoint python3 shigoku -m pytest -q tests/unit/config/test_caido_proxy_resolution.py tests/core/swarm/worker/test_recon_workers.py tests/core/recon/test_recon_orchestrator.py tests/recon/test_step3b_hybrid_url.py`
- 結果: 9件成功。
- `SHIGOKU_SCAN__PROXY` を未設定にし、`SHIGOKU_CAIDO__URL=http://127.0.0.1:8081` だけを渡したDocker確認で、`settings.caido.url` と `settings.get_proxy_url()` の両方が8081になった。

## 残るリスク

- 実際の対象通信を送る確認は行っていない。利用者の許可済み対象で再実行してCaido HTTP Historyを確認する必要がある。
- NaabuのTCPポート探索はCaidoのHTTP Historyには表示されない。

## 次のステップ

既存の `SHIGOKU_CAIDO__URL=http://127.0.0.1:8081` とtokenだけで同じDockerコマンドを再実行し、Katana以降のHTTP通信をCaidoで確認する。
