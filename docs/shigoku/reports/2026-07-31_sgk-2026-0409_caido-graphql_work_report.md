---
task_id: SGK-2026-0409
doc_type: work_report
status: done
parent_task_id: SGK-2026-0408
related_docs:
- docs/shigoku/subtasks/done/2026-07-31_caido-graphql_subtask_plan.md
- src/core/preflight/caido_check.py
- tests/unit/preflight/test_caido_check.py
- docs/shigoku/worklogs/2026-07-31_sgk-2026-0409_caido-graphql_work_log.md
created_at: '2026-07-31'
updated_at: '2026-08-07'
---

# 作業報告：Caido GraphQL 転送対応と事前チェック接続先表示修正

## 実施内容

- Caido の identity 確認、GraphQL 確認、base URL 確認で HTTP 転送を明示的に追従するようにした。
- `CAIDO_IDENTITY_UNVERIFIED` のエラー文が固定の `8080` ではなく、設定 URL のポートを表示するようにした。
- 転送追従と実ポート表示の回帰テストを追加した。

## 判断理由

Caido が `/graphql` を `/graphql/` へ転送する環境で事前チェックが停止しないようにし、実際の接続先と異なるポートを表示しないためです。

## 検証

- `docker compose run --rm --no-deps -w /app --entrypoint python3 shigoku -m pytest tests/unit/preflight/test_caido_check.py -q`
- 結果: 53 passed。
- 実 Caido への接続は token の再発行後に利用者が行うため、本タスクでは実施していない。

## 残るリスク

- 文書全体の検証には、今回と無関係な既存台帳の参照切れ2件が残る。

## 次のステップ

利用者は新しい Caido token を設定した後、同じ Docker 実行を再試行する。
