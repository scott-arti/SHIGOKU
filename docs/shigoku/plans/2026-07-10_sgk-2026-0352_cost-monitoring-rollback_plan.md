---
task_id: SGK-2026-0352
doc_type: plan
status: active
parent_task_id: SGK-2026-0349
related_docs:
  - src/main.py
  - config/shigoku.yaml
created_at: 2026-07-10
updated_at: '2026-07-21'
---

# SGK-2026-0352: コストモニタリングとロールバック計画（SGK-2026-0349 継続監視）

## 目的

MasterConductor を v4-pro に切り替えたことによる API コスト影響を 1 週間モニタリングし、問題発生時の即時切り戻し手順を整備する。

## 実施内容

- コスト試算: 現行 (v4-flash) vs 移行後 (v4-pro) の推定トークン数×単価差分
- 1週間のコストモニタリング（想定比 +50% 超過で自動アラート）
- ロールバック計画: `SHIGOKU_MC_MODEL_ROLE=specialist_light` で即時切り戻し
- 判断基準: コスト +50%、エラーレート +10%、脆弱性検出数 -20%
- docker-compose の具体的切り戻し手順を文書化

## deferred_tasks

| 追跡タスクID | 内容 | 優先度 |
|---|---|---|
| (なし) | | |
