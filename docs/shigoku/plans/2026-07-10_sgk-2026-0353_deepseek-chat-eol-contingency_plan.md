---
task_id: SGK-2026-0353
doc_type: plan
status: active
parent_task_id: SGK-2026-0349
related_docs:
  - src/core/models/llm.py
  - docker-compose.yml
created_at: 2026-07-10
updated_at: '2026-07-21'
---

# SGK-2026-0353: deepseek-chat 廃止コンティンジェンシー（SGK-2026-0349 継続監視）

## 目的

deepseek-chat 廃止デッドライン（2026-07-24）に備え、7/20 時点で SGK-2026-0349 の進捗を確認し、未完了の場合は最小限ホットフィックスを緊急デプロイする。

## 実施内容

- 2026-07-20 時点で SGK-2026-0349 Step 0〜7（P0 相当）の進捗を確認
- 未完了の場合:
  - `llm.py:88`/`498`/`701` の `deepseek-chat` → `deepseek-v4-flash` への置換のみ
  - `SHIGOKU_MODEL` env 参照は `deepseek-v4-flash` にフォールバック
  - role 追加、model="default" 修正、smart_xss リファクタリングは後続タスクに切り離し
- ホットフィックス用の独立 SGK タスクを事前に定義

## deferred_tasks

| 追跡タスクID | 内容 | 優先度 |
|---|---|---|
| (なし) | | |
