---
task_id: SGK-2026-0351
doc_type: plan
status: active
parent_task_id: SGK-2026-0349
related_docs:
  - src/core/agents/swarm/injection/smart_xss.py
  - config/shigoku.yaml
created_at: 2026-07-10
updated_at: '2026-07-21'
---

# SGK-2026-0351: XSS回帰テスト（SGK-2026-0349 継続監視）

## 目的

smart_xss の rejudge/final モデルを OpenAI (gpt-4o-mini/gpt-4o) から DeepSeek (v4-flash/v4-pro) に切り替えたことによる XSS 判定品質変化を確認する回帰テスト。

## 実施内容

- 既知の XSS 陽性テストケース（最低10件）で修正前後比較
- 既知の XSS 陰性テストケース（最低10件）で修正前後比較
- 判定一致率を算出し、95%未満の場合は要調査
- 必要に応じて `xss_rejudge`/`xss_final` role の provider を openai にフォールバック

## deferred_tasks

| 追跡タスクID | 内容 | 優先度 |
|---|---|---|
| (なし) | | |
