---
task_id: SGK-2026-0354
doc_type: plan
status: deferred
parent_task_id: SGK-2026-0350
related_docs: []
created_at: 2026-07-10
updated_at: '2026-07-21'
---

# SGK-2026-0354: ReAct JSON化（A案）+ パーサー全面書き換え

Phase 4 deferred task from SGK-2026-0350.

## 目的

全マネージャー/スペシャリストのアクション形式をJSON構造化に移行し、パーサーを `json.loads` + フォールバックに置き換える。

## 背景

現在のReActパーサーはテキストベースの `Thought: / Action: tool(args)` フォーマットをAST+正規表現で解析している。フォーマット崩れでパース失敗が連続し、`max_turns=5` 到達によるsilent failureが発生するリスクがある。

## スコープ

1. 全マネージャー/スペシャリストのアクション形式をJSON構造化に移行
2. `_parse_llm_output` を `json.loads` ベースに書き換え（テキストフォールバック付き）
3. Phase1-3のB案ルール（`[DEPRECATED]`コメント箇所）を削除

## 参照

- 親タスク: SGK-2026-0350 (System Prompt Optimization)
- B案ルール箇所: `src/prompts/agents/manager_base.md` (Jinja2コメント `[DEPRECATED with Phase4 JSON migration]`)
