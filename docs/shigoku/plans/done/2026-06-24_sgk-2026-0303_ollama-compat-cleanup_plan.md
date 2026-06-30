---
task_id: SGK-2026-0303
doc_type: plan
status: done
parent_task_id: SGK-2026-0292
related_docs:
  - docs/shigoku/reports/2026-06-24_SGK-2026-0292_work_report.md
  - docs/shigoku/reports/2026-06-24_SGK-2026-0303-D02_work_report.md
  - docs/shigoku/worklogs/2026-06-24_SGK-2026-0303-D02_work_log.md
created_at: '2026-06-24'
updated_at: '2026-06-24'
tags:
  - shigoku
  - llm
  - ollama-removal
  - deferred
---

# Ollama互換層除去・flat config整理・prompt動的化 計画

SGK-2026-0292 (Ollama廃止とLLM設定統一) の deferred_tasks 継続タスク。

## D01: Ollama互換層の完全削除
- `src/core/llm/local_provider.py` (LocalLLMProvider, TaskComplexityClassifier) の削除
- `src/core/gpu_accelerator.py` の Ollama メソッド群削除
- `src/core/llm/__init__.py` の `__all__` 更新
- `src/core/models/llm.py` の `_init_local_provider` / `_should_use_local` 削除

## D02: flat LLM config field 削除 (done)
- [x] `src/config.py` の `local_llm_*`, `model_lightweight`, `model_output`, `llm_fallback_model` 削除
- [x] `src/core/config/settings.py` の同様の field を deprecated 化
- [x] `src/core/config/llm_resolver.py` の `build_legacy_profile_mapping()` 削除
- [x] `tests/core/test_llm_config.py` のレガシーテスト削除

## D03: SYSTEM_PROMPT 動的レンダリング対応
- 各 injection agent の `{placeholder}` を Jinja2 `{{ placeholder }}` に変更
- `PromptRenderer.render(template, context)` で解決するよう移行

## D04: 残存 hardcode system prompt の template 化
- `src/core/engine/master_conductor.py:6529` → `attack_suggester` role (template作成済)
- `src/core/preflight/ai_classifier.py:51/205` → `response_classifier` role (template作成済)  
- `src/core/agents/swarm/biz_logic_hunter.py:397` → `vuln_validator` role (template作成済)
- `src/core/intelligence/chain_proposal.py:85/199` → `chain_proposer` role (template作成済)
- `src/core/engine/conductor_prompts.py:6` → conductor系 template
- role と template は config/shigoku.yaml と src/prompts/roles/ に配置済み
