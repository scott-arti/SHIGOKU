---
task_id: SGK-2026-0401
doc_type: work_report
status: done
parent_task_id: null
related_docs:
  - docs/shigoku/plans/done/2026-07-29_llm-provider-endpoint-explicit-configuration-and-legacy-routing-removal_plan.md
  - config/shigoku.yaml
  - src/core/models/llm.py
created_at: '2026-07-29'
updated_at: '2026-08-07'
---

# SGK-2026-0401 作業報告

## 実施内容

- DeepSeekとOpenAIの接続先URLをLLM設定へ明示した。
- Thinkingの設定を`extra.thinking`へ統一し、値をSHIGOKU側で変換せずプロバイダーへ渡すようにした。Cheap profileは`type: disabled`と`reasoning_effort: null`を明示した。
- 役割なしのLLMClientはYAMLの既定roleを使うようにし、環境変数モデルのフォールバックを削除した。
- XSS再判定・最終判定を`xss_rejudge`・`xss_final` roleへ移行した。

## 検証

- `venv/bin/pytest tests/core/test_llm_config.py tests/core/llm/test_llm_client.py tests/core/agents/swarm/injection/test_smart_xss_logic.py -q` : 68 passed。
- `venv/bin/pytest tests/core/test_llm_config.py tests/core/llm/test_llm_client.py tests/unit/config/test_legacy_settings_parallelism_bridge.py tests/core/test_phase4_regression.py -q` : 81 passed。

## リスク

- ドキュメント全体の既存リンク切れと台帳不整合は本タスクの変更前から残っており、別途修復が必要。
