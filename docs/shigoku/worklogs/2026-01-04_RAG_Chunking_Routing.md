---
task_id: SGK-2026-0201
doc_type: work_log
status: done
parent_task_id: null
related_docs: []
created_at: '2026-01-04'
updated_at: '2026-05-19'
---

2026-01-04 | Enhancement | RAG Header-Based Chunking | `rag.py`改修: Markdown を見出し(#, ##)単位で分割しベクトル化精度向上
2026-01-04 | Feature | Model Routing | コスト最適化: 軽量タスク(ReAct/Critic)と高精度タスク(Report)でモデルを使い分け
2026-01-04 | Configuration | Model Routing | `config.py`に`model_lightweight`, `model_output`設定追加(デフォルト: Ollama/qwen3:8b)
2026-01-04 | Documentation | Docs Sync | CHANGELOG, README, TECHNICAL_SPEC, MANUAL に新機能(RAG Chunking, Model Routing)を追記
