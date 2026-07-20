---
task_id: SGK-2026-0355
doc_type: plan
status: deferred
parent_task_id: SGK-2026-0350
related_docs: []
created_at: 2026-07-10
updated_at: '2026-07-21'
---

# SGK-2026-0355: プロンプトバージョニングシステム

Phase 4 deferred task from SGK-2026-0350.

## 目的

各プロンプトテンプレートにメタデータ（version, last_updated）を付与し、A/Bテストを可能にするバージョニングシステムを構築する。

## 背景

現在のプロンプトテンプレートにはバージョン管理の仕組みがない。プロンプト変更の効果測定や安全なロールバックのために、バージョニングが必要。

## スコープ

1. 各プロンプトファイルにメタデータヘッダーを標準化（version, last_updated, author）
2. プロンプトバージョンを管理するレジストリの構築
3. A/Bテストフレームワーク（role単位でプロンプトバージョンを切り替え可能にする）

## 参照

- 親タスク: SGK-2026-0350 (System Prompt Optimization)
- フォールバック機構: `src/core/config/llm_resolver.py` (`SHIGOKU_PROMPT_FALLBACK` env var, Step 0-1)
