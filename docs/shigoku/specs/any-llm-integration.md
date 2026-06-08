---
task_id: SGK-2026-0105
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 機能仕様書: Any-LLM (Proxy Gateway) の導入

## 1. 概要

SHIGOKUの `LLMClient` のバックエンドとして、Mozilla.ai の `any-llm` プロキシゲートウェイを導入し、統合的なメトリクス収集とコスト管理を可能にする。

## 2. 変更範囲

- `src/core/models/llm.py`
  - `litellm` の `api_base` を設定からオーバーライドできるように修正。
- `src/core/config/settings.py` (設定機能)
  - `ANY_LLM_BASE_URL` および `ANY_LLM_API_KEY` の設定項目読み込みを追加。

## 3. 挙動

- 設定にて `ANY_LLM_BASE_URL`（例: `http://localhost:8000/v1` 等）が有効な場合、`litellm.completion()` / `acompletion()` 呼び出し時に `api_base` および `api_key` 引数をプロキシのものへ上書きしてルーティングする。
- 設定がない場合、またはローカルLLMを指定している場合は従来通りのエンドポイント（OpenAI等）を直接利用する。
- ツール呼び出し（Function Calling）や非同期処理、その他の `litellm` 依存機能は一切の変更なく動作する。

## 4. 制約

- **EthicsGuard との整合性**: 既存の PII Masking や `EthicsGuard` の機能は LLM 呼び出しの実装（通信）の*手前*で処理されるため、この変更による安全機構への影響はない。
- **アーキテクチャの維持**: 今回の変更はインフラ/モデル層のみの微細な調整であり、`MasterConductor` や配下のエージェント(`Specialists`)側のプロンプト、インターフェース設計に変更を一切加えない。
