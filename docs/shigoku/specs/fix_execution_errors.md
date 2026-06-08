---
task_id: SGK-2026-0121
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 仕様書: 実行時エラーとタイムアウトの修正

## 概要

ユーザーから提供された実行ログにて、ツール不在（Subjack）、外部サービス認証失敗（GitHub MCP）、ノイズ出力のパースエラー（Katana）、非同期実行時の全体タイムアウトなどが同時に発生し、正常な機能評価や進行を妨げていることが判明した。本機能修正は、各コンポーネントが例外を適切に捕捉およびリトライ・スキップすることで、SHIGOKUエンジンの堅牢性を引き上げることを目的とする。

## 変更範囲

- `src/recon/pipeline.py`
- `src/core/agents/swarm/discovery/github_recon.py`
- `src/core/agents/swarm/base_manager.py`
- `src/core/agents/swarm/discovery/takeover.py`
- `src/core/engine/parallel_orchestrator.py`
- `src/core/engine/master_conductor.py`

## 挙動

- **Katana パースエラー**: Katana が不要な情報で出力を汚染した場合に、ログの `ERROR` レベルが `DEBUG` レベルに抑制され、無視して処理を進める。
- **GitHub MCP エラー**: クレデンシャル（Bad credentials）の理由による例外は、処理自体を "skip" とみなし、エージェントをクラッシュさせずに優雅に終了させる。
- **ベースマネージャーのリトライ**: 「LLMが空の応答を返す」事象に対し直ちに処理を打ち切るのではなく、`max_turns` に達するまで思考ループの中で追加プロンプトを与えてリトライをさせる。
- **サブジャック未インストール**: `TakeoverSpecialist` 実行時、`subjack` バイナリが見つからない場合はエラー終了せず、スキャンを放棄してログだけ残す。
- **タイムアウト緩和**: 外部ツールを多数起動するタスクの完了を見据え設定タイムアウト値を60秒/300秒から1800秒に拡張し、`TimeoutError` での大規模クラッシュを防ぐ。

## 制約

- `EthicsGuard` のスコープ外リクエスト検証には影響を及ぼさない。
- `MasterConductor` の再帰的計画や `ParallelOrchestrator` のイベントループライフサイクルを阻害しないこと。
