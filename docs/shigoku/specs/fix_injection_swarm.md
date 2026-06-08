---
task_id: SGK-2026-0122
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 仕様書: InjectionSwarm (InjectionManagerAgent) の正常化

## 1. 概要
SHIGOKU のインジェクション検知を司る `InjectionSwarm` (InjectionManagerAgent) が、タスクを受け取っても何も実行しない問題を修正します。
調査の結果、LLM 駆動の Phase 2 において、実行可能なツールがエージェントに登録されていないことが判明しました。

## 2. 変更範囲
- `src/core/agents/swarm/injection/manager.py`: 
    - `__init__` 内で Specialist を LLM ツールとして登録する処理を追加。
    - `dispatch` ロジックで Phase 1 の知見を Phase 2 の LLM に引き継ぐように修正。
- `src/core/agents/swarm/injection/smart_xss.py` (および他):
    - エージェント単体としての instructions（プロンプト）のロード不備を再確認し、必要なら修正。

## 3. 具体的な挙動の修正
### 3.1 ツール登録の追加
`InjectionManager` の初期化時に、以下のツールを `available_tools` に登録します。
- `sqli_scan`: SQL インジェクションスキャンの実行
- `xss_scan`: XSS スキャンの実行
- `lfi_scan`: LFI スキャンの実行
- `open_redirect_scan`: オープンリダイレクトスキャンの実行
- `cmd_ssrf_scan`: OSコマンド/SSRFスキャンの実行

### 3.2 コンテキストの連携
Phase 1 (Deterministic) で発見された「反射パラメータ」や「興味深いターゲット」のリストを、Phase 2 のシステムプロンプトまたは初期メッセージに注入し、LLM が効率的に探索を開始できるようにします。

## 4. 制約と整合性
- `src/core/security/ethics_guard.py`: 各スキャン実行前に必ずスコープチェックを継続。
- `shigoku_architecture`: `BaseManagerAgent` の構造を逸脱せず、オーケストレーション機能を最大化する。

## 5. 検証プラン
1. ユニットテスト: `InjectionManager` の `available_tools` が正しく埋まっているか確認。
2. 統合テスト: ローカルの脆弱なエンドポイントに対して `InjectionSwarm` を走らせ、LLM がツールを呼び出すログを確認。
