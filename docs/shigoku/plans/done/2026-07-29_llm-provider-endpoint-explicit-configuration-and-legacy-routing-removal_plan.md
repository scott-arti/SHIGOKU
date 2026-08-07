---
task_id: SGK-2026-0401
doc_type: plan
status: done
parent_task_id: null
related_docs:
- config/shigoku.yaml
- src/core/models/llm.py
title: LLM provider endpoint explicit configuration and legacy routing removal
created_at: '2026-07-29'
updated_at: '2026-08-07'
tags:
- shigoku
target: config/shigoku.yaml and role-based LLM routing
---

# 実装計画書：LLM provider endpoint explicit configuration and legacy routing removal

## 1. 達成したいゴール（ユーザー視点）
- [x] `config/shigoku.yaml` だけを見れば、役割ごとのモデル、APIキー環境変数、接続先URL、Thinking設定を確認・変更できること。
- [x] モデル名から外部ライブラリが接続先を推測する経路と、`deepseek-chat` / `SHIGOKU_MODEL` に依存する実行経路を廃止すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `config/shigoku.yaml`, `config/shigoku.yaml.example`: provider endpoint、profile、roleの正本。
  - `src/core/config/settings.py`: provider schemaの検証。
  - `src/core/models/llm.py`: role解決、endpoint伝播、Thinkingリクエスト生成。
  - `src/core/agents/swarm/injection/smart_xss.py`: XSS再判定・最終判定をroleで選択。
- **データの流れ / 依存関係:**
  - `role` -> `profile` -> `provider (model, api_key_env, base_url)` -> LiteLLM
- **データの流れ / 依存関係:**
  - [入力元] -> [処理] -> [保存/表示先]

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** YAMLのrole/profile/provider設定。
- **出力/結果 (Output):** 明示されたURL・APIキー・モデル・Thinking設定でのLiteLLMリクエスト。
- **制約・ルール:**
  - APIキー値はYAMLに保存せず、`api_key_env`だけを保存する。
  - すべてのproviderは明示的なHTTPS endpointを持つ。ローカルproxyだけHTTPを許容する。
  - `reasoning_effort` は `extra.thinking.reasoning_effort` のみを正本とする。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: provider schemaとYAMLを明示endpoint・role設定へ更新する。
- [x] ステップ2: LLMClientの既定roleとThinking payloadを設定から解決する。
- [x] ステップ3: XSSの再判定・最終判定を専用roleへ移行し、直接モデル切替を削除する。
- [x] ステップ4: 設定・クライアントの単体テスト、設定読込、ドキュメント検証を実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] 役割化されていないAgentConfigの表示用`model`属性 - 実際のLLM呼び出し経路を確認後、別タスクで削除する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0401-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
