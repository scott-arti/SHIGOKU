---
task_id: SGK-2026-0325
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/plans/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0321_recon-step-state-resume-diff_subtask_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0326_flexible-report-generation-reinjection_subtask_plan.md
- src/core/conductor/interactive_bridge.py
- src/cli/cli.py
- scripts/shigoku_ops_cli.py
title: 'A: 対話型オペレーション（チャットベース指揮 軽量版）'
created_at: '2026-06-29'
updated_at: '2026-07-02'
tags:
- shigoku
- conversational
- cli
- repl
target: src/core/conductor/interactive_bridge.py, scripts/shigoku_ops_cli.py, src/main.py, src/core/engine/master_conductor.py
---

# 実装計画書：A 対話型オペレーション（チャットベース指揮 軽量版）

> たたき台（ブラッシュアップ前提）。実行中MCへの動的タスク注入（重量版）は次期フェーズとし、本タスクは軽量版（外部LLMエージェントが shigoku-ops をツールとして呼ぶ + NL→指示翻訳）を先行する。

## 1. 達成したいゴール（ユーザー視点）
- [ ] 「2回目は API だけ Fuzz して」「1回目の step3 から再開して」「このワードリストで攻撃して」をチャット/指示ベースで伝えられる。
- [ ] 外部LLMエージェント（opencode 等）が `shigoku-ops --json-envelope` をツール呼び出しする形で、SHIGOKU を対話的に指揮できる。
- [ ] NL（自然言語）の指示を SHIGOKU のコマンド/ターゲット設定/step指定に翻訳して実行できる。
- [ ] Recon step 再開・カスタムワードリスト指定・特定エンドポイント攻撃が CLI/対話から指定できる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `scripts/shigoku_ops_cli.py`: JSON envelope 出力（既存 `shigoku.ops.v1`）の対話向け拡張、`ops run` 相当の実行起点。
  - `src/core/conductor/interactive_bridge.py`: `ask_for_approval()` のみの現状から、指示受付フックへ拡張。
  - `src/main.py`: `--recon-resume`(P0), `--wordlist`, `--attack-targets`(JSON/list) フラグ追加。
  - NL翻訳レイヤ: `src/cli/intent_parser.py`（新設想定）。`LLMClient(role=...)` で NL→コマンド辞書へ。
- **データの流れ / 依存関係:**
  - ユーザ/外部エージェント → NL指示 → intent_parser → `shigoku-ops`/`main.py` コマンド → 実行 → JSON envelope 結果 → 次指示
  - 実行中でない場合はワンショット実行の連鎖で「対話」を構成（軽量版）

## 3. 現状の前提（実装踏まえた評価）
- インターフェースはワンショット CLI のみ。旧 `src/cli/cli.py` の REPL は DEPRECATED（`InteractiveBridgeに移行済み`）。
- `InteractiveBridge` は `ask_for_approval()` の y/n 一 shot のみ。会話ループなし。
- `--recon-start-step`/`--recon-end-step` は既存フラグあり（resume 連動は P0/SGK-2026-0321）。
- HITL（`intervention_policy.py`）はタスク境界の構造化承認（approve/reject/defer）のみ。自由形式会話ではない。
- `shigoku-ops` は `--json --json-envelope` で `schema_version: "shigoku.ops.v1"` の agent 消費 JSON を既に出力可能。
- NL→plan 翻訳は `LLMClient(role=...)` が使える（AGENTS.md §18）。

## 4. 具体的な仕様と制約条件
- **入力情報 (Input):** NL 指示文字列、session/report パス、カスタムワードリスト、attack targets リスト、resume step。
- **出力/結果 (Output):**
  - 実行結果の JSON envelope（次指示のコンテキストとして再利用）
  - intent_parser が生成するコマンド/設定辞書（透明性のため人間確認可能）
- **制約・ルール:**
  - 実行中MCへの動的タスク注入は次期（重量版）。本タスクは「実行起点を対話で決めてワンショット実行を繰り返す」軽量版。
  - 危険操作（攻撃実行、スコープ外）は実行前に intent を人間/HITL で確認。
  - NL翻訳の誤認識対策: 翻訳結果コマンドを必ず表示し確認ステップを挟む。
  - secret を指示文やログに漏らさない（既存 redactor）。

## 5. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `shigoku-ops` の対話起点整理。`report loop` 相当の「次アクション推薦」を JSON envelope で返す仕組みを汎用化（既存 `_build_gate_next_commands` を参考）。
- [ ] ステップ2: `src/main.py` に `--wordlist <path>`, `--attack-targets <json|list>`, `--recon-resume`(P0連動) を追加。
- [ ] ステップ3: `src/cli/intent_parser.py` 新設。`LLMClient(role="ops_intent")` で NL→{command, target, recon_start_step, wordlist, attack_targets, mode} 辞書へ変換。`config/shigoku.yaml` の `llm.roles` に `ops_intent` role を追加。
- [ ] ステップ4: 翻訳結果のコマンドを表示して確認（HITL 相当）→ 実行する lightweight ループを `interactive_bridge` に追加（`--interactive` の dead code を置換）。
- [ ] ステップ5: 外部エージェント向けツール定義（`shigoku-ops` を呼ぶ function-calling schema）を README/仕様に明記。
- [ ] ステップ6: 単体テスト（intent_parser の翻訳、確認フロー）+ 手動対話シナリオ検証。

## 5.1 フェーズ分割
- Phase A: CLI 拡張（wordlist/attack-targets/resume 連動）（ステップ2）
- Phase B: NL intent_parser（ステップ3-4）
- Phase C: 外部エージェント連携定義（ステップ1/5）
- ※ 重量版（実行中MC動的注入）は次期フェーズで別起票

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] 実行中MCへの動的タスク注入はアーキテクチャ変更が必要。本タスクでは扱わず次期フェーズへ。
- [ ] [重要度:高] NL翻訳の誤認識で意図しない攻撃を実行するリスク。必ず翻訳結果を表示し確認ステップを挟む。
- [ ] [重要度:中] 対話の文脈保持。session/report パスを都度明示し、状態は外部エージェント側で持つ設計（SHIGOKU 側はステートレス実行）。
- [ ] [重要度:中] 旧 `src/cli/cli.py` の deprecated REPL は本タスクで削除 or 置換し、混乱を防ぐ。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0325-D01
    title: "継続監視: 実行中MC動的タスク注入（重量版）"
    reason: "アーキテクチャ変更を伴うため次期フェーズ"
    impact: high
    tracking_task_id: SGK-2026-0320
    recommended_next_action: "軽量版の運用知見をもとにMC動的注入の設計を別起票する"
```
