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
updated_at: '2026-07-21'
tags:
- shigoku
- conversational
- cli
- repl
target: src/core/conductor/interactive_bridge.py, scripts/shigoku_ops_cli.py, src/main.py, src/core/engine/master_conductor.py
---

# 実装計画書：A 対話型オペレーション（チャットベース指揮 軽量版）

> たたき台（ブラッシュアップ前提）。SGK-2026-0326 と同じ束で扱うが、完全統合までは行わない。0325 は「入力側」として、外部LLMエージェント/オペレータの自然言語指示を CLI 実行へつなぐ軽量導線を担当する。実行中MCへの動的タスク注入（重量版）は次期フェーズとし、本タスクは外部LLMエージェントが `shigoku-ops` をツールとして呼ぶ + NL→指示翻訳を先行する。

## 1. 達成したいゴール（ユーザー視点）
- [ ] 「2回目は API だけ Fuzz して」「1回目の step3 から再開して」「このワードリストで攻撃して」をチャット/指示ベースで伝えられる。
- [ ] 外部LLMエージェント（opencode 等）が `shigoku-ops --json-envelope` をツール呼び出しする形で、SHIGOKU を対話的に指揮できる。
- [ ] NL（自然言語）の指示を SHIGOKU のコマンド/ターゲット設定/step指定に翻訳して実行できる。
- [ ] Recon step 再開・カスタムワードリスト指定・特定エンドポイント攻撃が CLI/対話から指定できる。
- [ ] SGK-2026-0326 が出力した structured target file / endpoint list を、そのまま次回実行の入力として受け渡せる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `scripts/shigoku_ops_cli.py`: JSON envelope 出力（既存 `shigoku.ops.v1`）の対話向け拡張。SGK-2026-0326 と共有する CLI / 運用導線の中核。
  - `src/core/conductor/interactive_bridge.py`: 既存のセッション起点・承認フックを活かしつつ、指示受付と確認ループを軽量追加。
  - `src/main.py`: 既存 `--recon-resume` を前提に、`--wordlist`, `--attack-targets`(JSON/list) など不足している入力フラグを追加。
  - NL翻訳レイヤ: `src/cli/intent_parser.py`（新設想定）。`LLMClient(role=...)` で NL→コマンド辞書へ。
- **データの流れ / 依存関係:**
  - ユーザ/外部エージェント → NL指示 → intent_parser → `shigoku-ops`/`main.py` コマンド → 実行 → JSON envelope 結果 → 次指示
  - SGK-2026-0326 の出力（endpoint list / attack target file）→ 本タスクの入力 (`--attack-targets` 等) → 攻撃/分析実行
  - 実行中でない場合はワンショット実行の連鎖で「対話」を構成（軽量版）。出力生成そのものは SGK-2026-0326 に寄せる。

## 3. 現状の前提（実装踏まえた評価）
- `--interactive` と `InteractiveBridge` は既に存在し、preflight / ProjectManager / MasterConductor 起動の橋渡しは実装済み。旧 `src/cli/cli.py` の REPL は DEPRECATED（`InteractiveBridgeに移行済み`）。
- `InteractiveBridge` は承認ダイアログに加え、recipe/plan ベースのタスク起動までは担っているが、自由形式の会話ループや NL→コマンド翻訳は未実装。
- `--recon-start-step`/`--recon-end-step`/`--recon-resume` は既存フラグあり。resume 解決も実装済みで、本タスクでは不足している入力面（wordlist / attack target 受け）を補う。
- HITL（`intervention_policy.py`）はタスク境界の構造化承認（approve/reject/defer）のみ。自由形式会話ではない。
- `shigoku-ops` は `--json --json-envelope` で `schema_version: "shigoku.ops.v1"` の agent 消費 JSON を既に出力可能。
- `shigoku-ops` には `report loop` / `session resolve-from-report` 等の運用補助 CLI があり、0326 の出力側と共有する導線として再利用可能。
- NL→plan 翻訳は `LLMClient(role=...)` が使える（AGENTS.md §18）。

## 4. 具体的な仕様と制約条件
- **入力情報 (Input):** NL 指示文字列、session/report パス、カスタムワードリスト、attack targets リスト、resume step。
- **出力/結果 (Output):**
  - 実行結果の JSON envelope（次指示のコンテキストとして再利用）
  - intent_parser が生成するコマンド/設定辞書（透明性のため人間確認可能）
- **制約・ルール:**
  - 0325 は「入力側」の兄弟タスクであり、自由形式レポート生成やテンプレート設計そのものは SGK-2026-0326 側の責務とする。
  - 実行中MCへの動的タスク注入は次期（重量版）。本タスクは「実行起点を対話で決めてワンショット実行を繰り返す」軽量版。
  - 危険操作（攻撃実行、スコープ外）は実行前に intent を人間/HITL で確認。
  - NL翻訳の誤認識対策: 翻訳結果コマンドを必ず表示し確認ステップを挟む。
  - 逆投入入力は SGK-2026-0326 が出力する structured target file を正本とし、任意 Markdown の自由解析は初期スコープに含めない。
  - secret を指示文やログに漏らさない（既存 redactor）。

## 5. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: SGK-2026-0326 と共有する CLI / 運用導線の契約を整理。`session/report` 解決方法、`attack-targets` ファイル形式、JSON envelope の最小フィールドを明文化する。
- [ ] ステップ2: `src/main.py` / `InteractiveBridge` に不足している入力経路を追加。既存 `--recon-resume` を前提に、`--wordlist <path>` と `--attack-targets <json|list|file>` を受けて MC 実行へ渡す。
- [ ] ステップ3: `src/cli/intent_parser.py` 新設。`LLMClient(role="ops_intent")` で NL→{command, target, recon_start_step, wordlist, attack_targets, report_or_session, mode} 辞書へ変換。`config/shigoku.yaml` の `llm.roles` に `ops_intent` role を追加。
- [ ] ステップ4: 翻訳結果のコマンドを表示して確認（HITL 相当）→ 既存 `start_interactive_session()` / `shigoku-ops` 呼び出しへ接続する lightweight ループを追加する。既存ブリッジを置換するのではなく拡張する。
- [ ] ステップ5: 外部エージェント向けツール定義（`shigoku-ops` を呼ぶ function-calling schema）と、SGK-2026-0326 の出力 artifact を入力に再利用する運用例を README/仕様に明記。
- [ ] ステップ6: 単体テスト（intent_parser の翻訳、確認フロー）+ 手動対話シナリオ検証。

## 5.1 フェーズ分割
- Phase A: shared CLI 契約整理 + 入力拡張（ステップ1-2）
- Phase B: NL intent_parser + 確認ループ（ステップ3-4）
- Phase C: 外部エージェント連携定義（ステップ5）
- ※ 重量版（実行中MC動的注入）は次期フェーズで別起票

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] 実行中MCへの動的タスク注入はアーキテクチャ変更が必要。本タスクでは扱わず次期フェーズへ。
- [ ] [重要度:高] NL翻訳の誤認識で意図しない攻撃を実行するリスク。必ず翻訳結果を表示し確認ステップを挟む。
- [ ] [重要度:中] 0326 側の出力契約と 0325 側の入力契約がズレると運用導線が壊れる。shared schema の最小版を先に固定する。
- [ ] [重要度:中] 対話の文脈保持。session/report パスを都度明示し、状態は外部エージェント側で持つ設計（SHIGOKU 側はステートレス実行）。
- [ ] [重要度:低] 旧 `src/cli/cli.py` の deprecated REPL は本タスクの主目的ではないため、整理は別変更として切り出す方が安全。

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
