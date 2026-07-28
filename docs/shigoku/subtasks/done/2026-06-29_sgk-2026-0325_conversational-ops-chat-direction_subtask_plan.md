---
task_id: SGK-2026-0325
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/plans/done/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
- docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0321_recon-step-state-resume-diff_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0326_flexible-report-generation-reinjection_subtask_plan.md
- src/core/conductor/interactive_bridge.py
- src/cli/cli.py
- scripts/shigoku_ops_cli.py
title: 'A: 対話型オペレーション（チャットベース指揮 軽量版）'
created_at: '2026-06-29'
updated_at: '2026-07-28'
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
- `InteractiveBridge` は承認ダイアログに加え、recipe/plan ベースのタスク起動までは担っている。`shigoku-ops ops intent` と `src/cli/intent_parser.py` により NL→allowlist command の preview/confirmation loop は実装済みだが、実行中MCへの重量版会話ループは未実装。
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
- [x] ステップ1: SGK-2026-0326 と共有する CLI / 運用導線の契約を整理する。`IntentCommand` の allowlist、`attack-targets` の参照方法、`correlation_id`, `reason_codes`, `manifest_hash` を含む JSON envelope 最小フィールドを先に固定する。
- [x] ステップ2: 入力側の安全策を先に固定する。`llm_parse_timeout_sec`, `command_timeout_sec`, `retry_budget`, `max_attack_targets_per_run`, `non_tty_policy`, `kill_switch`, `feature_flag`, `daily_llm_budget` を定義し、attack 系指示では `observe` を既定にしない方針を明記する。
- [x] ステップ3: `src/main.py` / `InteractiveBridge` に不足している入力経路を追加する。既存 `--recon-resume` を前提に、`--wordlist <path>` と `--attack-targets <json|list|file>` を受け、scope 検証済みデータだけを MC 実行へ渡す。
- [x] ステップ4: `src/cli/intent_parser.py` を新設し、`LLMClient(role="ops_intent")` で NL→{command, target, recon_start_step, wordlist, attack_targets, report_or_session, mode} の構造化辞書へ変換する。shell 文字列は生成せず、未許可コマンドは reject する。
- [x] ステップ5: 翻訳結果のコマンドを表示して確認（HITL 相当）し、承認後のみ既存 `start_interactive_session()` / `shigoku-ops` 呼び出しへ接続する lightweight ループを追加する。non-TTY では attack 系実行を fail-closed または dry-run 限定にする。
- [x] ステップ6: 外部エージェント向けツール定義（`shigoku-ops` を呼ぶ function-calling schema）と、SGK-2026-0326 の出力 artifact を入力に再利用する運用例を README/仕様へ明記する。
- [x] ステップ7: 単体テストと手動対話シナリオ検証を追加する。`malformed intent`, `unknown command`, `approval deny`, `non-TTY`, `scope外 target`, `timeout`, `kill_switch on` の失敗系も必ず含める。

進捗メモ（2026-07-21）:
- `ops intent` preview は real report artifact で確認済み。
- `docs/shigoku/manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md` に `ops intent` の function-calling schema、approval / retry / kill-switch 運用、`0326` artifact 再利用例を追記済み。
- `ops intent --execute --approve --main-dry-run` により export → main 呼び出しの限定実行を確認済み。
- failure 系では `unknown command` / `non-TTY` に加えて、`approval deny` / `timeout` / `kill_switch on` / `scope外 target` の回帰テストを追加済み。
- `malformed intent` の end-to-end と、LLM fallback 初期化失敗時の `intent_llm_unavailable` fail-closed を追加済み。
- real TTY で `shigoku-ops ops intent --execute --main-dry-run` を実行し、preview 表示後の `Execute it? [y/N]` 承認を通して `report.export-targets -> main.attack-targets` の限定実行を確認し、Step 7 を完了。

## 5.1 フェーズ分割
- Phase A: shared CLI 契約整理 + 安全策固定（ステップ1-2）
- Phase B: 入力拡張 + NL intent_parser + 確認ループ（ステップ3-5）
- Phase C: 外部エージェント連携定義 + 検証（ステップ6-7）
- ※ 重量版（実行中MC動的注入）は次期フェーズで別起票

## 6. 懸念点と対策 / 既知のリスク
### 6.1 懸念点と対策
- [ ] [視点:SRE/インフラ][発生確率:高][影響度:大] 対話ループに timeout や target 数上限がないと、誤指示やループ不具合で長時間実行が止まらない。
  対策: `llm_parse_timeout_sec`, `command_timeout_sec`, `retry_budget`, `max_attack_targets_per_run`, `kill_switch` を plan の必須設定として先に固定する。
- [ ] [視点:ソフトウェアアーキテクト][発生確率:高][影響度:中] `0325` が parser、確認UI、bridge拡張、実行本体まで抱えすぎると責務がぼやける。
  対策: `0325` は parse / confirm / dispatch に責務を限定し、実行本体は既存 `start_interactive_session()` と `shigoku-ops` 再利用を原則にする。
- [ ] [視点:デバッガー][発生確率:高][影響度:中] どの NL 指示がどの command preview と実行結果に対応するか追えないと、障害調査が難しい。
  対策: `correlation_id`, `intent_hash`, `reason_codes`, `report_or_session`, `manifest_hash` を preview / envelope / log に必須で残す。
- [ ] [視点:ハッカー][発生確率:高][影響度:大] NL 出力を shell 文字列へ落とす設計だと、意図しないコマンド実行や注入リスクが高い。
  対策: parser は allowlist 済みの構造化 command だけを返し、未許可コマンド・自由文字列の shell 実行は禁止する。
- [ ] [視点:ハッカー][発生確率:中][影響度:大] non-TTY や `observe` モードで attack 系実行が自動承認されると、安全境界が弱い。
  対策: attack 系 intent では `enforce_human_preferred` 以上を既定とし、non-TTY は fail-closed または dry-run 限定にする。
- [ ] [視点:CTO][発生確率:中][影響度:中] lightweight 導線でも feature flag や予算上限がないと、運用開始後に止めにくい。
  対策: feature flag, daily LLM budget, rollout 停止条件を実装後ではなく Phase A で決める。

### 6.2 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] 実行中MCへの動的タスク注入はアーキテクチャ変更が必要。本タスクでは扱わず次期フェーズへ。
- [ ] [重要度:高] NL翻訳の誤認識で意図しない攻撃を実行するリスク。必ず翻訳結果を表示し確認ステップを挟む。
- [ ] [重要度:中] 0326 側の出力契約と 0325 側の入力契約がズレると運用導線が壊れる。shared schema の最小版を先に固定する。
- [ ] [重要度:中] 対話の文脈保持。session/report パスを都度明示し、状態は外部エージェント側で持つ設計（SHIGOKU 側はステートレス実行）。
- [ ] [重要度:低] 旧 `src/cli/cli.py` の deprecated REPL は本タスクの主目的ではないため、整理は別変更として切り出す方が安全。

### 6.3 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0325-D01
    title: "継続監視: 実行中MC動的タスク注入（重量版）"
    reason: "アーキテクチャ変更を伴うため次期フェーズ"
    impact: high
    tracking_task_id: SGK-2026-0320
    recommended_next_action: "軽量版の運用知見をもとにMC動的注入の設計を別起票する"
```
