---
task_id: SGK-2026-0298
doc_type: plan
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/specs/visibility_and_metrics.md
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/plans/2026-06-08_sgk-2026-0268_haddix-report-payout-readiness-output-improvements_plan.md
- docs/shigoku/subtasks/done/2026-06-24_sgk-2026-0299_run-ledger-llm-usage-session-persistence_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-24_sgk-2026-0300_run-narrative-target-profile-markdown_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-24_sgk-2026-0301_haddix-ja-en-paired-report_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-24_sgk-2026-0302_attack-path-markdown-neo4j-prep_subtask_plan.md
title: SHIGOKU 内部挙動可視化・ガバナンス出力 実装計画
created_at: '2026-06-24'
updated_at: '2026-07-02'
tags:
- shigoku
target: MC/Swarm observability, reports, target profile, attack paths
---

# 実装計画書：SHIGOKU 内部挙動可視化・ガバナンス出力 実装計画

## 1. 達成したいゴール（ユーザー視点）
- [ ] SHIGOKU実行後、ユーザーが「どのAI/Swarm/ツールが、何を根拠に、何を実行し、どう失敗/成功し、次に何を判断したか」をMarkdownで追えること。
- [ ] 実行ごとのLLM Input / Output / InputCacheトークン、タスク試行履歴、失敗理由、再試行、HITL、Finding生成までをセッション一次証跡として保存できること。
- [ ] ターゲット概要、機能、URL/API/ページ数、脆弱性仮説、攻撃面、次回シナリオ入力を `target_profile.md` として残せること。
- [ ] Haddixレポートは日本語理解用セクションと企業提出用英語セクションを併記し、英語提出部分の品質を落とさないこと。
- [ ] 攻撃パスはまずMarkdown/Mermaidで可視化し、Neo4j/UI連携は後段で拡張できる契約にすること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/models/decision_trace.py`: 既存。MC判断の入力、選択肢、選択理由、結果の基礎モデル。
  - `src/core/models/task_execution_log.py`: 既存。タスク実行履歴、結果、脆弱性、エラーの基礎モデル。
  - `src/core/utils/audit_logger.py`: 既存。JSONL監査ログの基礎モデル。
  - `src/core/engine/master_conductor_session_service.py`: 修正候補。session payloadに判断・行動・usage証跡を永続化する。
  - `src/core/engine/swarm_dispatcher.py`: 修正候補。MC -> Swarm委譲、Swarm結果、execution_logの境界イベントを記録する。
  - `src/reporting/haddix_formatter.py`: 修正候補。日本語併記版Haddix出力を追加する。
  - `scripts/shigoku_ops_cli.py`: 修正候補。`report narrative`、`report target-profile`、`report attack-paths` のCLI入口を追加する。
  - `src/reporting/`: 新規/修正。Run Narrative、Target Profile、Attack Path、JA/EN report formatterを配置する。
  - `tests/unit/reporting/`、`tests/core/engine/`: 新規/修正。formatterとsession永続化の回帰を固定する。
- **データの流れ / 依存関係:**
  - MC/Swarm/Tool/LLM実行 -> `run_ledger` events -> `session_*.json` / optional JSONL spool -> Markdown formatter -> `run_narrative.md`, `target_profile.md`, `attack_paths.md`, `haddix_report_ja_en.md`
  - 一次証跡はJSON/JSONL、ユーザー向け出力はMarkdownとする。安価なAI整形を使う場合も、source event idを保持し一次証跡との対応を失わない。
  - 実装順は S1 -> S2 -> S3 -> S4 とする。S2-S4はS1のsession/ledger契約を読む側として実装する。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - `session_*.json`: completed_tasks, context, findings, scenario_coverage, coverage_gate, pending_hitl, new run_ledger / llm_usage fields
  - `AuditLogger` JSONL: tool/request/finding/error/config events
  - `DecisionTracer`: decision_id, decision_type, input_context, selected_option, reasoning, outcome
  - `TaskExecutionLog`: task_id, agent_type, action, target_url, result, error, duration, metadata
- **出力/結果 (Output):**
  - `run_ledger` / `llm_usage_summary` がセッションに保存される。
  - `run_narrative.md`: 時系列の判断・行動・結果・次判断を日本語で説明する。
  - `target_profile.md`: ターゲット概要と次回シナリオ入力を保存する。
  - `haddix_report_ja_en.md`: 日本語サマリー + 英語提出用レポートを併記する。
  - `attack_paths.md`: Finding/Endpoint/Task/Decisionの攻撃パスをMarkdown/Mermaidで表示する。
- **制約・ルール:**
  - report/session consistency gateの原則を守り、提供されたreport pathがある場合は必ず対応sessionを一次情報とする。
  - セッションschemaは破壊せず、追加フィールドで拡張する。
  - prompt全文、秘密情報、認証情報、Cookie、トークン、生レスポンスは既存マスキング規約に従って保存・表示する。
  - Markdownは人間向けの説明であり、raw証跡と区別する。推定やbackfillは明示する。
  - Neo4j/UIはS4で契約までに留め、初期実装はMarkdown/Mermaidを優先する。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: S1でRun Ledger、LLM usage、session永続化契約を実装し、既存session互換を保つ。
- [ ] ステップ2: S2で `run_narrative.md` と `target_profile.md` のformatter/CLIを実装する。
- [ ] ステップ3: S3でHaddix JA/EN併記出力を追加し、既存英語Haddix出力とconsistency parserを壊さないことを確認する。
- [ ] ステップ4: S4で攻撃パスMarkdown/Mermaid出力を実装し、Neo4j export用の最小ノード/エッジ契約を定義する。
- [ ] ステップ5: 実セッション/実レポートがある場合は、consistency checker -> narrative/profile/report/path生成 -> gate関連テストの順に検証する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] ログ量が増えすぎるとsessionが肥大化する。 - S1で保持上限、要約、JSONL spoolへの逃がし方を決める。
- [ ] [重要度:高] LLM整形が一次証跡にない説明を混ぜる可能性がある。 - `source_event_ids` と `inference_level` を必須にする。
- [ ] [重要度:中] Haddix日本語併記が提出用英語本文にノイズを混ぜる可能性がある。 - 英語提出セクションを明確に分離し、既存Haddix互換テストを残す。
- [ ] [重要度:中] Neo4j/UIを先に作ると実装範囲が膨らむ。 - 初期はMarkdown/Mermaidを正本にし、Neo4jはexport契約までに留める。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0298-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
