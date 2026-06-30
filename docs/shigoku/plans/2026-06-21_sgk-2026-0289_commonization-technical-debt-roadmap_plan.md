---
task_id: SGK-2026-0289
doc_type: plan
status: active
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/plans/2026-06-05_sgk-2026-0264_master-conductor-split-plan_plan.md
- docs/shigoku/plans/2026-06-05_sgk-2026-0265_injection-manager-split-plan_plan.md
title: SHIGOKU共通化・技術的負債返済ロードマップ
created_at: '2026-06-21'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/core, src/cli, src/recon, src/intelligence
---

# 実装計画書：SHIGOKU共通化・技術的負債返済ロードマップ

## 1. 達成したいゴール（ユーザー視点）
- [ ] SHIGOKUのモジュール開発で重複した処理を段階的に共通化し、機能追加時の修正漏れ・挙動差分・テスト重複を減らすこと。
- [ ] 大規模リファクタを一度に行わず、サブプラン単位で安全に進められる継続タスクにすること。
- [ ] 共通化してよいもの、してはいけないものを切り分け、過度な抽象化で開発速度を落とさないこと。
- [ ] MasterConductor分割、InjectionManager分割、CLI分割、ReconPipeline再設計と衝突しない順序で進めること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/`: orchestration、queue、planning、retry、decision、event連携の重複整理。
  - `src/core/agents/swarm/`: Swarm manager/specialist 間の実行・finding・handoff・rate-limit 共通化。
  - `src/core/llm/` / `src/core/models/llm.py`: LLM provider、model routing、fallback、local/cloud差分の共通化。
  - `src/core/notifications/`: 通知文面・送信・batch制御の共通化。
  - `src/core/adapters/` / `src/core/adapters/external/`: 外部ツール実行、timeout、stderr処理、schema化の共通化。
  - `src/reporting/` / `src/core/reports/`: finding/session/report整形ロジックの責務境界整理。
  - `src/cli/` / `src/main.py`: CLI entrypoint、オプション定義、ユーザー向け表示の共通化。
- **データの流れ / 依存関係:**
  - 棚卸し -> 重複クラスタ分類 -> 優先度付け -> サブプラン起票 -> 小さな抽出 -> 互換層維持 -> テスト/実セッション確認。
  - 共通化対象は「同じ責務で同じ入力/出力にできるもの」だけに限定する。
  - 既存の巨大ファイル分割計画を先行または並行し、責務境界が見えた単位から共通化する。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `rg`/graphifyによる重複候補、テストカバレッジ、変更頻度、バグ履歴、既存計画書、実セッションの失敗傾向。
- **出力/結果 (Output):** 共通化候補一覧、優先度、サブプラン、抽出済み共通モジュール、互換層、回帰テスト。
- **制約・ルール:**
  - 一度に広範囲を置換しない。1サブプラン1責務、1PR/1作業単位で完結できる粒度にする。
  - 既存の public API、session/report schema、CLI option は原則後方互換を維持する。
  - security testing の挙動差分が出る箇所は、抽象化より明示性を優先する。
  - 共通化前に必ず reader/search を行い、schema field や artifact field を削除・改名しない。
  - 外部ツールラッパーは `src/core/adapters/external/*_adapter.py` の配置規則を守る。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 重複棚卸しを行う。候補軸は LLM呼び出し、外部ツール実行、通知、Finding生成、Task生成、retry/timeout、JSON parsing、rate limiting、session/report整形。
- [ ] ステップ2: 候補ごとに「共通化価値」「変更リスク」「既存テスト」「依存範囲」「先行タスク」を評価し、優先順位を付ける。
- [ ] ステップ3: サブプランを起票する。初期候補は LLM model routing、通知formatter、外部tool executor、Task/Finding factory、Swarm execution contract。
- [ ] ステップ4: 低リスクな共通化から進める。まず文面formatter/設定読み取り/小さなfactoryなど、挙動差分が少ないものを抽出する。
- [ ] ステップ5: 中リスクの共通化に進む。外部ツール実行、LLM routing、Swarm manager共通処理は互換層とfeature flagを用意する。
- [ ] ステップ6: 高リスク領域は最後に扱う。MasterConductor実行ループ、report/session schema、InjectionManager深部は分割計画の完了状況を見て進める。
- [ ] ステップ7: 各サブプラン完了時に graphify update、対象ユニットテスト、必要なら実セッション/レポート検証を行う。

## 5. サブプラン候補
- [ ] LLM Provider/Model Router 共通化: Ollama除去、DeepInfra等の低コストモデル、役割別モデル選択、fallbackを一箇所で管理する。
- [ ] Notification Formatter 共通化: Discord日本語化と合わせ、通知文面を送信処理から分離する。
- [ ] External Tool Adapter 共通化: subprocess/timeout/stderr/JSON parse/rate-limitを統一し、既存tool wrapperを段階移行する。
- [ ] Task/Finding Factory 共通化: MasterConductor、AttackPlanner、Swarm、ErrorReplannerでばらばらに作る Task/Finding を薄いfactoryに寄せる。
- [ ] Swarm Execution Contract 共通化: specialist実行、結果集約、handoff、Finding抽出、skip条件を共通インターフェース化する。
- [ ] Queue/PlanGraph 共通化: DynamicTaskQueue、SmartScheduler、TaskPrioritizer、pruning policy、AttackPlanを統合的に扱える設計へ進める。
- [ ] Report/Session Formatter 共通化: raw finding、backfill、summary、gate判定の責務境界を明確化する。

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] 抽象化しすぎて診断ロジックの意図が見えなくなる - security-critical な判定はドメイン名を残し、共通化は周辺処理に限定する。
- [ ] [重要度:高] 大規模置換で既存セッション/レポート互換が壊れる - schema変更は禁止し、互換層とテストを先に置く。
- [ ] [重要度:中] 巨大ファイル分割計画と競合する - 分割済み/分割予定の境界を確認し、先行タスクに依存関係を明記する。
- [ ] [重要度:中] 重複に見えて実は意図的な差分がある - 共通化前に各呼び出し元の失敗時挙動、timeout、side effectを表にする。
- [ ] [重要度:低] 継続タスク化により放置される - サブプランごとに小さな完了条件と検証コマンドを固定する。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0289-D01
    title: "継続監視: 共通化候補のサブプラン化"
    reason: "本計画は親ロードマップであり、実装は責務別サブプランに分割して進める"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "LLM Router、Notification Formatter、External Tool Adapter の順でサブプランを起票する"
```
