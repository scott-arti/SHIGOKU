---
task_id: SGK-2026-0309
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0291
related_docs:
- docs/shigoku/subtasks/2026-06-23_sgk-2026-0291_swarm-parallelism-review_subtask_plan.md
- docs/shigoku/plans/2026-06-21_sgk-2026-0289_commonization-technical-debt-roadmap_plan.md
title: 'Swarm並列化 Phase 0: 現状正本化と非対象固定'
created_at: '2026-06-26'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/core/engine/master_conductor.py, src/core/engine/parallel_orchestrator.py,
  src/core/engine/swarm_dispatcher.py, src/core/agents/swarm/
---

# 実装計画書：Swarm並列化 Phase 0: 現状正本化と非対象固定

## 1. 達成したいゴール（ユーザー視点）
- [x] SHIGOKU の現行実行フローを、MC外側 / SwarmDispatcher / SwarmManager / specialist内部の4層に分けて正本化すること。
- [x] どこが本当に並列で、どこが直列意味論を持つかをコード根拠付きで説明できること。
- [x] Phase 1以降で壊してはいけない不変条件、初期非対象、危険な共有状態を実装前に固定すること。
- [x] 本フェーズではコード挙動を一切変更しないこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: task queue、batch選択、ParallelOrchestrator接続点の棚卸し。
  - `src/core/engine/parallel_orchestrator.py`: 既存category worker、rate limiter、target抽出ロジックの棚卸し。
  - `src/core/engine/swarm_dispatcher.py`: Swarm pool、dispatch順序、複数Swarm呼び出しの棚卸し。
  - `src/core/agents/swarm/base.py`: `SwarmManager.dispatch()` のspecialist直列実行とadaptive skip意味論の棚卸し。
  - `src/core/agents/swarm/base_manager.py`: `current_context` 共有状態の棚卸し。
  - `src/core/agents/swarm/injection/manager.py`: Injection Phase 1/2、URL処理、`current_context` 依存の棚卸し。
- **データの流れ / 依存関係:**
  - Recon / task generation -> MasterConductor task queue -> ParallelOrchestrator -> task full flow -> SwarmDispatcher -> SwarmManager -> specialist -> finding/result。
  - 本フェーズの成果物は Phase 1-9 の設計入力として使う。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** 既存ソースコード、親計画 `SGK-2026-0291`、関連計画 `SGK-2026-0287`、既存テスト。
- **出力/結果 (Output):** 実行フロー表、並列/直列棚卸し、mutable state inventory、specialist初期分類表、初期非対象リスト、責務分担表、分類ルール表、コード根拠付き証跡表、Phase 1-4 着手前提の固定事項一覧。
- **制約・ルール:**
  - コード挙動変更は禁止。必要ならコメントやドキュメントのみ。
  - `SwarmManager.dispatch()` の High/Critical finding adaptive skip は保護対象として扱う。
  - `current_context`、Swarm pool、EventBus、rate limiter の現状は推測せずコード参照で確認する。
  - 本フェーズで固定するのは契約名、観測項目、判定基準、保護理由までとし、schema追加や制御方式の実装には踏み込まない。
  - `parallel_safe` / `sequential_required` / `rate_limited` / `stateful` / `aggressive_exclusive` の分類は、根拠コード参照と判定理由を必須にし、根拠不足は `不明` または安全側分類に倒す。
  - Phase 1-4 の設計入力になる契約候補（例: target identity、event reliability、dispatch-local state）は「名称・依存先・保護対象」を固定し、実装詳細は後続フェーズへ委譲する。
  - `SGK-2026-0287` および関連する recon/pruning 側の責務境界は、依存関係として明文化するが、本フェーズでは仕様変更しない。
  - 完了条件に使う成果物は、親計画 `SGK-2026-0291` の 4.1 / 4.2 / 4.4 へトレース可能でなければならない。
  - Phase 0の成果物がない状態で Phase 1以降を開始しない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `rg` と該当ファイル確認で、`await` / `for` / `gather` / semaphore / worker / pool / lock の実態を一覧化する。
- [x] ステップ2: MC外側、SwarmDispatcher、SwarmManager、specialist内部の4層ごとに「並列済み」「直列前提」「局所並列」「不明」を分類し、各判定にファイル/関数/行番号の根拠を紐付ける。
- [x] ステップ3: `MasterConductor` / `ParallelOrchestrator` / `SwarmDispatcher` / `SwarmManager` / specialist内部について、`task generation` / `admission` / `scheduling` / `execution` / `observation` の責務分担表を作成する。
- [x] ステップ4: `current_context`、cookie/auth/header/cache/temp artifact、EventBus queue、rate limiter target抽出などの共有状態を inventory 化し、`dispatch-local` / `shared immutable` / `shared mutable` / `external state` に分類する。
- [x] ステップ5: specialist / task を `parallel_safe`、`sequential_required`、`rate_limited`、`stateful`、`aggressive_exclusive` の初期分類へ落とし、unknown時の扱いと昇格条件を含む分類ルール表を作成する。
- [x] ステップ6: Phase 1-4 の前提になる契約候補について、実装せずに「契約名」「後続フェーズで使う理由」「保護対象」「依存先」を固定事項一覧として整理する。
- [x] ステップ7: EventBus、rate limiter、timeout/deadline、resource bulkhead、recon/pruning 依存について、現行実装の観測項目と責務境界だけを整理し、仕様変更を伴わないブロッカー一覧を親計画へ反映する。
- [x] ステップ8: Phase 1-9 のブロッカー、非対象、最初にGoしてよい候補を親計画へ反映し、特に Phase 1-4 の着手前提が親計画 4.1 / 4.2 / 4.4 にトレースできることを確認する。
- [x] ステップ9: ドキュメント検証を実行する。

> **Note**: 本計画書は planning artifact です。完了実績・成果物・テスト結果・検証は `docs/shigoku/reports/2026-06-26_sgk-2026-0309_work_report.md` を正本とします。リスク一覧（Section 5）のチェックボックスは計画時点の棚卸しであり、未対応項目は work_report の `deferred_tasks` へ移管済みです。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
### 5.1 SRE / インフラ観点
- [ ] [発生確率:高 / 影響度:大] `rate limiter` の棚卸し粒度が粗いと Phase 2 の per-origin budget 設計が推測混じりになる - Phase 0 では制御方式を変えず、現行の host/task 単位制御、worker 数、inflight 上限、cooldown 相当、target 抽出根拠を観測項目として固定する。
- [ ] [発生確率:高 / 影響度:大] EventBus の queue full / drop 挙動が未記録だと Phase 4 以降の shadow 判定に抜けが出る - EventBus については reliability class を実装せず、現行の queue、drop 条件、retry 有無、dead-letter 有無を inventory として固定する。
- [ ] [発生確率:高 / 影響度:中] timeout/deadline の階層が曖昧なまま後続フェーズへ進むと budget 設計がぶれる - `session -> batch -> task -> specialist -> request` の現行 timeout 伝播点を観測し、実装変更なしで伝播表だけを作る。
- [ ] [発生確率:中 / 影響度:中] connection 枯渇や bulkhead 不足の懸念が Phase 0 で拾われない - LLM、network I/O、external tool、Swarm worker の資源境界を現行構造ベースで列挙し、隔離候補名だけを固定する。
- [ ] [発生確率:中 / 影響度:中] ドキュメントだけ整っても根拠追跡が弱いと SRE レビューで差し戻される - すべての観測結果にコード参照を紐付け、根拠なしの断定を完了扱いにしない。

### 5.2 ソフトウェアアーキテクト観点
- [ ] [発生確率:高 / 影響度:大] 責務境界が曖昧なまま分類だけ進むと、Phase 1-4 で所有責務が再分配されて計画が崩れる - `task generation` / `admission` / `scheduling` / `execution` / `observation` の責務分担表を Phase 0 成果物へ追加する。
- [ ] [発生確率:高 / 影響度:大] mutable state inventory に state の性質が入らないと Phase 3 の isolation 設計に直結しない - 共有状態は `dispatch-local` / `shared immutable` / `shared mutable` / `external state` の4分類で固定する。
- [ ] [発生確率:高 / 影響度:中] Phase 0 が後続フェーズの実装方針まで踏み込むと責務侵食が起きる - 本フェーズでは契約名・保護理由・依存先のみ固定し、schema・API・制御方法の具体化は後続フェーズへ送る。
- [ ] [発生確率:中 / 影響度:中] `parallel_safe` などの分類語がレビューごとに解釈されると、Phase 4 shadow 判定がぶれる - 初期分類ごとに判定基準、unknown時の扱い、昇格条件を文章で固定する。
- [ ] [発生確率:中 / 影響度:中] 親計画の固定事項と Phase 0 成果物の対応が弱いとトレーサビリティが失われる - 親計画 4.1 / 4.2 / 4.4 に対する対応表を作り、各固定事項の参照先を明記する。

### 5.3 デバッガー観点
- [ ] [発生確率:高 / 影響度:大] 「コード根拠付き」で残さないと後続の不具合調査で証跡として使えない - ファイル、関数、行番号、並列原語、観測結果、保護判断を揃えた証跡表を Phase 0 の成果物に含める。
- [ ] [発生確率:高 / 影響度:中] `不明` が理由なしで残ると、未解決か見落としか判別できない - `不明` には blocker reason、追加確認先、後続フェーズへ送る理由を必須記載にする。
- [ ] [発生確率:高 / 影響度:中] adaptive skip を保護対象と書くだけでは Phase 8 で再現対象として弱い - High/Critical finding 時の skip 条件、観測入力、結果集約点の因果メモを Phase 0 で固定する。
- [ ] [発生確率:中 / 影響度:中] Phase 1 の debug metadata 候補が散ると観測設計がぶれる - `correlation_id`、`auth_context_version`、`recon_snapshot_version` などの候補を「観測上必要なキー」として要求一覧にまとめる。
- [ ] [発生確率:中 / 影響度:中] 対象ファイルの分類漏れに気づかないまま完了扱いになる - 対象ファイルごとに未分類関数が残っていないことを完了確認に含める。

### 5.4 CTO観点
- [ ] [発生確率:高 / 影響度:大] Phase 0 の完了条件が成果物の有無だけだと、Go/No-Go 材料として弱い - Phase 1-4 着手可否の判定表と、未解消なら No-Go にすべき論点一覧を成果物へ追加する。
- [ ] [発生確率:高 / 影響度:大] `SGK-2026-0287` や recon 側との依存が Input 記載だけだと後続で責務競合が起きる - recon/pruning との責務境界を「依存関係メモ」として明文化し、本フェーズでは変更しないことを固定する。
- [ ] [発生確率:高 / 影響度:中] safety default や初期非対象が散在すると後続フェーズで解釈が割れる - 初期 safety default、初期非対象、後続フェーズの解禁前提を Phase 0 の固定事項一覧へ集約する。
- [ ] [発生確率:中 / 影響度:中] operator 観点が後ろ倒しになると rollout 時に観測不足が露呈する - lane pause、kill switch、rollback に必要な前提観測項目名だけを Phase 0 で親計画へ逆流する。
- [ ] [発生確率:中 / 影響度:中] 成功定義が主観的だとレビューで合意形成しづらい - 根拠未提示の断定禁止、unknown の安全側分類、親計画へのトレース可能性を完了条件として明文化する。

### 5.5 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0309-D01
    title: "継続監視: 並列/直列分類の実装追従"
    reason: "Phase 0時点の棚卸しは後続実装で陳腐化する可能性がある"
    impact: medium
    tracking_task_id: SGK-2026-0309
    recommended_next_action: "Phase 1以降で分類差分が出たら親計画と本サブタスクへ追記する"
```
