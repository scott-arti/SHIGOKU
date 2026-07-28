---
task_id: SGK-2026-0324
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/plans/done/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
- docs/shigoku/subtasks/done/2026-06-23_sgk-2026-0293_vulnerability-management-review-trail_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-24_sgk-2026-0302_attack-path-markdown-neo4j-prep_subtask_plan.md
- docs/shigoku/plans/2026-06-25_sgk-2026-0307_attack-path-phase2-bundle_plan.md
- docs/shigoku/specs/modules/KNOWLEDGE_GRAPH.md
- docs/shigoku/reports/2026-07-21_sgk-2026-0324_attack-path-cypher-neo4j-ingest_work_report.md
- docs/shigoku/worklogs/2026-07-21_sgk-2026-0324_attack-path-cypher-neo4j-ingest_work_log.md
title: 'P3: 攻撃パスNeo4j UI＋脆弱性管理システム'
created_at: '2026-06-29'
updated_at: '2026-07-28'
tags:
- shigoku
- neo4j
- vulnerability-management
- attack-path
target: src/reporting/attack_path_formatter.py, src/core/knowledge/models.py, src/core/knowledge/attack_path_ingestor.py, src/core/intelligence/chain_builder.py, src/core/learning/findings_repository.py, src/reporting/attack_review_builder.py, src/reporting/attack_review_formatter.py, src/reporting/target_profile_formatter.py, src/core/engine/master_conductor_session_service.py, scripts/shigoku_ops_cli.py
---

# 実装計画書：P3 攻撃パスNeo4j UI＋脆弱性管理システム

> たたき台（ブラッシュアップ前提）。SGK-2026-0302(deferred) / SGK-2026-0307(active) / SGK-2026-0293(done, 2026-07-21 時点で MVP 実装完了) を統合し、残っている可視化UI・CLI導線・継続検証を完了させる。

## 1. 達成したいゴール（ユーザー視点）
- [ ] 攻撃パス（脆弱性連鎖）が Neo4j に投入され、Web UI で対話的に探索できる。
- [x] 見つけた脆弱性が脆弱性単位で記録・一覧化・抽出でき、タイプ/重大度/エンドポイント別に検索できる。
- [x] ターゲットのシステム理解（認証・機能・エンドポイント・状態遷移・攻撃面）が蓄積され、次シナリオ設計の材料になる。
- [x] SHIGOKU がターゲットで判断・実行した結果が、ユーザーが読めるレビュー artifact になる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/reporting/attack_path_formatter.py`: Mermaid + Neo4j Cypher 出力（契約定義済み、実投入拡張）。
  - `src/core/knowledge/models.py`: ノード/エッジ契約（SGK-2026-0302 で定義済み）。
  - `src/core/intelligence/chain_builder.py`: 攻撃チェーン正規入力。
  - `src/core/learning/findings_repository.py`: SQLite 脆弱性ストア（既存、`findings list/search/stats/export-targets` で CLI 露出済み）。
  - `src/reporting/attack_review_builder.py` / `src/reporting/attack_review_formatter.py` / `src/reporting/target_profile_formatter.py`: `TargetSystemProfile` / `AttackReviewTrail` / `ScenarioCandidate` と `attack_review.md` の正本実装（SGK-2026-0293 で追加済み）。
  - `src/core/engine/master_conductor_session_service.py`: additive review field を session payload に載せる保存経路（SGK-2026-0293 で追加済み）。
- **データの流れ / 依存関係:**
  - session/findings → chain_builder → attack_path → Neo4j Cypher → Neo4j → Web UI
  - session/completed_tasks → finding_extractor → FindingsRepository → 脆弱性一覧/検索
  - task result/Finding/Swarm execution_log → TargetSystemProfile/AttackReviewTrail → レビュー artifact

## 3. 現状の前提（実装踏まえた評価）
- `attack_path_formatter.py` は Mermaid グラフ（`attack_paths.md`）と Neo4j ノード/エッジ契約を SGK-2026-0302 で実装済み。`evidence_state` 語彙、`observed_at`/`inferred_after` タイムラインあり。
- Neo4j 実投入と Web UI は SGK-2026-0307(active) で進行中（D01-D05 deferred 束）。
- `FindingsRepository`（SQLite `~/.shigoku/findings.db`）は存在し `search(severity,vuln_type,target,source_agent,verified_only)` / `get_statistics()` を持つ。2026-07-21 時点で `shigoku-ops findings list/search/stats/export-targets` により CLI 露出済み。
- 脆弱性管理（`TargetSystemProfile` / `AttackReviewTrail` / `ScenarioCandidate`）と `attack_review.md` formatter は SGK-2026-0293 で 2026-07-21 に MVP 実装済み。残課題は実セッション継続検証、CLI 露出、必要なら `scenario_candidates.jsonl` export の整理。

## 4. 具体的な仕様と制約条件
- **入力情報 (Input):** session（run_ledger/findings/completed_tasks）、attack chain、FindingsRepository、target_info。
- **出力/結果 (Output):**
  - Neo4j への攻撃パス投入（Cypher）と探索用 Web UI
  - 脆弱性一覧/検索 CLI（`findings list/search/stats/export-targets`）
  - `target_profile.md` / `attack_review.md` の既存 artifact を運用導線から呼び出せること
  - 必要に応じた `scenario_candidates.jsonl` export と `shigoku-ops report attack-review` の追加
- **制約・ルール:**
  - グラフ中心ではなく、まずユーザーが読める Markdown/JSONL レビュー artifact を優先（SGK-2026-0293 制約）。
  - 機密値（PII/secret）は必ずマスク。既存 redactor 再利用。
  - 推定と raw evidence を区別（`estimated`/`backfill` 明記）。
  - 既存 session/report schema を壊さず追加 artifact として始める。
  - SGK-2026-0293 で導入済みの additive review field / formatter を正本として再利用し、同等機能を再実装しない。

## 5. 実装ステップ（AIに指示する手順）
- [x] ステップ1: SGK-2026-0307 の Neo4j 投入・Web UI 設計を引き継ぎ、攻撃パス Cypher 生成と UI 要件を確定。
- [x] ステップ2: `FindingsRepository` の CLI 露出。`shigoku-ops findings list/search/stats/export-targets` を追加し、既存 `search()`/`get_statistics()` を利用しつつ cross-session export の最小版も開放する。
- [x] ステップ3: `TargetSystemProfile`（認証/機能/エンドポイント/入力点/状態遷移/tech/攻撃面）のデータモデルと蓄積ロジックは SGK-2026-0293 で実装済み。0324 では実セッション妥当性確認と必要最小限の差分整理のみを扱う。
- [x] ステップ4: `AttackReviewTrail`（観測/仮説/行動/結果/次候補）と `ScenarioCandidate`（根拠/期待結果/必要条件/危険度/採用状態）は SGK-2026-0293 で実装済み。0324 では再実装せず、運用導線と継続検証へ寄せる。
- [x] ステップ5: 既存 `attack_review.md` formatter を再利用しつつ、`shigoku-ops report attack-review` と、必要なら `scenario_candidates.jsonl` export を追加する。
- [x] ステップ6: 実 session artifact を複数件使い、レビュー artifact がユーザーの次判断に使えるか継続検証する。必要な unit test / real artifact validation をここで追加する。

## 5.1 フェーズ分割
- Phase A: FindingsRepository CLI 露出（ステップ2）※ 最も即効
- Phase B: 既存脆弱性管理 artifact の運用導線・継続検証（ステップ3-6）
- Phase C: Neo4j UI 統合（ステップ1、SGK-2026-0307 連動）

進捗メモ（2026-07-21）:
- `shigoku-ops findings list/search/stats/export-targets` を実装し、Phase A を完了。
- `findings export-targets` は `--allowed-host` または `--target` がない mixed-scope export を fail-closed で拒否する。
- `SGK-2026-0293` は 2026-07-21 時点で done。`target_system_profile` / `attack_review_trail` / `scenario_candidates` / `attack_review.md` は既存実装を前提に扱う。
- `shigoku-ops report attack-paths --cypher-output` と `--neo4j-ingest` を追加し、`attack_paths.json` → Cypher / Neo4j ingest の backend contract を実装した。`AttackPathFormatter.build_json_payload()` を正本にし、Endpoint は raw URL を保持したまま取り込める。
- `src/core/intelligence/chain_builder.py` を正本入力とする前提は維持し、旧 `attack/chain_builder.py` は新規 ingest では参照しない。
- Step5/6 は 2026-07-21 時点で実装・評価済みとして扱い、review artifact の CLI 導線と実 session 継続検証を完了した。
- 本タスクの実装スコープは完了。残るのは SGK-2026-0307 に紐づく継続確認（実 attack chain session を使った Neo4j ingest / Web UI 妥当性確認）であり、0324 自体は done 化してよい。

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] 履歴を貯めすぎて読めなくなる。レビュー artifact は要約中心、時系列ログとシステム理解を分離（SGK-2026-0293 制約）。
- [ ] [重要度:高] 機密情報保存リスク。PII/secret masking と保存対象制御を必須化。
- [ ] [重要度:中] Neo4j 依存追加の運用コスト。Markdown 先行で Neo4j は任意とする。
- [ ] [重要度:中] AI 判断の過信防止。採用/棄却理由と根拠を残し人間レビュー可能に。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0324-D01
    title: "継続監視: Neo4j Web UI の実ターゲット妥当性"
    reason: "UI は SGK-2026-0307 進行依存"
    impact: medium
    tracking_task_id: SGK-2026-0307
    recommended_next_action: "SGK-2026-0307 完了後に本タスクの Phase C を再開する"
```
