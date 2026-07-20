---
task_id: SGK-2026-0326
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/plans/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0325_conversational-ops-chat-direction_subtask_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0324_neo4j-attack-path-ui-vuln-management_subtask_plan.md
- docs/shigoku/plans/done/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- src/reporting/session_finding_inspector.py
- src/reporting/finding_extractor.py
- src/core/learning/findings_repository.py
- scripts/shigoku_ops_cli.py
title: 'B: 自由形式レポート生成→SHIGOKU再投入'
created_at: '2026-06-29'
updated_at: '2026-07-21'
tags:
- shigoku
- reporting
- query
- reinjection
target: src/reporting/, src/core/learning/findings_repository.py, scripts/shigoku_ops_cli.py, src/main.py
---

# 実装計画書：B 自由形式レポート生成→SHIGOKU再投入

> たたき台（ブラッシュアップ前提）。SGK-2026-0325 と同じ束で扱うが、完全統合までは行わない。0326 は「出力側」として、既存の finding inspector / フィルタ / 射影 / JSON envelope を土台に、single-session のエンドポイント抽出・構造化出力・再投入用 artifact 生成を先行する。cross-session 連携は SGK-2026-0324 依存があるため後段フェーズへ送る。

## 1. 達成したいゴール（ユーザー視点）
- [ ] 見つけた URI エンドポイント一覧を、自由な形式（Markdown/JSON/CSV）で抽出・出力できる。
- [ ] 脆弱性をタイプ/重大度/エンドポイント別に一覧化し、任意のフィールド・形式で出力できる。
- [ ] 出力したレポートのうち、再投入に使う structured target file / endpoint list を SHIGOKU に渡して、その対象を分析・攻撃させられる。
- [ ] 人間向け表示（Markdown/CSV）と機械再投入用の構造化出力を分けて扱える。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `scripts/shigoku_ops_cli.py`: SGK-2026-0325 と共有する CLI / 運用導線。report/session 解決、JSON envelope、export 起点をまとめる。
  - `src/reporting/session_finding_inspector.py`: 既存 `inspect_session_findings` の拡張（single-session export の主軸）。
  - `src/reporting/finding_extractor.py`: 正規抽出（既存 `extract_all_findings`）の再利用。
  - `src/core/learning/findings_repository.py`: SQLite ストア（既存）。cross-session の後段フェーズで CLI 露出（SGK-2026-0324 と連動）。
  - `src/reporting/`: エンドポイント抽出フォーマッタ（`endpoint_extractor.py` 新設想定）と、再投入用 structured target file 生成ロジック。
  - `scripts/shigoku_ops_cli.py`: 既存 `report` / `session` 系コマンドの延長として `endpoints list` と export 導線を追加。
  - `src/main.py`: `--attack-targets <file>`（A/SGK-2026-0325 と共用）で再投入。
- **データの流れ / 依存関係:**
  - session/classified files/tagged_urls → endpoint_extractor → endpoints.{md,json,csv}
  - session → finding_extractor/inspector → findings list（フィルタ/射影、single-session 先行）
  - export 結果 → structured target file → `--attack-targets` → MC `_create_attack_tasks_from_recon` 相当のタスク生成 → 攻撃
  - cross-session 検索/集約 → FindingsRepository CLI 露出後に追加（SGK-2026-0324 依存）

## 3. 現状の前提（実装踏まえた評価）
- `inspect_session_findings(session, detection_class, finding_fields, max_findings)` はフィルタ＋フィールド射影が既存（`session_finding_inspector.py:97`）。
- `FINDING_FIELD_PRESETS`（minimal/triage/full）と `--finding-fields` カスタム射影が既存（`shigoku_ops_cli.py:89`）。
- `extract_all_findings()` は7レベルフォールバックの正規抽出（`finding_extractor.py:13`）。SGK-2026 lessons で正規抽出の使用が CRITICAL 指定済み。
- `--json --json-envelope` で `shigoku.ops.v1` agent 消費 JSON が既存。
- `shigoku-ops` には `report consistency` / `report loop` / `session findings` / `session resolve-from-report` が既にあり、single-session の export 導線は部分的に揃っている。
- FindingsRepository（SQLite）は `search()/get_statistics()` を持つが CLI 未露出。cross-session は後段フェーズ扱いが自然。
- エンドポイントは Recon の classified files / tagged_urls JSONL に散在。クエリ可能な形での抽出フォーマッタは未実装。
- 逆投入（export→攻撃ターゲット）の structured artifact は未実装だが、MC の `_create_attack_tasks_from_recon` パターンが再利用可能。

## 4. 具体的な仕様と制約条件
- **入力情報 (Input):** session/report パス、抽出対象（findings/endpoints）、フィルタ（type/severity/endpoint/category）、フィールド/テンプレート、出力形式。
- **出力/結果 (Output):**
  - エンドポイント一覧（`endpoints.{md,json,csv}`）
  - 脆弱性一覧（フィルタ/射影/テンプレート適用）
  - 再投入用ターゲットファイル（`--attack-targets` 受け）
- **制約・ルール:**
  - 0326 は「出力側」の兄弟タスクであり、入力解釈や会話ループは SGK-2026-0325 側の責務とする。
  - 一次証拠は `extract_all_findings()` / `inspect_session_findings()` 由来。report/session 整合性は `verify_report_session_consistency()` で保証（SGK-2026 lessons CRITICAL）。
  - 機密値（PII/secret）はマスク。既存 redactor 再利用。
  - 初期スコープは single-session を正本とし、再投入に使うのは machine-readable な structured target file とする。任意 Markdown の逆解析は含めない。
  - テンプレート/プリセットは既存フォーマッタ（narrative/target-profile/attack-path/haddix）を壊さず追加するが、初期は built-in preset 中心で進める。
  - cross-session クエリは FindingsRepository(SQLite) を活用するが、SGK-2026-0324 の CLI 露出に依存するため後段フェーズへ送る。

## 5. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: SGK-2026-0325 と共有する export / reinjection 契約を整理。`attack-targets` ファイル schema、provenance、scope 情報、session/report 解決手順を明文化する。
- [ ] ステップ2: `endpoint_extractor.py` 新設。Recon classified files / tagged_urls JSONL / httpx.json からエンドポイントを正規化抽出し `{md,json,csv}` と structured target file を出力する。
- [ ] ステップ3: `shigoku-ops endpoints list --session <path> [--format md|json|csv] [--category api|has_params|...]` を追加し、single-session のエンドポイント export 導線を固める。
- [ ] ステップ4: 既存 `session findings` / report 解決導線を拡張し、フィルタ済み findings export と再投入用ターゲット出力を single-session で提供する。まずは preset / field projection ベースで進める。
- [ ] ステップ5: 逆投入 CLI。出力したエンドポイント/ターゲットリストを `--attack-targets <file>` で受け、MC のタスク生成へ渡す（`_create_attack_tasks_from_recon` パターンを汎用化）。
- [ ] ステップ6: cross-session export / FindingsRepository 連携は SGK-2026-0324 依存の後段フェーズとして切り出し、初期実装では無理に統合しない。
- [ ] ステップ7: 単体テスト + 実 session/report artifact で抽出・再投入の一貫性検証。

## 5.1 フェーズ分割
- Phase A: shared export 契約 + single-session export / reinjection（ステップ1-5）
- Phase B: built-in preset / 表示改善（ステップ4 の拡張）
- Phase C: cross-session / FindingsRepository 連携（ステップ6）

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] report/session 整合性。必ず `verify_report_session_consistency()` を通し `consistent` のみ許可（SGK-2026 lessons）。
- [ ] [重要度:高] 人間向け Markdown と再投入用 structured data を混同すると運用事故になる。機械入力の正本を別 artifact として固定する。
- [ ] [重要度:中] テンプレートの自由度と秘匿。初期は built-in preset 中心にし、追加出力も redactor 経由を必須化。
- [ ] [重要度:中] 逆投入時のスコープ逸脱。`--attack-targets` は scope ポリシーで検証し逸脱は警告。
- [ ] [重要度:低] cross-session クエリは SGK-2026-0324/FindingsRepository CLI 露出に依存。後段フェーズとして別扱いにする。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0326-D01
    title: "継続監視: cross-session 脆弱性クエリ"
    reason: "FindingsRepository CLI 露出は P3/SGK-2026-0324 に依存"
    impact: medium
    tracking_task_id: SGK-2026-0324
    recommended_next_action: "SGK-2026-0324 完了後に findings export の cross-session を有効化する"
```
