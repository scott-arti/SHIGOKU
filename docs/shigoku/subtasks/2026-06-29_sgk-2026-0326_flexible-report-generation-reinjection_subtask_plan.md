---
task_id: SGK-2026-0326
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/plans/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0325_conversational-ops-chat-direction_subtask_plan.md
- docs/shigoku/plans/done/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- src/reporting/session_finding_inspector.py
- src/reporting/finding_extractor.py
- src/core/learning/findings_repository.py
- scripts/shigoku_ops_cli.py
title: 'B: 自由形式レポート生成→SHIGOKU再投入'
created_at: '2026-06-29'
updated_at: '2026-07-02'
tags:
- shigoku
- reporting
- query
- reinjection
target: src/reporting/, src/core/learning/findings_repository.py, scripts/shigoku_ops_cli.py, src/main.py
---

# 実装計画書：B 自由形式レポート生成→SHIGOKU再投入

> たたき台（ブラッシュアップ前提）。基盤が最も近い（finding inspector + フィルタ/射影 + JSON envelope 既存）。エンドポイント抽出・テンプレート化・逆投入 CLI を追加する。

## 1. 達成したいゴール（ユーザー視点）
- [ ] 見つけた URI エンドポイント一覧を、自由な形式（Markdown/JSON/CSV）で抽出・出力できる。
- [ ] 脆弱性をタイプ/重大度/エンドポイント別に一覧化し、任意のフィールド・形式で出力できる。
- [ ] 出力したレポート（エンドポイント群や脆弱性群）を SHIGOKU に再投入し、その対象を分析・攻撃させられる。
- [ ] 出力形式をテンプレート/プリセットで自由に指定できる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/reporting/session_finding_inspector.py`: 既存 `inspect_session_findings` の拡張（エンドポイント抽出、cross-session）。
  - `src/reporting/finding_extractor.py`: 正規抽出（既存 `extract_all_findings`）の再利用。
  - `src/core/learning/findings_repository.py`: SQLite ストア（既存）の CLI 露出（P3/SGK-2026-0324 と連動）。
  - `src/reporting/`: エンドポイント抽出フォーマッタ（`endpoint_extractor.py` 新設想定）、テンプレートエンジン（`report_template.py` 新設想定）。
  - `scripts/shigoku_ops_cli.py`: `findings export` / `endpoints list` / `report from-template` サブコマンド。
  - `src/main.py`: `--attack-targets <file>`（A/SGK-2026-0325 と共用）で再投入。
- **データの流れ / 依存関係:**
  - session/classified files/tagged_urls → endpoint_extractor → endpoints.{md,json,csv}
  - session → finding_extractor/inspector → findings list（フィルタ/射影）
  - 出力レポート → `--attack-targets` → MC `_create_attack_tasks_from_recon` 相当のタスク生成 → 攻撃

## 3. 現状の前提（実装踏まえた評価）
- `inspect_session_findings(session, detection_class, finding_fields, max_findings)` はフィルタ＋フィールド射影が既存（`session_finding_inspector.py:97`）。
- `FINDING_FIELD_PRESETS`（minimal/triage/full）と `--finding-fields` カスタム射影が既存（`shigoku_ops_cli.py:89`）。
- `extract_all_findings()` は7レベルフォールバックの正規抽出（`finding_extractor.py:13`）。SGK-2026 lessons で正規抽出の使用が CRITICAL 指定済み。
- `--json --json-envelope` で `shigoku.ops.v1` agent 消費 JSON が既存。
- FindingsRepository（SQLite）は `search()/get_statistics()` を持つが CLI 未露出。
- エンドポイントは Recon の classified files / tagged_urls JSONL に散在。クエリ可能な形での抽出フォーマッタは未実装。
- 逆投入（レポート→攻撃ターゲット）の CLI は未実装だが、MC の `_create_attack_tasks_from_recon` パターンが再利用可能。

## 4. 具体的な仕様と制約条件
- **入力情報 (Input):** session/report パス、抽出対象（findings/endpoints）、フィルタ（type/severity/endpoint/category）、フィールド/テンプレート、出力形式。
- **出力/結果 (Output):**
  - エンドポイント一覧（`endpoints.{md,json,csv}`）
  - 脆弱性一覧（フィルタ/射影/テンプレート適用）
  - 再投入用ターゲットファイル（`--attack-targets` 受け）
- **制約・ルール:**
  - 一次証拠は `extract_all_findings()` / `inspect_session_findings()` 由来。report/session 整合性は `verify_report_session_consistency()` で保証（SGK-2026 lessons CRITICAL）。
  - 機密値（PII/secret）はマスク。既存 redactor 再利用。
  - テンプレートは既存フォーマッタ（narrative/target-profile/attack-path/haddix）を壊さず追加。
  - cross-session クエリは FindingsRepository(SQLite) を活用（P3 と連動）。

## 5. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `endpoint_extractor.py` 新設。Recon classified files / tagged_urls JSONL / httpx.json からエンドポイントを正規化抽出し `{md,json,csv}` 出力。
- [ ] ステップ2: `shigoku-ops endpoints list --session <path> [--format md|json|csv] [--category api|has_params|...]` サブコマンド追加。
- [ ] ステップ3: `shigoku-ops findings export` を拡張。`--filter type=X,severity>=high`、`--template <file>`、`--format` で柔軫出力。cross-session は FindingsRepository 経由（P3 連動）。
- [ ] ステップ4: `report_template.py` 新設。既存フォーマッタをテンプレート化し、ユーザ定義テンプレート（Jinja2 等）を適用可能に。
- [ ] ステップ5: 逆投入 CLI。出力したエンドポイント/ターゲットリストを `--attack-targets <file>` で受け、MC のタスク生成へ渡す（`_create_attack_tasks_from_recon` パターンを汎用化）。
- [ ] ステップ6: 単体テスト + 実 session/report artifact で抽出・再投入の一貫性検証。

## 5.1 フェーズ分割
- Phase A: エンドポイント抽出フォーマッタ（ステップ1-2）
- Phase B: findings export 拡張＋テンプレート（ステップ3-4）
- Phase C: 逆投入 CLI（ステップ5）

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] report/session 整合性。必ず `verify_report_session_consistency()` を通し `consistent` のみ許可（SGK-2026 lessons）。
- [ ] [重要度:中] テンプレートの自由度と秘匿。テンプレート出力も redactor 経由を必須化。
- [ ] [重要度:中] 逆投入時のスコープ逸脱。`--attack-targets` は scope ポリシーで検証し逸脱は警告。
- [ ] [重要度:低] cross-session クエリは P3/FindingsRepository CLI 露出に依存。Phase B の一部は P3 完了後に拡充。

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
