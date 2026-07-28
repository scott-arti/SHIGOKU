---
task_id: SGK-2026-0326
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/plans/done/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
- docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0325_conversational-ops-chat-direction_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0324_neo4j-attack-path-ui-vuln-management_subtask_plan.md
- docs/shigoku/plans/done/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- src/reporting/session_finding_inspector.py
- src/reporting/finding_extractor.py
- src/core/learning/findings_repository.py
- scripts/shigoku_ops_cli.py
title: 'B: 自由形式レポート生成→SHIGOKU再投入'
created_at: '2026-06-29'
updated_at: '2026-07-28'
tags:
- shigoku
- reporting
- query
- reinjection
target: src/reporting/, src/core/learning/findings_repository.py, scripts/shigoku_ops_cli.py, src/main.py
---

# 実装計画書：B 自由形式レポート生成→SHIGOKU再投入

> たたき台（ブラッシュアップ前提）。SGK-2026-0325 と同じ束で扱うが、完全統合までは行わない。0326 は「出力側」として、既存の finding inspector / フィルタ / 射影 / JSON envelope を土台に、single-session のエンドポイント抽出・構造化出力・再投入用 artifact 生成を先行した。2026-07-21 時点で SGK-2026-0324 の FindingsRepository CLI 露出を取り込み、cross-session export の最小版も解放した。

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
  - `src/core/learning/findings_repository.py`: SQLite ストア（既存）。`shigoku-ops findings list/search/stats/export-targets` を通じた cross-session export の最小版を担当。
  - `src/reporting/`: エンドポイント抽出フォーマッタ（`endpoint_extractor.py` 新設想定）と、再投入用 structured target file 生成ロジック。
  - `scripts/shigoku_ops_cli.py`: 既存 `report` / `session` 系コマンドの延長として `endpoints list` と export 導線を追加。
  - `src/main.py`: `--attack-targets <file>`（A/SGK-2026-0325 と共用）で再投入。
- **データの流れ / 依存関係:**
  - session/classified files/tagged_urls → endpoint_extractor → endpoints.{md,json,csv}
  - session → finding_extractor/inspector → findings list（フィルタ/射影、single-session 先行）
  - export 結果 → structured target file → `--attack-targets` → MC `_create_attack_tasks_from_recon` 相当のタスク生成 → 攻撃
  - cross-session 検索/集約 → FindingsRepository CLI 露出後に段階追加。2026-07-21 時点で `findings export-targets` の最小版まで実装。

## 3. 現状の前提（実装踏まえた評価）
- `inspect_session_findings(session, detection_class, finding_fields, max_findings)` はフィルタ＋フィールド射影が既存（`session_finding_inspector.py:97`）。
- `FINDING_FIELD_PRESETS`（minimal/triage/full）と `--finding-fields` カスタム射影が既存（`shigoku_ops_cli.py:89`）。
- `extract_all_findings()` は7レベルフォールバックの正規抽出（`finding_extractor.py:13`）。SGK-2026 lessons で正規抽出の使用が CRITICAL 指定済み。
- `--json --json-envelope` で `shigoku.ops.v1` agent 消費 JSON が既存。
- `shigoku-ops` には `report consistency` / `report loop` / `session findings` / `session resolve-from-report` が既にあり、`report/session export-targets`, `report/session endpoints`, `report findings` まで single-session 導線が拡張済み。
- FindingsRepository（SQLite）は `search()/get_statistics()` を持ち、`shigoku-ops findings list/search/stats/export-targets` で CLI 露出済み。
- エンドポイントは Recon の classified files / tagged_urls JSONL に散在していたが、`endpoint_extractor.py` と `report/session endpoints` で single-session query は実装済み。cross-session は `findings export-targets` の最小版を実装済みで、高度な集約/ランキングは未実装。
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
  - cross-session クエリは FindingsRepository(SQLite) を活用する。最小版は `findings export-targets` で開放し、より高度な集約/ランキングだけを後段フェーズへ残す。

## 5. 実装ステップ（AIに指示する手順）
- [x] ステップ1: SGK-2026-0325 と共有する export / reinjection 契約を整理する。`AttackTargetSpec`, `ExportManifest`, `provenance`, `allowed_hosts`, `manifest_hash`, `source_session`, `source_report`, `generated_at` を最小必須項目として明文化する。
- [x] ステップ2: artifact lifecycle を先に固定する。出力先ディレクトリ、ファイル名規則、`ttl_days`, `max_export_records`, `atomic_write`, `overwrite_policy`, `redaction_required` を決め、Markdown 表示用と機械再投入用の正本を分離する。
- [x] ステップ3: `endpoint_extractor.py` を新設し、Recon classified files / tagged_urls JSONL / httpx.json からエンドポイントを正規化抽出して `{md,json,csv}` と structured target file を出力する。境界の型は ad hoc dict ではなく明示的 schema で扱う。
- [x] ステップ4: `shigoku-ops` の既存 `session` / `report` 導線を再利用しつつ、`endpoints list` と findings export を single-session で追加する。report 起点では `.venv/bin/shigoku-ops report consistency` または `session resolve-from-report` で `consistent` を確認できた時だけ先へ進む。
- [x] ステップ5: 逆投入 CLI を追加する。出力したターゲットリストを `--attack-targets <file>` で受け、`manifest_hash` 検証、scope validation、`allowed_hosts` 照合を通ったものだけ MC のタスク生成へ渡す。任意 Markdown の逆解析は行わない。
- [x] ステップ6: cross-session export / FindingsRepository 連携は SGK-2026-0324 依存の後段フェーズとして切り出し、初期実装では統合しない。解放条件は「CLI 露出済み」「整合性チェックを通る」「out-of-scope 混入を拒否できる」の3点とする。
- [x] ステップ7: 単体テスト + 実 session/report artifact で抽出・再投入の一貫性検証を行う。`empty export`, `invalid manifest`, `tampered hash`, `consistency blocked`, `out-of-scope host`, `redaction regression` の失敗系も必ず含める。

進捗メモ（2026-07-21）:
- real report artifact に対して `verify_report_session_consistency.py`, `shigoku-ops report endpoints`, `shigoku-ops report export-targets` を確認済み。
- `shigoku-ops findings list/search/stats/export-targets` を追加し、cross-session export の最小版を開放済み。
- mixed-scope findings DB から explicit host なしで export しようとした場合の `cross_session_scope_required` fail-closed を追加済み。
- `tampered hash`, `allowed_hosts mismatch`, `redaction regression`, `empty export` の回帰テストを追加し、human-facing artifact では secret token を redact するようにした。
- reinjection 時は `generated_at` / `ttl_days` / `scope_snapshot` / source provenance 欠落を fail-closed とし、expired bundle の再利用も拒否するようにした。
- real report artifact と real findings DB に対して export 経路を再確認し、Step 7 を完了。
- 高度な cross-session 集約/ランキングは別フェーズへ残しつつ、本タスク範囲の single-session export/reinjection と cross-session 最小版はクローズ可能な状態まで完了。

## 5.1 フェーズ分割
- Phase A: shared export 契約 + artifact lifecycle + single-session export（ステップ1-4）
- Phase B: reinjection と表示改善（ステップ5）
- Phase C: cross-session / FindingsRepository 連携 + 総合検証（ステップ6-7）

## 6. 懸念点と対策 / 既知のリスク
### 6.1 懸念点と対策
- [ ] [視点:SRE/インフラ][発生確率:高][影響度:中] export artifact の配置、寿命、上書き方法が曖昧だと、古い出力や壊れた途中ファイルを運用で拾いやすい。
  対策: artifact lifecycle を計画へ追加し、出力先、命名、TTL、atomic write、overwrite policy を明文化する。
- [ ] [視点:SRE/インフラ][発生確率:中][影響度:大] report/session 不整合のまま export すると、誤った finding や endpoint を再投入してしまう。
  対策: report 起点の処理は `.venv/bin/shigoku-ops report consistency` または `session resolve-from-report` で `consistent` を確認できた場合だけ継続する。
- [ ] [視点:ソフトウェアアーキテクト][発生確率:中][影響度:大] `session_finding_inspector` 拡張を ad hoc dict のまま進めると、後で 0325 との接続時に schema ずれが起きる。
  対策: `EndpointRecord`, `FindingExportRow`, `AttackTargetSpec`, `ExportManifest` の型を先に固定し、境界では型付きデータのみを通す。
- [ ] [視点:デバッガー][発生確率:高][影響度:大] 空の export、壊れた manifest、整合性NG report の異常系が計画に入っていないと、実運用で初めて壊れ方が分かる。
  対策: `empty export`, `invalid manifest`, `tampered hash`, `consistency blocked`, `out-of-scope host` の回帰テストを Step 7 に明記する。
- [ ] [視点:ハッカー][発生確率:高][影響度:大] `structured target file` が改ざんされると、scope 外ホストや余計な path を混入させられる。
  対策: `manifest_hash`, `allowed_hosts`, `source_scope`, `source_session` を必須にし、再投入前の hash 検証と scope validation を fail-closed で実施する。
- [ ] [視点:CTO][発生確率:中][影響度:大] cross-session を早く混ぜると、最小版の価値確認前に依存が増え、開発速度が落ちる。
  対策: single-session を MVP として固定し、cross-session は `0324` の成果と CLI 露出の完了後にだけ Phase C で解放する。

### 6.2 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] report/session 整合性。必ず `verify_report_session_consistency()` を通し `consistent` のみ許可（SGK-2026 lessons）。
- [ ] [重要度:高] 人間向け Markdown と再投入用 structured data を混同すると運用事故になる。機械入力の正本を別 artifact として固定する。
- [ ] [重要度:中] テンプレートの自由度と秘匿。初期は built-in preset 中心にし、追加出力も redactor 経由を必須化。
- [ ] [重要度:中] 逆投入時のスコープ逸脱。`--attack-targets` は scope ポリシーで検証し逸脱は警告。
- [ ] [重要度:低] 高度な cross-session 集約/ランキングはまだ未実装。`findings export-targets` の最小版は入ったが、優先度付けや program 単位の集約は後段フェーズとして別扱いにする。

### 6.3 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0326-D01
    title: "継続監視: cross-session 集約/ランキング"
    reason: "`findings export-targets` の最小版は入ったが、program 単位集約や優先度付けは未実装"
    impact: low
    tracking_task_id: SGK-2026-0326
    recommended_next_action: "運用実績をもとに Phase C 後半で集約/ランキングを追加する"
```
