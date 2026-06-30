---
task_id: SGK-2026-0302
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0298
related_docs:
- docs/shigoku/plans/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/subtasks/2026-06-23_sgk-2026-0293_vulnerability-management-review-trail_subtask_plan.md
title: '内部挙動可視化 S4: 攻撃パスMarkdownグラフ・Neo4j連携準備'
created_at: '2026-06-24'
updated_at: '2026-06-30'
tags:
- shigoku
target: attack_paths.md, Mermaid, Neo4j export contract
---

# 実装計画書：内部挙動可視化 S4: 攻撃パスMarkdownグラフ・Neo4j連携準備

## 1. 達成したいゴール（ユーザー視点）
- [ ] SHIGOKU実行結果から、成立済み/候補/未検証の攻撃パスをMarkdownで把握できること。
- [ ] 初期版はMermaidグラフで十分に読みやすくし、Neo4j/UIは後続で接続できるノード/エッジ契約だけを定義すること。
- [ ] Target ProfileやRun Narrativeと同じsession一次証跡から生成し、raw findingと推定chainを区別すること。
- [ ] 1ページ目だけ見れば「今すぐ追うべき攻撃パス」「成立扱いしてはいけない推定」「次に検証すべき高ROIの一手」を判断できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/attack/chain_builder.py`: **参照のみ**。旧APIであり `ExploitChain` 型を返す。attack_path_formatter の入力としては使用しない。
  - `src/core/intelligence/chain_builder.py`: **主入力源**。`AttackChain` / `AttackChainRule` 型を返し、`state`・`decision_trace`・`confidence`・`actor_path` を保持する。`analyze_hybrid()` の `draft_candidates` を canonical input とする。
  - `src/core/knowledge/models.py`: 修正。Node/Edge contract の Python dataclass 型定義を追加する（現状は空ファイル）。
  - `src/core/knowledge/schema.py`: 修正。`AttackPath`, `Decision`, `Task`, `ToolRun` のユニーク制約を追記する。
  - `src/core/knowledge/`: 確認。Neo4j node/edge schemaとの整合を見る。
  - `src/reporting/attack_path_formatter.py`: 新規。Markdown/Mermaidを生成する。
  - `scripts/shigoku_ops_cli.py`: 修正。`report attack-paths` の入口を追加する。
  - `tests/unit/reporting/test_attack_path_formatter.py`: 新規。graph出力とevidence区別を固定する。
- **データの流れ / 依存関係:**
  - session findings + target profile facts + chain candidates -> attack path builder/formatter -> `attack_paths.md`
  - optional export -> `attack_paths.json` / Neo4j ingest contract
  - Mermaid graph -> Markdown preview
  - Neo4j/UIは初期実装の必須範囲外

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - findings, target_url, affected endpoints, parameters, severity, confidence, evidence, decision_trace, scenario_coverage
  - optional target_profile sections
- **出力/結果 (Output):**
  - `attack_paths.md`: Overview, High-value paths, Candidate paths, Blocked/missing evidence paths, Mermaid graph, next validation steps
  - `attack_paths.json`: optional machine-readable graph for Neo4j export
  - Node contract: Target, Endpoint, Parameter, Finding, Task, Decision, ToolRun, AttackPath
  - Edge contract: HAS_ENDPOINT, HAS_PARAM, PRODUCED_FINDING, SUPPORTS_PATH, DEPENDS_ON, BLOCKED_BY, NEXT_VALIDATION
- **制約・ルール:**
  - raw finding、candidate chain、heuristic/backfillを明確に分ける。
  - Mermaidが巨大化する場合は上位N件とcritical/highパスに絞る。
  - Neo4j書き込みは初期版では必須にしない。schema/export契約までを完了条件にできる。
  - Neo4j接続が不可の場合でも `attack_paths.md` のMarkdown/Mermaid出力は正常に生成できること（graceful degradation必須）。`attack_paths.json` は Neo4j 接続不可時にローカルJSONとして書き出し、Neo4j ingest は後続バッチで実行可能にする。
  - report path指定時はconsistency checkerでsessionを解決してから生成する。

## 3.1 可視性・判断支援の表示原則
- [ ] 画面上部の要約で、少なくとも `Top 3 paths`、`blocked paths`、`next validation` を先に示し、詳細は後段に送る。
- [ ] 攻撃パスの状態語彙は `evidence_state` に統一し、以下のマッピング規則を定義する:
  - `AttackChain.state == "confirmed"` かつ `confidence >= 0.8` → `evidence_state: confirmed`
  - `AttackChain.state == "confirmed"` かつ `confidence < 0.8` → `evidence_state: candidate`（十分な証拠なしに confirmed に見せない）
  - `AttackChain.state in {"blocked", "draft"}` → `evidence_state: blocked`
  - session 外で推論された chain（`analyze_hybrid` の `ai_candidates` で `source == "proposal_engine"`） → `evidence_state: backfill`
  - この変換ロジックは `attack_path_formatter.py` に `_resolve_evidence_state()` 関数として実装し、unit test で全パターンを固定する。
- [ ] 各 path / node / edge に `finding_id`、`decision_id`、`task_id`、`source_event_ids`、`session_path` などの一次証跡参照を残す。
- [ ] High-value path の優先度は `asset criticality`、`exploitability`、`confidence`、`required preconditions`、`blast radius` を基準に決める。
- [ ] `attack_paths.md` の章立ては `Executive Summary -> Top Paths -> Candidate/Blocked Paths -> Mermaid Graph -> Blockers -> Next Validation` を基本順とする。
- [ ] Mermaid/Markdown の両方で `confirmed/candidate/blocked/backfill` を同じ凡例、バッジ、線種で表現し、見た目だけで昇格して見えないようにする。
- [ ] Mermaid の縮約ルールはデフォルト閾値を定義し、`config/shigoku.yaml` の `reporting.attack_paths` セクションで上書き可能にする:
  - `max_mermaid_nodes`: デフォルト 25
  - `max_mermaid_edges`: デフォルト 40
  - `max_top_paths`: デフォルト 5
  - `appendix_threshold`: Top Paths に含まれないかつ severity が medium 以下のパスは appendix に送る
- [ ] Node/Edge contract には機械処理用IDだけでなく、`display_label`、`why_in_path`、`blocked_reason`、`next_validation_hint`、`source_refs` を含める。
- [ ] 入力データ欠損時は推測で補わず、`No data in source session` と `inference_level` を明示する。
- [ ] 各 next validation step には `expected information gain` と `unblocks which blocker` を添え、次の一手の妥当性を説明できるようにする。
- [ ] 各 path に `observed_at` と `inferred_after` の時間軸を持たせ、後付け推定と現場証跡を混同しない:
  - `observed_at`: セッション JSON の `findings[].timestamp` または `events[].timestamp` から取得。存在しない場合は `session.started_at` をフォールバックとし `timestamp_source: "session_fallback"` を付記。
  - `inferred_after`: `attack_path_formatter` 実行時刻を ISO 8601 で記録。
  - いずれも欠損時は `null` とし「不明」と表示。推測値で埋めない。
- [ ] 実装完了判定は「レビューアが30秒で重要パス、未成立理由、次の一手を答えられること」を目安にする。

## 4. 実装ステップ（AIに指示する手順）

### Phase 1（MVP — 本タスクの完了条件）

- [ ] ステップ1: 既存chain builder、decision_trace、knowledge schema、session参照IDを棚卸しし、攻撃パスに使う一次証跡と欠損パターンを一覧化する。
  - `intelligence/chain_builder.py` の `AttackChain` / `analyze_hybrid()` を主入力源として確認する。
  - `attack/chain_builder.py` の `ExploitChain` は旧APIとして参照のみに留める。
- [ ] ステップ1.5: 既存Neo4jスキーマ（`schema.py` の constraint一覧 + 実DB上のノード/エッジ）と計画書の Node/Edge contract を突き合わせる。
  - 既存ノード/エッジとの命名・意味論の衝突がないことを確認する。
  - `Finding` ノードに `evidence_state` プロパティを追加する場合のマイグレーション方針を決める。
  - 新規 constraint を `schema.py` に追記し、`GraphSchema.apply_constraints()` でべき等に適用できることを確認する。
- [ ] ステップ2: `evidence_state` の語彙、§3.1のマッピング規則に基づく `_resolve_evidence_state()` の実装、欠損時表示、`No data in source session` の扱いを決め、表示ルールを fixture で固定する。
  - `ExploitChain` 由来の Finding（`additional_info` に `decision_trace` がない）でも crash しないことを保証するガード条件を設ける。
- [ ] ステップ3: `attack_paths.md` の章立て、Top Paths/Blocked Paths/Next Validation の先頭要約、凡例、バッジ、線種、時間軸表示を設計する。
- [ ] ステップ5: `src/core/knowledge/models.py` に `AttackPathNode`, `AttackPathEdge`, `AttackPathGraph` 等の Python dataclass 型定義を追加し、`display_label`、`why_in_path`、`blocked_reason`、`next_validation_hint`、`source_refs` を含む Node/Edge contract を決める。`attack_path_formatter.py` はこの models.py の型を import して使い、ad-hoc な dict 構築を避ける。
- [ ] ステップ6: `attack_path_formatter.py` にMarkdown/Mermaid出力を実装する。
  - Top Paths、Candidate/Blocked Paths、Mermaid Graph、Blockers、Next Validation を生成する。
  - Neo4j接続不可時でもMarkdown/Mermaid出力が正常に生成されること（graceful degradation）。
  - `additional_info.get("decision_trace", {})` のように安全アクセスし、旧 `ExploitChain` 由来 Finding でも crash しないことを保証する。
- [ ] ステップ9: unit tests と実 session artifact で検証する。
  - raw/candidate/backfill の分離、表示の誤認防止を確認する。
  - 以下の欠損パターンを必ず test fixture に含める:
    - findings が空 list のセッション
    - `decision_trace` が空 / None のチェーン
    - `confidence` が 0.0 のチェーン
    - `target_url` が `""` / `"Multiple"` / `"multiple"` のチェーン
    - `scenario_coverage` キーが存在しない旧形式セッション
    - `additional_info` が None（dict でない）Finding
    - chain_builder が 0件を返す正常ケース（Top Paths セクションが「なし」と表示されること）
  - 30秒レビュー検証プロトコル:
    - 実セッション artifact から `attack_paths.md` を生成し、以下3問に即答できるか確認する:
      1. 「今すぐ追うべき攻撃パスは何か？」→ Executive Summary / Top Paths から即答
      2. 「成立扱いしてはいけない推定はどれか？」→ `candidate` / `backfill` バッジで識別
      3. 「次に検証すべき一手は何か？」→ Next Validation の最優先項目が理由付きで記載
    - `tests/integration/test_attack_path_readability.py` にアサーション実装（Executive Summary 存在、Top Paths に最低1パス、Next Validation に最低1ステップ等）。

### Phase 2（後続イテレーション — 本タスク完了条件外）

- [ ] ステップ4: High-value path の5軸採点基準（asset criticality, exploitability, confidence, preconditions, blast radius）、Mermaid の縮約条件を定義する。
- [ ] ステップ7: `attack_paths.json` の任意出力とNeo4j export契約を定義し、Markdownで見えている状態分類とずれないようにする。既存Neo4jスキーマ（`schema.py`）に `AttackPath`, `Decision`, `Task`, `ToolRun` の constraint を追記する。
- [ ] ステップ8: `shigoku-ops report attack-paths` を追加する。
  - `_resolve_session_data()` を再利用してセッション解決する（`_run_report_narrative` と同じパターン）。
  - `VERIFICATION_TEST_MAP["report"]` に `tests/unit/reporting/test_attack_path_formatter.py` を追加する。
  - `--output-dir` オプションを設け、`attack_paths.md` の出力先を指定可能にする（他の report コマンドとの一貫性）。
- [ ] ステップ10: `observed_at` / `inferred_after` の時間軸を実装する（§3.1 のタイムスタンプ取得元定義に従う）。

## 5. 懸念点と対策（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] 攻撃パスが推定なのに成立済みのように見える。 - confidence/evidence_stateを必須表示にする。
- [ ] [重要度:中] UI/Neo4jまで含めると範囲が膨らむ。 - 初期はMarkdown/Mermaidを完了条件にする。
- [ ] [重要度:中] Mermaidグラフが読みにくくなる。 - top pathsとappendixに分ける。
- [ ] [重要度:高] ゴールが「見えること」に寄りすぎ、レビューアが何を判断できるべきか曖昧。 - Top Paths、未成立理由、次の一手を即答できる完成基準を置く。
- [ ] [重要度:高] `成立済み/候補/未検証` と `raw/candidate/backfill` が別語彙で混在し、状態解釈がぶれる。 - `evidence_state` の単一語彙と昇格条件に統一する。
- [ ] [重要度:高] Mermaidや本文から一次証跡へ戻れず、監査や再判断ができない。 - `finding_id`、`decision_id`、`task_id`、`source_event_ids`、`session_path` を必須表示にする。
- [ ] [重要度:高] `attack_paths.md` の章順が判断順になっておらず、重要判断が下に埋もれる。 - `Executive Summary -> Top Paths -> Candidate/Blocked -> Mermaid -> Blockers -> Next Validation` の順に固定する。
- [ ] [重要度:高] High-value path の定義が曖昧で、レビューアごとに優先順位が変わる。 - asset criticality、exploitability、confidence、preconditions、blast radius を採点軸として固定する。
- [ ] [重要度:中] 上位N件の縮約が未定義で、重要パスが図から消える。 - 最大ノード数、最大エッジ数、appendix送り条件、top paths選定基準を先に決める。
- [ ] [重要度:高] 見た目のつながりだけで「成立した攻撃チェーン」に見える危険がある。 - `confirmed/candidate/blocked/backfill` を凡例、バッジ、線種で厳格に分ける。
- [ ] [重要度:中] Node/Edge contract が機械処理寄りで、人が読むための説明属性が不足する。 - `display_label`、`why_in_path`、`blocked_reason`、`next_validation_hint`、`source_refs` を契約に追加する。
- [ ] [重要度:中] 欠損データを暗黙補完すると、セッションに無い情報があるように誤認される。 - 欠損時は `No data in source session` と `inference_level` を明示する。
- [ ] [重要度:中] Next Validation が単なるTODOになると、なぜその一手が最優先か伝わらない。 - `expected information gain` と `unblocks which blocker` を必須化する。
- [ ] [重要度:中] 後から補った推定と観測時点の事実が混ざり、時系列判断を誤らせる。 - `observed_at` と `inferred_after` を各 path に残す。
- [ ] [重要度:中] 実装完了判定が技術実装ベースだけだと、人間可視性の質が担保されない。 - 「30秒で重要パス、未成立理由、次の一手を答えられるか」をレビュー観点に追加する。

### 5.2 クロスレビュー懸念点（2026-06-25 追記 — SRE/アーキテクト/デバッガー/CTO観点）

- [ ] [SRE / 発生確率:高 / 影響度:大] Neo4j接続不可時のgraceful degradation未設計。 - `driver.py` が接続失敗時に `raise` しており、Markdown生成もろとも停止する。→ §3制約に graceful degradation 必須を追加済み。ステップ6で Neo4j 不在でも Markdown/Mermaid 出力が正常生成されることを保証する。
- [ ] [SRE / 発生確率:中 / 影響度:大] Mermaidグラフのサイズ上限デフォルト値未定義。 - 実セッション finding 50〜200件で Mermaid 30ノード超のブラウザ描画劣化。→ §3.1にデフォルト閾値（max_mermaid_nodes: 25, max_mermaid_edges: 40, max_top_paths: 5）を追加済み。
- [ ] [SRE / 発生確率:中 / 影響度:中] Neo4jスキーマの破壊的変更リスク管理未計画。 - 既存の `Finding -> AFFECTS -> Endpoint` との関係整理が未定義。→ ステップ1.5で既存スキーマとの突合を追加済み。
- [ ] [アーキテクト / 発生確率:高 / 影響度:大] 2つのchain_builderの入力源が不明。 - `attack/chain_builder.py`（`ExploitChain`）と `intelligence/chain_builder.py`（`AttackChain`）は型も構造も異なる。→ §2で `intelligence/chain_builder.py` を主入力源と明記済み。2つの統合/非推奨化は SGK-2026-0302-D02 として backlog に記録する。
- [ ] [アーキテクト / 発生確率:高 / 影響度:大] `evidence_state` と既存 `AttackChain.state` のマッピング未定義。 - `evidence_state` はコードベース全体で0件の完全新規概念。→ §3.1にマッピング規則（`_resolve_evidence_state()`）を追加済み。
- [ ] [アーキテクト / 発生確率:高 / 影響度:中] `knowledge/models.py` が空ファイル — Node/Edge contract の実装基盤なし。→ ステップ5で `models.py` に dataclass 型定義を追加するよう明記済み。
- [ ] [デバッガー / 発生確率:高 / 影響度:中] 入力欠損パターンの網羅テスト設計がない。 - `decision_trace` 空、`confidence` 0、`target_url` 空文字、`scenario_coverage` 不在、`additional_info` が None 等。→ ステップ9に欠損パターン fixture 一覧を追加済み。
- [ ] [デバッガー / 発生確率:中 / 影響度:大] 2つの `to_finding()` の `additional_info` 構造差でサイレント crash。 - `ExploitChain.to_finding()` は `{"chain_details": str}` のみ、`AttackChain.to_finding()` は `decision_trace` 等を含む。→ ステップ2・6で安全アクセスとガード条件を明記済み。
- [ ] [デバッガー / 発生確率:中 / 影響度:中] `observed_at` / `inferred_after` のタイムスタンプ取得元不明。 - `Finding` にタイムスタンプ属性が存在せず、セッション JSON 経由では利用不可の可能性。→ §3.1にフォールバック規則を追加済み。Phase 2 ステップ10で実装。
- [ ] [CTO / 発生確率:高 / 影響度:大] MVPスコープが事実上フル実装と区別がつかない。 - §3.1で12項目、§4で9ステップは初期版として過剰。→ Phase 1（MVP）/ Phase 2（後続）に分割済み。
- [ ] [CTO / 発生確率:中 / 影響度:中] `shigoku-ops` CLI の既存 report サブコマンド体系との整合未確認。 - `_resolve_session_data()` 再利用、`VERIFICATION_TEST_MAP` 登録等が未定義。→ ステップ8に既存パターン準拠の詳細を追加済み。
- [ ] [CTO / 発生確率:中 / 影響度:中] 30秒レビューの検証プロトコル未形式化。 - 実装者セルフチェックだけでは作成者バイアスで品質ゲート不成立。→ ステップ9に3問チェックリスト + integration test を追加済み。

### 5.3 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0302-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
