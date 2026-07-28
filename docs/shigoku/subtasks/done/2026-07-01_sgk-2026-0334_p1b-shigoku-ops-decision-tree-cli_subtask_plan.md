---
task_id: SGK-2026-0334
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/plans/done/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
- docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0322_reconstate-completion-parallel-checkpoint-decision-tree_subtask_plan.md
- docs/shigoku/plans/done/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- docs/shigoku/subtasks/done/2026-06-24_sgk-2026-0300_run-narrative-target-profile-markdown_subtask_plan.md
title: 'P1b: 判断ツリー可視化＋shigoku-ops decision-tree CLI'
created_at: '2026-07-01'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/reporting/, scripts/shigoku_ops_cli.py
---

# 実装計画書：P1b: 判断ツリー可視化＋shigoku-ops decision-tree CLI

## 1. 達成したいゴール（ユーザー視点）
- [ ] `shigoku-ops report decision-tree --session <path>` または `--report <path>` を実行すると、Recon→MC→Swarm入口→Report の判断と結果が、一次証拠由来の Markdown / Mermaid ツリーとして読める。
- [ ] 運用者が失敗ノード、重要判断、再開判断だけを絞り込んで見られ、中断後の再実行判断に使える。
- [ ] 巨大 session や親子リンク欠落があっても壊れず、縮約表示や degrade 表示で「読めるが推測しない」出力になる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/reporting/decision_tree_formatter.py`: `run_ledger` / `decision_traces` / `task_execution_records` / checkpoint metadata から判断ツリーを構築する formatter。
  - `src/reporting/`: 必要なら既存 reporting helper を再利用し、一次証拠抽出と redaction を共有する。
  - `scripts/shigoku_ops_cli.py`: `report decision-tree` サブコマンドと表示オプション。
- **データの流れ / 依存関係:**
  - `session_*.json` の `run_ledger` + `decision_traces` + `task_execution_records` + checkpoint metadata -> formatter が親子関係と補助情報を構築 -> Markdown / Mermaid と要約を生成
  - `shigoku-ops report decision-tree --session ...` -> session 読み込み -> formatter -> `decision_tree.md` または stdout 表示
  - `shigoku-ops report decision-tree --report ...` -> report/session consistency check -> source session 解決 -> formatter -> `decision_tree.md` または stdout 表示

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** session artifact (`run_ledger`, `decision_traces`, `task_execution_records`), 必要に応じて SGK-2026-0322 の checkpoint metadata (`artifact_refs`, resume/rerun 判定に関係する field)
- **出力/結果 (Output):**
  - `decision_tree.md`（Mermaid `graph TD` + Markdown summary + degrade summary）
  - `--phase` / `--actor` / `--only-failures` / `--max-nodes` などで絞り込んだ CLI 出力
  - `--json` / `--json-envelope` で `status`, `reason_codes`, `markdown`, `output` を返す機械可読出力
  - 親子リンク欠落や情報不足時の degrade 表示（推定は `estimated`、孤立は `unlinked`、制限到達は `degraded` を明記）
- **制約・ルール:**
  - 一次証拠（session/ledger）由来のみを表示し、推定は `estimated` を明記する。
  - `run_ledger` を時系列の正本、`decision_traces` を判断詳細、`task_execution_records` を実行補助、checkpoint metadata を再開判断補助として扱い、優先順位を固定する。
  - secret/PII は既存 redactor 済みデータを優先しつつ、formatter 出力直前にも nested dict/list と `source_refs` を再帰確認して再 redaction する。
  - 巨大 session では phase/actor 畳み込みとノード上限で既定表示を抑制し、全文展開を既定にしない。上限超過時は `status=degraded` と `reason_codes` を返す。
  - ノードは `event_id` / `decision_id` / `task_id` / `source_refs` の少なくとも1つで元証拠へたどれるようにし、並び順は `timestamp` -> `event_id` の安定ソートに固定する。
  - Mermaid / Markdown / stdout に出す文字列は escape し、prompt全文・raw request/response・cookie・header・tool command 全文は allowlist 外として表示しない。
  - `--report` 指定時は report/session consistency check が `consistent` の場合のみ生成する。
  - Swarm 内部の think ループ詳細までは扱わず、対象は `Recon→MC→Swarm入口→Report` の判断に限定する。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 既存 `report narrative` / `report attack-paths` / `SGK-2026-0322` の checkpoint 契約を確認し、decision-tree の入力契約表を作る。`run_ledger` を正本にする優先順位、`decision_traces` / `task_execution_records` / checkpoint metadata の補助役割、必須フィールド、`estimated` / `unlinked` / `degraded` の発火条件、安定ソート規則、reason code 一覧をここで固定する。
- [ ] ステップ2: `src/reporting/decision_tree_formatter.py` に内部 contract（ノード/エッジ/要約）を定義する。各ノードが `event_id` / `decision_id` / `task_id` / `source_refs` の少なくとも1つを保持し、`link_status`, `degrade_reason`, `missing_fields` を持てるようにして、後段の renderer と CLI から同じ情報を再利用できる形にする。
- [ ] ステップ3: `run_ledger` を主系にしたツリー構築を実装する。`parent_event_id` のチェーンを第一優先で結び、`decision_id` / `task_id` を補助キーにして Recon→MC→Swarm入口→Report の判断系列を復元し、失敗ノード・重要判断・再開判断を優先抽出する。
- [ ] ステップ4: `decision_traces` / `task_execution_records` / checkpoint metadata を補助情報として接続する。リンクできない項目は補完推測せず `unlinked`、証拠不足の再開判断は `estimated`、artifact provenance 不一致は `rerun_required` 相当の警告で退避し、summary に理由を残す。
- [ ] ステップ5: Markdown / Mermaid renderer を実装する。巨大 session 向けの `max_nodes` / `max_edges` / `max_depth` / `max_children_per_node` を既定化し、上限超過時は畳み込みと `status=degraded` を返す。Mermaid/Markdown/stdout 用の escape と、nested `source_refs` を含む再 redaction もここで適用する。
- [ ] ステップ6: `scripts/shigoku_ops_cli.py` に `report decision-tree` サブコマンドを追加する。`--session`, `--report`, `--sessions-dir`, `--output`, `--phase`, `--actor`, `--only-failures`, `--max-nodes`, `--json`, `--json-envelope` を接続し、`--report` 時は consistency check を通過した場合のみ出力する。あわせて `VALIDATION_SUITES` と `--help` を更新し、既存 `report` サブコマンドと同じ exit code / payload ルールへ合わせる。
- [ ] ステップ7: targeted tests を追加する。formatter と CLI の両方で、正常系、legacy session、親子リンク欠落、巨大 session の縮約、checkpoint metadata 連携、stable sort、`estimated` / `unlinked` / `degraded` 表記、nested secret/PII redaction、Mermaid/Markdown 文字列 escape、`--report` inconsistency block、各絞り込みオプションを検証する。
- [ ] ステップ8: `.venv/bin/pytest` で formatter/CLI の targeted tests を先に実行し、その後に実 session artifact で `decision_tree.md` と CLI 出力を確認する。実 report がある場合は consistency checker を通した `--report` 経路も確認し、運用者が 1 回の表示で「失敗点」「再開可否」「根拠ID」を判断できる粒度かを完了条件として確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] 巨大 session はツリー全展開だと読めなくなる。phase/actor 畳み込みと `--only-failures` を既定運用に寄せる。
- [ ] [重要度:中] 親子リンクが不完全な古い session では、一部ノードが孤立表示になる。リンク補完は推測せず `estimated` / `unlinked` として退避する。
- [ ] [重要度:中] Swarm 内部の thought/action 詳細統合は本タスク外。詳細統合は SGK-2026-0293 系の設計に委ねる。

### 5.1 懸念点と対策

#### SRE/インフラエンジニア視点
- [ ] [SRE-1][発生確率:高][影響度:大] 巨大 session のとき、どこで表示を打ち切るかが未定だと CLI が重くなり、運用で使いにくくなる。
  修正案: ステップ1とステップ5に `max_nodes` / `max_edges` / `max_depth` / `max_children_per_node` の既定値定義と `status=degraded` / `reason_codes` 返却を明記し、縮約条件を仕様化する。
- [ ] [SRE-2][発生確率:高][影響度:大] `--report` 経路の整合性確認が計画に入っていないと、古い report と別 session を混ぜて誤判断する。
  修正案: ゴール・仕様・ステップ6・ステップ8に `--report` / `--sessions-dir` と consistency check 成功時のみ生成する条件を追加し、`blocked` / `reason_codes` の返却を固定する。
- [ ] [SRE-3][発生確率:中][影響度:大] 自動運用で使うには終了コードと JSON 契約が曖昧で、CI や運用スクリプトから分岐しにくい。
  修正案: 仕様に `--json` / `--json-envelope` の payload 項目と exit code ルールを追加し、ステップ6とステップ7で既存 `shigoku-ops` の contract にそろえる。

#### ソフトウェアアーキテクト視点
- [ ] [ARCH-1][発生確率:高][影響度:大] `run_ledger` / `decision_traces` / `task_execution_records` / checkpoint metadata の優先順位が曖昧なままだと、同じ判断が二重表示されたり矛盾が出る。
  修正案: 仕様とステップ1で「`run_ledger` は正本、`decision_traces` は判断詳細、`task_execution_records` は補助、checkpoint metadata は再開判断補助」と役割を固定する。
- [ ] [ARCH-2][発生確率:中][影響度:大] decision tree の内部データ構造が未定義のままだと、formatter 内に ad-hoc な dict が増えて保守しづらい。
  修正案: ステップ2にノード/エッジ/要約の内部 contract 定義を追加し、`link_status`, `degrade_reason`, `missing_fields` を共通フィールドとして持たせる。
- [ ] [ARCH-3][発生確率:中][影響度:大] 古い session や欠損 session の reader 互換方針が弱いと、後方互換を崩しやすい。
  修正案: ステップ1で legacy fallback 条件を定義し、ステップ7で legacy session fixture と欠損フィールド系テストを明示する。

#### デバッガー視点
- [ ] [DBG-1][発生確率:高][影響度:大] ツリーだけ見ても元証拠へ戻れないと、「なぜこう表示されたか」を追跡しにくい。
  修正案: 仕様とステップ2に、各ノードは `event_id` / `decision_id` / `task_id` / `source_refs` の少なくとも1つを持つことを必須条件として追加する。
- [ ] [DBG-2][発生確率:高][影響度:中] `estimated` / `unlinked` / `degraded` が出ても、理由が表示されないと調査の初手で止まる。
  修正案: ステップ2・4・5に `degrade_reason`, `missing_fields`, `link_status`, `reason_codes` を summary へ出す処理を追加する。
- [ ] [DBG-3][発生確率:中][影響度:中] 並び順が不安定だと、同じ session でも出力差分が揺れて regression 判定に向かない。
  修正案: 仕様とステップ1に `timestamp` -> `event_id` の安定ソート規則を追記し、ステップ7で snapshot / golden test を追加する。

#### ハッカー視点
- [ ] [SEC-1][発生確率:高][影響度:大] `decision_traces` や `task_execution_records` 側で secret/PII が十分に消えていない場合、そのまま decision tree に出る危険がある。
  修正案: 仕様とステップ5に、出力直前の再 redaction を必須化し、nested dict/list と `source_refs` を再帰的に確認する処理を組み込む。
- [ ] [SEC-2][発生確率:中][影響度:大] Mermaid や Markdown に危険な文字列をそのまま流すと、図崩れや誤読を起こす。
  修正案: ステップ5とステップ7に Mermaid/Markdown/stdout 用 escape と悪意ある文字列 fixture テストを追加する。
- [ ] [SEC-3][発生確率:中][影響度:大] どの field を表示してよいかの allowlist がないと、raw request/response や command 全文が混ざる余地が残る。
  修正案: 仕様に表示 allowlist を明記し、ステップ1とステップ5で「prompt全文・raw request/response・cookie・header・tool command 全文は出さない」を固定する。

#### CTO視点
- [ ] [CTO-1][発生確率:中][影響度:大] 完了条件が「読める」だけだと、運用者価値が測れず、実装の良し悪しを判定しづらい。
  修正案: ゴールとステップ8に「1回の表示で失敗点・再開可否・根拠IDを判断できる」を受け入れ条件として追記する。
- [ ] [CTO-2][発生確率:高][影響度:大] SGK-2026-0322 から受ける checkpoint metadata の使い方が曖昧なままだと、P1a と P1b の契約がまたずれる。
  修正案: 仕様 Input とステップ1・4に、checkpoint metadata のうち `artifact_refs` と resume/rerun 判定に関係する field をどこで使うか明記する。
- [ ] [CTO-3][発生確率:高][影響度:中] CLI 追加だけで終わると、運用側から見た導線が半端になり、保守時に見つけにくい。
  修正案: ステップ6に `VALIDATION_SUITES` / `--help` 更新を追加し、ステップ8で実 CLI 導線の確認を完了条件へ含める。

### 5.2 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0334-D01
    title: "継続監視: Swarm内部判断ログの decision tree 統合"
    reason: "本タスクは Recon→MC→Swarm入口→Report に限定し、Swarm内部詳細は対象外"
    impact: medium
    tracking_task_id: SGK-2026-0293
    recommended_next_action: "SGK-2026-0293 系で execution trace の粒度と decision tree 連携契約を設計する"
```
