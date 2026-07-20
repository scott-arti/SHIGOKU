---
task_id: SGK-2026-0281
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0278
related_docs:
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
- docs/shigoku/roadmaps/future_functions1.md
title: 'Recon運用再設計: Resume・再利用・Recipe/PhaseGate連携計画'
created_at: '2026-06-20'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/recon/, src/core/engine/recipe_loader.py, src/core/engine/phase_gate.py,
  src/core/engine/master_conductor.py
---

# 実装計画書：Recon運用再設計: Resume・再利用・Recipe/PhaseGate連携計画

## 1. 達成したいゴール（ユーザー視点）
- 長い Recon が中断しても、途中成果を活かして再開できる。
- 既知ターゲットでは過去 Recon 成果物を再利用し、無駄な再走査を減らせる。
- Recon 結果が `RecipeLoader` と `PhaseGate` に賢く渡り、Attack 開始が「全部解放」ではなく「必要なものから解放」になる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/`: Step 単位 resume / artifact reuse の中心
  - `src/core/engine/master_conductor.py`: Recon 完了後の task 生成と gate 制御
  - `src/core/engine/recipe_loader.py`: context から recipe を選ぶ
  - `src/core/engine/phase_gate.py`: Phase unlock と phase data 蓄積
- **データの流れ / 依存関係:**
  - Recon state / prior artifacts -> ReconPipeline -> normalized results
  - normalized results -> `PhaseGate` / `_create_attack_tasks_from_recon()`
  - target_info / tech_stack / signals -> `RecipeLoader.match_recipes_to_context()`

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - Recon step range, intermediate state, prior project artifacts, tech stack, classified results
- **出力/結果 (Output):**
  - Step 単位 resume 可能な Recon 実行
  - `--import-recon` 相当の artifact reuse
  - score-based recipe selection
  - 粒度の細かい `PhaseGate` 制御案
- **制約・ルール:**
  - `タグベース動的Agent選択` は次期バージョン送りとし、本計画では扱わない
  - `RecipeLoader` は全面作り直しではなく、現行接続を生かした選抜改善を優先する
  - `PhaseGate` は MC 代替ではなく、MC の判断材料を細かくする部品として扱う

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `src/recon/pipeline.py`、`src/core/engine/master_conductor.py`、`src/core/engine/recipe_loader.py`、`src/core/engine/phase_gate.py` を棚卸しし、すでに存在する `resume` / `import-recon` / score-based recipe selection / granular gate の現行仕様と、本計画で追加すべき差分をギャップ表として固定する
- [ ] ステップ2: `resume` の正本経路を定義し、CLI / InteractiveBridge / MasterConductor の全経路で `ReconState.validate_for_resume()` または `resolve_resume_start_step()` 相当の共有判定を通す設計へ寄せる。`target_fingerprint` 不一致、破損 state、完了済み state は fail-closed とし、`resume_verdict.reason_code` / `resume_source` / `diff_base_run_id` を必須診断項目として残す
- [ ] ステップ3: `--import-recon` の受理契約を明文化し、`target_fingerprint` 一致、freshness 閾値充足、`artifact_hash` / `import timestamp` / provenance 保持を受理条件として定義する。stale / mismatch / provenance 欠落 artifact は「情報表示のみ」で、ATTACK 解放や task 生成には使わない
- [ ] ステップ4: `resume_verdict`、`_import_provenance`、`AttackSurfaceSignal`、`RecipeCandidate` のデータ契約を表形式で固定し、どのコンポーネントがそれぞれの正本 writer / reader かを責務境界表として追記する
- [ ] ステップ5: `RecipeLoader.match_recipes_to_context()` の運用方針として、score threshold、per-category top-N、suppression key、`manual_review_required`、`low_confidence`、`unsupported_action`、`suppression_active` 時の分岐（recipe 実行 / swarm fallback / HITL 保留）を decision matrix として定義する
- [ ] ステップ6: `PhaseGate` と `_create_attack_tasks_from_recon()` の連携条件を定義し、ATTACK 解放は「count > 0」ではなく「in-scope かつ actionable な signal / category が存在すること」を条件とする。scope / auth / budget / stale import / critical finding をカテゴリ単位で判定し、`gate_reasons` を必須記録にする
- [ ] ステップ7: task explosion と運用事故を防ぐため、derived task 上限、signal ごとの top-N、degraded mode、manual review 比率の監視項目を定義し、過剰 task 生成時の fail-soft 条件を計画へ組み込む
- [ ] ステップ8: 検証と段階導入の計画を追加し、`resume` failure path、stale import、scope/auth/budget 拒否、manual review / suppression 分岐、CLI 後方互換 (`--recon-resume` / `--recon-start-step` / `--import-recon`) をテストマトリクス化する。あわせて feature flag と rollback 条件を定義する

## 4.1 フェーズ分割
- Phase A: Recon step 単位 resume
- Phase B: 過去 Recon 成果物の再利用
- Phase C: Recipe 選抜改善
- Phase D: PhaseGate 細粒度化
- Phase E: 検証・段階導入・運用監視

## 4.2 いま不足していること
- `ReconState.validate_for_resume()` / `resolve_resume_start_step()` は存在するが、`MasterConductor` 側で resume state を直接読む経路が残っており、共有 validator を必ず通す設計が本文に固定されていない
- `RecipeLoader.match_recipes_to_context()` は score / suppression / `manual_review_required` を返せるが、threshold、top-N、fallback、HITL 条件の運用 decision matrix が本文に固定されていない
- `PhaseGate.can_create_attack_task()` は scope / auth / budget / stale import を見られるが、ATTACK 解放自体は Recon 結果件数ベースに寄りやすく、actionable 判定と観測項目が不足している
- `--import-recon` の load / merge 基盤はあるが、artifact hash、fingerprint、freshness、provenance の fail-closed 契約が本文に十分明記されていない

## 4.3 細粒度 PhaseGate の価値
- scope 逸脱や予算超過で Attack 全体を止めやすくなる
- auth 必須 endpoint と public endpoint を同じ熱量で解放しなくてよくなる
- critical finding 発生後に Report/HITL 優先へ寄せる判断を実装しやすくなる

## 5. 懸念点と対策

### 5.1 SRE / インフラ視点
- 【発生確率:高】【影響度:大】`resume` 失敗、import reject、ATTACK 未解放の理由が本文上の必須観測項目になっておらず、運用で停止理由を追いにくい。対策: `resume_verdict.reason_code`、`resume_source`、`gate_reasons`、accepted/rejected artifact 件数、`all_rejected` を「必須ログ / サマリー項目」として本計画書に追加する
- 【発生確率:高】【影響度:大】artifact reuse を freshness / provenance 契約なしで進めると、古い成果物の混入や誤った ATTACK 解放を招きやすい。対策: `target_fingerprint` 一致、freshness 閾値、`artifact_hash`、import timestamp、provenance を受理条件として本文へ昇格し、欠落時は fail-closed と明記する
- 【発生確率:中】【影響度:大】signal-first routing と recipe routing の組み合わせで task explosion が起こると、キュー逼迫や運用劣化が起きやすい。対策: per-category top-N、derived task 上限、degraded mode、manual review 比率の監視項目を計画に追加する

### 5.2 ソフトウェアアーキテクト視点
- 【発生確率:高】【影響度:大】本文の「いま不足していること」が現行コードとずれていると、既存実装の再実装や責務の二重化を招く。対策: 「既存実装」「不足差分」「回帰禁止」を並べたギャップ表を追加し、差分実装計画として書き直す
- 【発生確率:高】【影響度:大】`ReconPipeline`、`MasterConductor`、`RecipeLoader`、`PhaseGate` の責務境界が本文で固定されておらず、判断ロジックの置き場がぶれやすい。対策: resume 判定、import merge、recipe score、attack gate の各正本コンポーネントを責務境界表で明示する
- 【発生確率:中】【影響度:大】辞書ベースの入出力契約が文書化されていないため、キー追加や reader 側の取り違えで壊れやすい。対策: `resume_verdict`、`_import_provenance`、`AttackSurfaceSignal`、`RecipeCandidate` の必須フィールド表を本計画へ追加する

### 5.3 デバッガー視点
- 【発生確率:高】【影響度:大】failure path の検証観点が計画に無いまま進めると、実装後に再現しづらい不具合が残りやすい。対策: `no_state_file`、`corrupt_state`、`target_mismatch`、`already_completed`、stale import、auth 不足、scope 外、manual review、suppression を含む検証マトリクスを追加する
- 【発生確率:高】【影響度:中】resume / checkpoint / gate の診断に必要な状態が必須記録になっておらず、再現時に情報不足になりやすい。対策: `run_id`、`diff_base_run_id`、`completed_steps`、`resume_reason`、`last_resume_decision`、`gate_reason` を必須診断項目として本文へ追加する
- 【発生確率:中】【影響度:中】`manual_review_required`、`low_confidence`、`suppression_active`、`unsupported_action` の分岐が曖昧だと、同じ入力でも挙動がぶれやすい。対策: recipe 実行、swarm fallback、HITL 保留の 3 分岐 decision matrix を本文で固定する

### 5.4 ハッカー視点
- 【発生確率:高】【影響度:大】`MasterConductor` 側に raw state load が残ると、共有 validator を通さない resume 経路が残り、安全条件をすり抜けやすい。対策: `ReconState.load()` の直接利用は shared validator 配下に限定し、CLI / Bridge / MC の全経路で共有判定を通すことを本文へ明記する
- 【発生確率:高】【影響度:大】Recon 結果件数だけで ATTACK を解放すると、価値の低い分類や誤分類から不要な攻撃タスクが広がりやすい。対策: ATTACK 解放条件を「in-scope かつ actionable な signal / category の存在」に置き換えることを本文へ追記する
- 【発生確率:中】【影響度:大】import merge に fingerprint / hash / timestamp 契約がないと、cross-target 汚染や改ざん混入に弱い。対策: `target_fingerprint`、`artifact_hash`、import timestamp、source provenance のいずれか欠落時は merge / unlock / task generation を禁止する

### 5.5 CTO 視点
- 【発生確率:高】【影響度:大】成功条件が定量化されていないと、完了判断が主観的になりやすい。対策: `resume` 成功率、stale import 誤採用ゼロ、不要 ATTACK task 削減率、manual review 比率などの計測指標を計画書へ追加する
- 【発生確率:中】【影響度:大】resume、import、selector、gate を同時に変えると切り戻しが難しい。対策: resume hardening、import fail-closed、deterministic recipe selection、granular gate enforcement を個別 feature flag で段階導入する方針を追記する
- 【発生確率:中】【影響度:中】CLI 引数の意味が暗黙に変わると既存運用が壊れやすい。対策: `--recon-resume`、`--recon-start-step`、`--import-recon` の後方互換を維持し、変更時は help 文と回帰テスト更新を必須にする

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] artifact reuse を急ぐと古い成果物の混入で誤判定しやすい - freshness 判定と provenance を先に設計する
- [ ] [重要度:中] recipe score を粗く入れると全件返しと大差ない - required/optional signal と top-N 制限を必須にする

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0281-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```

## 7. DeepSeekV4pro 実装指示

### 7.1 このタスクで達成すべきこと
- 既存の `resume` / `import-recon` / recipe selector / `PhaseGate` の土台を壊さずに、正本経路・受理契約・分岐条件・観測項目を追加して本流に接続すること
- 「新しい仕組みを全面作り直す」のではなく、「既存の reader / writer / gate を additive に硬化する」こと
- 最終的に、`resume` は共有 validator 経由、`import-recon` は fail-closed、recipe routing は decision matrix 付き、ATTACK 解放は actionable 条件付きになること

### 7.2 変更対象の正本
- `src/recon/pipeline.py`
  - `ReconState.validate_for_resume()`
  - `resolve_resume_start_step()`
  - checkpoint / diff / resume_reason の保存契約
- `src/core/engine/master_conductor.py`
  - Recon 実行前後の resume state 取込
  - `_load_import_recon_bundle()`
  - `_merge_imported_recon_results()`
  - `_create_attack_tasks_from_recon()`
- `src/core/engine/recipe_loader.py`
  - `match_recipes_to_context()`
  - `manual_review_required` / suppression / score まわり
- `src/core/engine/phase_gate.py`
  - `can_create_task()`
  - `can_create_attack_task()`
  - `gate_reasons` / summary
- `src/main.py` / `src/core/conductor/interactive_bridge.py`
  - `--recon-resume` / `--recon-start-step` / `--import-recon` の後方互換と shared resume path 維持

### 7.3 実装の厳守方針
- `RecipeLoader` を全面再設計しない。既存の signal / suppression / score の流れを活かして必要最小限で拡張すること
- `MasterConductor` から raw `ReconState.load()` を自由に呼ばない。resume 判定は共有 validator / resolver 配下へ寄せること
- `import-recon` は permissive にしない。`target_fingerprint`、freshness、provenance、`artifact_hash` 欠落時は fail-closed を優先すること
- ATTACK 解放条件を単純な `count > 0` のまま残さない。`in-scope` かつ actionable な signal / category の存在を基準にすること
- 旧 payload (`classified_files`, `file/count`, 互換 artifact) を即削除しない。reader を先に対応させ、互換経路は fallback として残すこと
- 新しい依存ライブラリを増やさない。標準ライブラリまたは既存コードで足りる形にすること

### 7.4 推奨する実装順序
1. 先に characterization / regression テストを書く
   - `resume` の共有経路
   - stale / mismatch import の reject
   - recipe selector の `manual_review_required` / suppression / threshold 分岐
   - `PhaseGate` の actionable gate / `gate_reasons`
2. `pipeline.py` の validator / resolver を正本化する
   - `validate_for_resume()` の reason code 契約を固定
   - `resolve_resume_start_step()` が CLI / Bridge / MC で共有されるようにする
3. `master_conductor.py` の resume 取込を shared path へ寄せる
   - raw load の前に共有 verdict を得る
   - `resume_verdict.reason_code`、`resume_source`、`diff_base_run_id` を残す
4. `import-recon` の受理契約を harden する
   - fingerprint / freshness / provenance / hash 条件を一か所で判定
   - stale は informational-only
   - mismatch / missing provenance は merge / unlock / task generation 禁止
5. `recipe_loader.py` に decision matrix を落とし込む
   - score threshold
   - per-category top-N
   - `manual_review_required`
   - `low_confidence`
   - `unsupported_action`
   - `suppression_active`
   - それぞれの結果を `recipe実行 / swarm fallback / HITL保留` に決め打ちする
6. `phase_gate.py` と `_create_attack_tasks_from_recon()` を接続する
   - ATTACK 解放条件を actionable 基準へ変更
   - scope / auth / budget / stale import / critical finding を category 単位で扱う
   - `gate_reasons` を summary へ出す
7. 観測項目と CLI 互換を仕上げる
   - `--recon-resume`
   - `--recon-start-step`
   - `--import-recon`
   - help 文 / message key / task metadata / summary を整合させる
8. 最後に docs / graph / worklog を更新する

### 7.5 実装時の具体ルール
- `resume`:
  - `no_state_file`
  - `corrupt_state`
  - `target_mismatch`
  - `already_completed`
  - `ok`
  の reason code を tests で固定すること
- `import-recon`:
  - accepted / rejected / stale を曖昧にしないこと
  - ATTACK 解放可否に使うのは accepted artifact のみ
  - provenance は `_import_provenance` に集約し、reader 側で別名を増やさないこと
- recipe selector:
  - `supporting_evidence`、`reasons`、`manual_review_required`、`suppression_reason` を必ずトレース可能にすること
  - score だけでなく「なぜその分岐になったか」を task params / logs に残すこと
- `PhaseGate`:
  - 「止める理由」を `gate_reasons` に残し、失敗を silent skip にしないこと
  - `critical finding` は即 reject 固定ではなく、report/HITL 優先へ回せる余地を残すこと

### 7.6 追加・更新すべきテスト
- `tests/unit/recon/test_recon_state_checkpoint.py`
  - shared resume path の reason code / start_step / override
- `tests/unit/engine/test_master_conductor_import_recon.py`
  - fingerprint mismatch
  - provenance 欠落
  - stale informational-only
  - accepted artifact のみ task generation 対象
- `tests/unit/engine/test_recipe_selector.py`
  - threshold / top-N / suppression / `manual_review_required` / fallback reason
- `tests/unit/engine/test_phase_gate_granularity.py`
  - actionable gate
  - `gate_reasons`
  - ATTACK unlock 条件
- `tests/unit/main/test_import_recon_cli.py`
  - CLI 後方互換
  - help key
  - pass-through 維持
- 必要なら `master_conductor` 系の targeted test を追加し、resume raw-load bypass が再発しないことを固定する

### 7.7 実行すべき検証コマンド
- まず targeted tests を通す
  - `.venv/bin/pytest tests/unit/recon/test_recon_state_checkpoint.py`
  - `.venv/bin/pytest tests/unit/engine/test_master_conductor_import_recon.py`
  - `.venv/bin/pytest tests/unit/engine/test_recipe_selector.py`
  - `.venv/bin/pytest tests/unit/engine/test_phase_gate_granularity.py`
  - `.venv/bin/pytest tests/unit/main/test_import_recon_cli.py`
- その後、変更範囲に応じて関連する `master_conductor` / routing テストを追加実行する
- docs を更新した場合のみ:
  - `python3 scripts/sync_shigoku_updated_at.py`
  - `python3 scripts/validate_shigoku_docs.py`
- コード変更後は `graphify update .` を実行して graph を更新する

### 7.8 完了条件
- shared resume path が CLI / Bridge / MC で一貫する
- `import-recon` が stale / mismatch / provenance 欠落で fail-closed する
- ATTACK 解放が actionable 条件に変わる
- recipe selector の decision matrix が tests と task trace の両方で確認できる
- targeted tests が通る
- docs を触った場合は SHIGOKU docs validator が 0 error
