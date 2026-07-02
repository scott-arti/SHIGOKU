---
task_id: SGK-2026-0253
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0251
related_docs:
- docs/shigoku/plans/2026-06-01_sgk-2026-0251_task_plan.md
title: 脆弱性チェーンルール拡張と program overrides 整備
created_at: '2026-06-02'
updated_at: '2026-07-02'
tags:
- shigoku
target: attack-chain-rules
---

# 実装計画書：脆弱性チェーンルール拡張と program overrides 整備

## 1. 達成したいゴール（ユーザー視点）
- [x] program / 業種情報を与えると、その文脈に合う chain rule と probing policy が優先適用されること。
- [x] 本 subtask では新しい probe 戦略自体は追加せず、既存戦略に対する rule / workflow / policy の解決順序と安全適用のみを整備すること。
- [x] `industry` / `program_override` に応じた解決結果の一貫性と安全性を高め、運用上の probe 判断と監査の説明可能性を改善すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `data/attack_chain_rules.json`: （修正）業種別 rule、workflow template、program override
  - `src/core/intelligence/chain_builder.py`: （修正）industry / override 適用
  - `src/core/engine/master_conductor.py`: （修正）program policy 反映
  - `tests/core/intelligence/test_chain_builder.py`: （修正）rule selection / workflow fallback / broken JSON fallback の検証
  - `tests/core/engine/test_master_conductor_phase1_step14.py`: （修正）program policy precedence / blocked/defer / budget 制御の検証
- **データの流れ / 依存関係:**
  - program metadata / industry -> rule selection -> workflow template / policy merge -> chain evaluation / probe planning
- **責務境界:**
  - `src/core/intelligence/chain_builder.py`: rule / workflow 解決の正本
  - `src/core/engine/master_conductor.py`: runtime guard / safety gate / audit 記録の正本

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `industry`, `auth_model`, `surface`, `program_override`, common rules, allow/deny/limit policy
- **出力/結果 (Output):** resolved rule set, resolved workflow template, resolved tactical policy
- **program_override の最小構造例:**
  ```json
  {
    "allow": ["scenario_probe"],
    "deny": [],
    "per_asset_qps_cap": 1,
    "global_probe_budget": 2,
    "race_mode": "interval",
    "dry_run": false,
    "fail_closed": true
  }
  ```
- **resolved tactical policy の最小構造:** `allow` / `deny` / `per_asset_qps_cap` / `global_probe_budget` / `source`
- **制約・ルール:**
  - 未一致時は必ず共通ルールへフォールバックする
  - `industry` / `auth_model` / `surface` の未指定値は空文字へ正規化して扱う
  - 現行 `dsl_version` と旧 JSON 互換読込を維持し、移行が不要な最小変更を優先する
  - policy merge は `program override > runtime flag > config default` を守る
  - program override は `allow` / `deny` / `per_asset_qps_cap` / `global_probe_budget` / `race_mode` / `dry_run` / `fail_closed` の許可済みキーのみ上書き可能とする
  - workflow template は Step 4 では read-only で解決結果を返すまでとし、probe planning や chain evaluation への適用は Step 6 で既存挙動との差分確認後に有効化する
  - 現行の active probing safety gate を迂回しない
  - WAF 検知・403/5xx・外部依存失敗時は override の有無に関わらず `blocked` / `defer` を優先する
  - broken JSON や schema 不一致時でも safe default と common rules fallback を維持する
  - override 適用時は `applied_override_keys` / `blocked_reason` / `defer_reason` / `qps_cap_hit` を audit 可能な形で残す
  - override 適用前後の差分として `planned_task_count_before_override` / `planned_task_count_after_override` を残す
  - QPS 制限に達した場合は `qps_cap_target` を残す
  - resolved workflow template は少なくとも `template_id` / `steps` / `source` を含む最小構造で返す
  - audit の保存先は task result / `decision_trace` / report payload のいずれか1つへ統一し、同一 run 内で分散させない
  - rule / workflow 解決の正本は `chain_builder`、runtime guard の正本は `master_conductor` とする

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `data/attack_chain_rules.json` の現行 schema、`dsl_version`、旧 JSON 互換読込、`chain_builder.py` の読込前提を照合し、互換維持が必要なキーと safe default 条件を洗い出す。
- [x] ステップ1A: 本 subtask の非目標（新しい probe 戦略追加を含まないこと）と、運用上改善したい判断/監査項目を確認し、スコープ外の変更を着手前に除外する。
- [x] ステップ2: `data/attack_chain_rules.json` に common rules / industry-specific rules / workflow templates / program overrides の配置を定義し、unknown industry・template未定義時の fallback 先と旧形式からの互換読込条件を明記する。
- [x] ステップ2A: `industry` / `program_override` 導入で改善したい運用判断（どの rule/policy が選ばれたか、なぜ blocked/defer になったか）を仕様へ対応付け、事業価値と監査価値が追える項目を固定する。
- [x] ステップ3: `tests/core/intelligence/test_chain_builder.py` に、(a) industry一致、(b) unknown industry fallback、(c) workflow template未定義時のcommon fallback、(d) broken JSON fallback、(e) 空/不正 override の無害化、(f) 旧 JSON 形式互換、(g) required key 欠落、(h) 型不一致、を先に追加して期待挙動を固定する。
- [x] ステップ4: `tests/core/engine/test_master_conductor_phase1_step14.py` に precedence matrix を追加し、program/runtime/config/invalid の組み合わせごとに `program override > runtime flag > config default`、`global_probe_budget`、`blocked`、`defer`、許可外キー無視、audit 記録、の期待値を1ケース1期待値で固定する。各ケース名には `source_program` / `source_runtime` / `source_config` / `source_invalid` を含め、assert message に source と expected winner を含める。
- [x] ステップ5: `src/core/intelligence/chain_builder.py` に `industry` / `auth_model` / `surface` / `program_override` の正規化と rule resolution を実装し、workflow template は read-only の resolved result として返す。resolved result の snapshot テスト追加に必要な安定フィールドを先に固定する。
- [x] ステップ6: `tests/core/intelligence/test_chain_builder.py` に resolved workflow template と resolved tactical policy の最小構造検証を追加し、`template_id` / `steps` / `source` と `allow` / `deny` / `per_asset_qps_cap` / `global_probe_budget` / `source` の存在を固定する。
- [x] ステップ7: `src/core/engine/master_conductor.py` に program policy 反映を実装し、`applied_override_keys` / `blocked_reason` / `defer_reason` / `qps_cap_hit` / `planned_task_count_before_override` / `planned_task_count_after_override` / `qps_cap_target` を audit 可能な形で保持する。audit の保存先は task result / `decision_trace` / report payload のいずれか1つへ固定する。
- [x] ステップ8: `src/core/engine/master_conductor.py` で workflow template の適用を既存の active probing safety gate と blocked/defer 判定の後段に限定し、override が safety 判定を上書きしないことを確認する。
- [x] ステップ9: `chain_builder` と `master_conductor` の両経路で resolved rule set / resolved workflow template / resolved tactical policy が一致することを targeted tests と snapshot 比較で確認する。
- [x] ステップ10: `blocked` / `defer` 比率、planned task 数差分、QPS cap hit を既存ベースラインと比較し、閾値超過時は workflow template 適用を停止して read-only に戻す切り戻し条件を文書化する。
- [x] ステップ11: `work_report` または親計画へ precedence matrix の結果、audit 観測項目、統合一致結果、切り戻し条件、更新した親計画ステップ/検証欄を要約反映し、subtask 完了判定の根拠を残す。
- [x] ステップ11A: `work_report` または親計画へ「何が改善したか（選択精度・安全性・説明可能性）」「何を今回の非目標として維持したか」「どの release gate 候補を backlog へ残したか」を要約反映する。

## 4.1 Done条件
- [x] targeted tests が通ること。
- [x] resolved rule set / resolved workflow template / resolved tactical policy が `chain_builder` と `master_conductor` の両経路で一致すること。
- [x] active probing safety gate の `blocked` / `defer` 回帰がないこと。
- [x] override 適用時の audit 情報が観測できること。
- [x] precedence matrix の結果と audit 観測結果が `work_report` または親計画に要約反映されること。
- [x] `blocked` / `defer` 比率がベースラインを超えた場合の切り戻し条件が記録されていること。
- [x] 親計画の関連ステップと `work_report` の検証欄に本 subtask の結果が反映されること。
- [x] この subtask の事業価値、安全性、非目標、release gate 候補が `work_report` または親計画に要約反映されること。

## 4.2 未実施項目の着手順整理
- **今すぐ実装すべき項目**
  - （完了）`Step 2`: `data/attack_chain_rules.json` の common/industry/workflow/program override 配置を実データへ反映した。
  - （完了）`Step 4`: precedence matrix を `tests/core/engine/test_master_conductor_phase1_step14.py` へ寄せ、ケース名規約と assert message を含めて固定した。
  - （完了）`Step 9`: `chain_builder` / `master_conductor` 間の resolved result 一致確認を targeted tests で追加した。
  - （完了）`Step 10`: `blocked` / `defer` 比率、planned task 差分、QPS cap hit の比較観点と切り戻し条件を文書化し、比較ロジックを追加した。
- **報告フェーズで実施する項目**
  - `Step 11`: precedence matrix 結果、audit 観測項目、統合一致結果、切り戻し条件を `work_report` または親計画へ要約反映する。
  - `Step 11A`: 事業価値、安全性、非目標、release gate 候補を `work_report` または親計画へ要約反映する。
- **判断基準**
  - `work_report` / 親計画更新を前提としない項目は「今すぐ実装」に分類する。
  - `work_report` / 親計画への反映を完了条件に持つ項目は「報告フェーズ」に分類する。

## 5. 懸念点と対策
- [x] **SRE/インフラ**【発生確率:高 / 影響度:大】override で probe 条件を広げると、QPS 超過や WAF/5xx 増加を招く懸念がある。  
  **対策:** override 可能キーを allowlist 化し、`blocked` / `defer` 判定は override より常に優先する。`tests/core/engine/test_master_conductor_phase1_step14.py` で budget 枯渇、WAF/5xx、dependency failure を固定する。
- [x] **ソフトウェアアーキテクト**【発生確率:高 / 影響度:中】rules ファイルの実配置と計画書の対象パスがズレると、実装対象の取り違えが起きる懸念がある。  
  **対策:** 対象ファイルを `data/attack_chain_rules.json` に統一し、schema 互換維持と fallback 条件を Step 1-2 で先に固定する。
- [x] **デバッガー**【発生確率:高 / 影響度:中】unknown industry、空 override、不正 override、workflow template 未定義、broken JSON の回帰が計画段階で固定されないと、実装後に不安定化する懸念がある。  
  **対策:** Step 3 と Step 5 で失敗系を先にテスト化し、`chain_builder` と `master_conductor` で同一の fallback/precedence を検証する。
- [x] **CTO**【発生確率:中 / 影響度:大】rule selection、workflow template、program policy を同時に有効化すると、責務境界が曖昧になり既存挙動との差分が見えにくくなる懸念がある。  
  **対策:** workflow template は Step 4 では read-only 解決に留め、Step 6 で safety gate 通過後の適用に段階化する。最終確認では resolved result の一致を Done 条件に含める。
- [x] **SRE/インフラ**【発生確率:中 / 影響度:中】override 適用後の観測項目が曖昧だと、QPS 制御や `blocked` / `defer` の異常増加を運用で追跡しづらい懸念がある。  
  **対策:** `applied_override_keys` / `blocked_reason` / `defer_reason` / `qps_cap_hit` を audit 出力対象として固定し、Step 4 と Step 6 でテストと実装へ反映する。
- [x] **ソフトウェアアーキテクト**【発生確率:中 / 影響度:中】互換方針が不明確だと、`dsl_version` や旧 JSON 形式の読込で意図しない破壊的変更を招く懸念がある。  
  **対策:** Step 1-3 に `dsl_version` / 旧形式互換の確認と回帰テストを組み込み、移行不要の最小変更を完了条件に含める。
- [x] **デバッガー**【発生確率:中 / 影響度:中】precedence が文章だけだと、program/runtime/config/invalid の組み合わせ漏れが起きる懸念がある。  
  **対策:** Step 4 で precedence matrix をテスト化し、各組み合わせを1ケース1期待値で固定する。
- [x] **CTO**【発生確率:中 / 影響度:中】subtask の完了条件が弱いと、統合一致や安全性確認が未完でも完了扱いになる懸念がある。  
  **対策:** `## 4.1 Done条件` を追加し、テスト通過・両経路一致・safety gate 回帰なし・audit 観測可能の4条件を満たした時のみ完了とする。
- [x] **SRE/インフラ**【発生確率:低 / 影響度:中】audit の保存先が複数に分散すると、障害時に probe 制御と safety 判定の因果を追跡しづらい懸念がある。  
  **対策:** audit 保存先を task result / `decision_trace` / report payload のいずれか1つへ固定し、Step 6 で実装、Step 9 で反映先を確認する。
- [x] **ソフトウェアアーキテクト**【発生確率:低 / 影響度:中】`resolved workflow template` の戻り値構造が曖昧だと、`chain_builder` と `master_conductor` で別形式が生まれる懸念がある。  
  **対策:** `template_id` / `steps` / `source` の最小構造を仕様へ明記し、Step 5 と Step 8 で同一形式を検証する。
- [x] **デバッガー**【発生確率:低 / 影響度:中】precedence test のケース名規約がないと、失敗時にどの入力ソース競合で崩れたか即座に特定しづらい懸念がある。  
  **対策:** Step 4 でケース名に `source_program` / `source_runtime` / `source_config` / `source_invalid` を含めるルールを追加する。
- [x] **CTO**【発生確率:低 / 影響度:中】subtask 完了時の成果要約が親タスクへ反映されないと、意思決定側が precedence と audit の検証結果を追跡しづらい懸念がある。  
  **対策:** Step 9 を追加し、`work_report` または親計画へ precedence matrix・audit 観測項目・統合一致結果を要約反映する。
- [x] **SRE/インフラ**【発生確率:中 / 影響度:中】`global_probe_budget` の override 前後で planned task 数差分が観測できないと、負荷変化の原因を追跡しづらい懸念がある。  
  **対策:** `planned_task_count_before_override` / `planned_task_count_after_override` を audit 項目へ追加し、Step 7 と Step 10 で差分監視と切り戻し条件へ利用する。
- [x] **SRE/インフラ**【発生確率:中 / 影響度:中】`qps_cap_hit` だけではどの asset で制限に達したか分からず、局所的な負荷異常を切り分けにくい懸念がある。  
  **対策:** `qps_cap_target` を audit 項目へ追加し、Step 7 で保存、Step 11 で要約反映する。
- [x] **SRE/インフラ**【発生確率:低 / 影響度:中】`blocked` / `defer` の異常増加時に read-only へ戻す条件が未定義だと、安全側への復帰判断が遅れる懸念がある。  
  **対策:** Step 10 でベースライン比較と切り戻し条件を文書化し、Done条件にも含める。
- [x] **ソフトウェアアーキテクト**【発生確率:中 / 影響度:中】`program_override` の受け入れ schema が例示だけだと、実装側で自由拡張されやすい懸念がある。  
  **対策:** 仕様に最小構造例を明記し、Step 2 と Step 6 で許可キー以外を拒否/無視する挙動を固定する。
- [x] **ソフトウェアアーキテクト**【発生確率:中 / 影響度:中】`resolved tactical policy` の構造が曖昧だと、呼び出し側の依存が不安定になる懸念がある。  
  **対策:** `allow` / `deny` / `per_asset_qps_cap` / `global_probe_budget` / `source` を最小構造として明記し、Step 6 と Step 9 で検証する。
- [x] **ソフトウェアアーキテクト**【発生確率:低 / 影響度:中】rule/workflow 解決と runtime guard の責務境界が暗黙だと、将来の変更で判定ロジックが重複する懸念がある。  
  **対策:** `chain_builder` を解決の正本、`master_conductor` を guard の正本と明記し、Step 5・7・9 の確認観点へ含める。
- [x] **デバッガー**【発生確率:中 / 影響度:中】precedence テスト失敗時のメッセージ粒度が不足すると、どの source が勝つべきだったか即断しづらい懸念がある。  
  **対策:** Step 4 で assert message に source と expected winner を含める。
- [x] **デバッガー**【発生確率:中 / 影響度:中】schema mismatch が broken JSON のみで代表されると、required key 欠落や型不一致の回帰を取り逃す懸念がある。  
  **対策:** Step 3 に required key 欠落と型不一致ケースを追加する。
- [x] **デバッガー**【発生確率:低 / 影響度:中】read-only 段階の resolved result に安定フォーマットがないと、snapshot 比較や差分確認がしづらい懸念がある。  
  **対策:** Step 5 と Step 9 で snapshot 比較向けの安定フィールドを固定する。
- [x] **CTO**【発生確率:中 / 影響度:中】親タスクへ何を更新するかが曖昧だと、subtask の成果が上位計画に反映されず意思決定材料が欠ける懸念がある。  
  **対策:** Step 11 で親計画の関連ステップと `work_report` の検証欄を更新対象として明記する。
- [x] **CTO**【発生確率:中 / 影響度:中】非目標が明示されないと、実装中に新しい probe 戦略追加までスコープが広がる懸念がある。  
  **対策:** ゴールに「新しい probe 戦略自体は追加しない」を明記し、Step 1 と Step 11 でスコープ逸脱がないか確認する。
- [x] **CTO**【発生確率:低 / 影響度:中】保守課題が backlog に残るだけでは、将来の release gate 候補としての重要度が埋もれる懸念がある。  
  **対策:** `schema test` と `sample rules` を release gate 候補として Backlog に明記し、Step 11 で要約反映する。
- [x] **CTO**【発生確率:中 / 影響度:中】subtask の目的が実装都合に寄ると、運用改善や監査説明性への寄与が見えず優先順位判断が難しくなる懸念がある。  
  **対策:** ゴールに選択一貫性・安全性・説明可能性の改善を明記し、Step 2A と Step 11A で事業価値/監査価値として要約反映する。
- [x] **CTO**【発生確率:中 / 影響度:中】責務境界が文中だけで終わると、実装時に `chain_builder` と `master_conductor` の責務が再混線する懸念がある。  
  **対策:** `## 2` に責務境界を明記し、Step 9 で両経路一致確認、Step 11A で責務分離を維持したことを報告する。
- [x] **CTO**【発生確率:中 / 影響度:中】安全性の優先順位が明示されても、成果報告に残らないと経営判断として「安全側に倒れる設計」が確認しづらい懸念がある。  
  **対策:** Step 10 と Step 11A で blocked/defer 優先と切り戻し条件を要約反映し、Done条件にも残す。
- [x] **CTO**【発生確率:低 / 影響度:中】観測性の改善が audit 項目追加だけで終わると、どの意思決定に使えるかが曖昧なままになる懸念がある。  
  **対策:** Step 2A で audit 項目と運用判断の対応付けを行い、Step 11A で「何の判断がしやすくなったか」を報告する。

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- ※本 subtask 自体は `status: done` とし、継続監視は `SGK-2026-0256`、技術的負債は `SGK-2026-0257` の別タスクで追跡する。
- [x] [重要度:中] ルール増加で保守コストが上がる - 未完了タスクとして `SGK-2026-0257` へ分離し、sample rules と schema test の整備を `status: active` で追跡する。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0253-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
