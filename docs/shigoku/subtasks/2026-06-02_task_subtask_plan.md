---
task_id: SGK-2026-0254
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0251
related_docs:
- docs/shigoku/plans/2026-06-01_task_plan.md
- docs/shigoku/reports/2026-06-03_sgk-2026-0254_temporal-state_work_report.md
- docs/shigoku/worklogs/2026-06-03_sgk-2026-0254_temporal-state_work_log.md
- docs/shigoku/subtasks/2026-06-03_sgk-2026-0258-temporal-followup_subtask_plan.md
title: 脆弱性チェーン時間軸制約とセッション世代追跡
created_at: '2026-06-02'
updated_at: '2026-06-02'
tags:
- shigoku
target: chain-temporal-state
---

# 実装計画書：脆弱性チェーン時間軸制約とセッション世代追跡

## 1. 達成したいゴール（ユーザー視点）
- [x] トークン更新やセッションローテーションを伴うチェーンでも、世代不整合を見分けて妥当な連鎖だけを昇格できること。
- [x] 誤昇格を抑えつつ、既存の妥当なチェーンを不要に降格させないこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/intelligence/chain_builder.py`: （修正）時間軸制約と epoch 判定
  - `src/core/engine/master_conductor.py`: （修正）state transition / trigger への session generation 反映
  - `tests/core/intelligence/test_phase0_risk_clearance_checklist.py`: （修正）Step 6 の残要件検証
  - `tests/core/engine/test_mc_intelligence_integration.py`: （修正）昇格/降格の回帰
- **データの流れ / 依存関係:**
  - finding/session evidence -> epoch extraction -> chain state evaluation -> promote / demote
- **責務分離 / 設計方針:**
  - `chain_builder` と `master_conductor` に世代判定ロジックを分散させず、epoch / rotation 判定は単一の評価ルールまたは値オブジェクトに集約する。
  - 判定結果は state transition と監査ログの両方で再利用し、評価基準の乖離を防ぐ。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `token_epoch`, `csrf_epoch`, `session_rotation_state`, chain state, finding evidence
- **出力/結果 (Output):** epoch-consistent chain は維持、矛盾時は `draft`/`blocked` へ降格
- **受け入れ基準 (Acceptance Criteria):**
  - representative session / benchmark 回帰で誤昇格を新規に発生させないこと
  - representative session / benchmark 回帰で既存の妥当なチェーンを不要に降格させないこと
  - metadata 欠損時は安全側に `draft` へ倒れ、`blocked` への誤判定を増やさないこと
- **制約・ルール:**
  - 既存 `state_version` / trigger idempotency と競合しない
  - 欠損時は保守的判定へフォールバックする
  - session 由来の状態は監査ログで追跡できる形にする
  - 同一 input を再評価しても state が揺れないことを保証し、再実行時も idempotent に扱えるようにする
  - 新判定は評価ルール集約層に閉じ込め、異常時に旧挙動へ切り戻しやすい差分構造を保つ
- **影響範囲 (Scope Impact):**
  - 本タスクの変更対象は chain state 判定、監査ログ、関連 integration test expectation に限定する
  - report / gate を含む他の公開出力形式の変更は本タスクでは行わない
- **状態遷移ルール:**
  - epoch 一致かつ session rotation と整合する場合のみ昇格候補とする
  - epoch 矛盾または rotation 状態と明確に衝突する場合は `blocked` へ降格する
  - metadata 欠損や比較不能で安全側判断が必要な場合は `draft` へ降格する
- **比較ルール表:**
  - `token_epoch` / `csrf_epoch` / `session_rotation_state` がすべて一致: chain を維持または昇格候補
  - epoch の一部のみ不一致: 矛盾として `blocked`
  - 片側にしか epoch が存在しない: 比較不能として `draft`
  - `session_rotation_state` がローテーション中で前後関係を確定できない: 保守的に `draft`
  - generation が後退して見える証跡: 不整合として `blocked`
- **監査・観測要件:**
  - 降格時は `finding_id`、旧 state、新 state、reason code、session generation、根拠 metadata を構造化監査ログへ残す
  - epoch 欠損率、generation 不整合率、`draft` / `blocked` 降格率を観測対象にする
  - 欠損率が閾値を超える場合は metadata 拡張の deferred task 候補として記録する

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: epoch / rotation state のデータモデルと単一の評価ルールを定義し、`chain_builder` と `master_conductor` の評価経路へ接続する。
- [x] ステップ2: 世代一致時の昇格・不一致時の降格・欠損時フォールバック・再実行時の idempotency を TDD で固定する。
- [x] ステップ3: 最小再現 fixture を用意し、正常系・不一致系・欠損系・generation 後退系を単体テストで固定する。
- [x] ステップ4: `chain_builder` 統合、`master_conductor` 統合、`verify_chaining_flow` の順に targeted integration を実施し、既存チェーンを壊さずに時間軸制約が効くことを確認する。
- [x] ステップ5: representative session / benchmark に対する回帰確認で、誤昇格抑制と既存チェーン維持の両立、および監査ログ出力を確認する。

## 5. 懸念点と対策
- **SRE / インフラ観点**
  - [x] 懸念点: epoch 不整合で `draft` / `blocked` に降格した件数や理由が観測できないと、運用時に誤判定増加と攻撃検知強化を切り分けにくい
    - 発生確率: 高
    - 影響度: 大
    - 対策: 降格時は reason code、session generation、根拠 metadata を構造化監査ログへ出力し、降格率を観測対象に含める
  - [x] 懸念点: 欠損時フォールバックが多発すると、チェーン品質が低下しても気づきにくい
    - 発生確率: 高
    - 影響度: 中
    - 対策: epoch 欠損率を観測対象に追加し、閾値超過時は metadata 拡張を deferred task 候補として記録する
  - [x] 懸念点: `state_version` や trigger idempotency と競合すると、再実行時に state が揺れる可能性がある
    - 発生確率: 中
    - 影響度: 大
    - 対策: 同一 input の再評価で state が揺れないことを仕様化し、再実行時 idempotency を TDD と統合テストで固定する
- **ソフトウェアアーキテクト観点**
  - [x] 懸念点: `chain_builder` と `master_conductor` に世代判定ロジックが分散すると、将来の仕様変更で乖離しやすい
    - 発生確率: 高
    - 影響度: 大
    - 対策: epoch / rotation 判定を単一の評価ルールまたは値オブジェクトに集約し、判定結果を state transition と監査ログで再利用する
  - [x] 懸念点: `token_epoch`、`csrf_epoch`、`session_rotation_state` の比較不能ケースが曖昧だと、実装者ごとに判定がぶれる
    - 発生確率: 中
    - 影響度: 大
    - 対策: 状態遷移ルールと比較ルール表を計画書に明記し、`draft` と `blocked` の使い分けを固定する
  - [x] 懸念点: 監査ログ要件が抽象的だと、後から原因追跡できない
    - 発生確率: 中
    - 影響度: 中
    - 対策: `finding_id`、旧 state、新 state、reason code、session generation、根拠 metadata を最小出力項目として定義する
- **デバッガー観点**
  - [x] 懸念点: 最小再現条件がないと、世代不整合バグの再現と切り分けが難しい
    - 発生確率: 高
    - 影響度: 大
    - 対策: 正常系・不一致系・欠損系・generation 後退系の最小再現 fixture を用意し、単体テストで固定する
  - [x] 懸念点: `draft` と `blocked` の使い分けが曖昧だと、仕様不備と実装不良の切り分けがしにくい
    - 発生確率: 中
    - 影響度: 中
    - 対策: 矛盾は `blocked`、比較不能や安全側判定は `draft` として状態遷移ルールに明記する
  - [x] 懸念点: integration 検証が一段だと、どの層で壊れたか追いにくい
    - 発生確率: 中
    - 影響度: 中
    - 対策: `chain_builder` 統合、`master_conductor` 統合、`verify_chaining_flow` の順で段階的に検証する
- **CTO 観点**
  - [x] 懸念点: 成功条件が「妥当な連鎖だけを昇格」に偏ると、誤昇格抑制と既存検知維持の両立が測れない
    - 発生確率: 高
    - 影響度: 大
    - 対策: ゴールに「誤昇格を抑えつつ既存の妥当なチェーンを不要に降格させない」を追加し、benchmark 回帰で両立を確認する
  - [x] 懸念点: representative session や benchmark への副作用が見えないと、導入判断が難しい
    - 発生確率: 中
    - 影響度: 大
    - 対策: representative session / benchmark に対する回帰確認を実装ステップへ追加し、監査ログ出力も合わせて確認する
  - [x] 懸念点: metadata 不足を backlog に送る基準が曖昧だと、完了判定がぶれやすい
    - 発生確率: 中
    - 影響度: 中
    - 対策: 欠損率の閾値監視と deferred task 化条件を定義し、後回し可の条件を可視化する

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] finding 側の metadata 不足で epoch 判定が空振りする可能性 - 欠損時フォールバックと metadata 拡張候補をあわせて設計する。
- [ ] [重要度:中] epoch / generation 欠損率が高い対象では `draft` 降格が増え、検知品質の解釈が難しくなる可能性 - 欠損率の閾値監視と deferred task 化条件を定義する。
- [ ] [重要度:中] representative session でのみ再現する世代不整合がある場合、単体テストだけでは見落とす可能性 - benchmark / session 回帰セットを維持する。
- [ ] [重要度:中] 降格 reason code が粗いと運用時の切り分けが難しい - `blocked` と `draft` の理由分類を安定化させる。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0254-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
