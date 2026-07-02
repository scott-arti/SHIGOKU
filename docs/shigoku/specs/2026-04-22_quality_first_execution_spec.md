---
task_id: SGK-2026-0087
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-04-22'
updated_at: '2026-07-02'
---

# 仕様書: Quality-First 攻撃成功強化フロー（crAPI起点・汎用運用）

## 1. 概要
本仕様は、SHIGOKU の次フェーズにおける優先順を固定し、  
「カバレッジ達成」より先に「攻撃成立品質」を引き上げるための実行フローを定義する。

本仕様の目的は、crAPI での改善を起点にしつつ、特定ターゲットへのカーブフィッティングを避け、  
他環境にも移植可能な品質基盤を先に完成させることである。

## 2. 背景と課題
- 直近運用では Scenario / Family のカバレッジは高水準に到達している。
- 一方で Confirmed finding の「再現証拠（PoC request/response）」が不足し、検出の成立強度が不十分。
- 高摩擦シナリオ（semantic business logic / advanced SSRF）は deferred 運用前提であり、自動のみでの完遂は初期版で非現実的。

## 3. 目的
- Confirmed finding の定義を厳格化し、再現可能性を必須化する。
- 未成立時の原因を reason code で必ず残し、次アクションへ機械的に接続する。
- 攻撃の深度を上げ、同一時間あたりの Confirmed を増やす。
- 初期版の運用方針（SCN10/12 deferred）を明文化し、判断の揺れをなくす。

## 4. 非目的
- SCN10/12 を初期版で完全自動化すること。
- crAPI 固有のハードコードルールを増やすこと。
- 毎回フルスキャンのみで改善検証すること。

## 5. 変更範囲
- `reporting`:
  - Confirmed/Candidate の判定規約強化
  - PoC 証跡欠損の可視化
  - reason code 集計と自動アクション出力
- `attack execution`:
  - 攻撃優先度制御（成立確率順）
  - 比較検証軸（unauth/authA/authB, objectA/objectB）の標準化
- `runtime workflow`:
  - `focus-tests -> short attack loop -> full scan` の段階運用
  - deferred/HITL の着手順固定

## 6. 用語定義
- `Confirmed`: 以下を満たす finding。  
  1) 再現条件が定義済み  
  2) `PoC Request` と `PoC Response` の双方が保存済み  
  3) 判定理由が機械的に説明可能
- `Candidate`: シグナルはあるが Confirmed 条件を満たさない finding。
- `Reason Code`: 未成立または降格理由を示す標準コード。
- `Deferred`: 初期版では自動完遂対象外として後段に回すシナリオ。

## 7. 実行順固定ポリシー（Order Lock）
- 本仕様の 8章「Step 1 -> Step 9」を厳守する。
- 各 Step は Exit Criteria を満たすまで次 Step に進めない。
- 例外進行を許可する場合は、実行ログに `override_reason` を必須記録する。

## 8. Step-by-Step 実装計画

### Step 1: 基準線固定（Source of Truth）
目的:
- 比較対象の揺れをなくし、改善評価を一貫化する。

実装要件:
- レポート + セッションの整合ペアを 1 つ固定する。
- 以後の比較は当該ペアとの差分のみを評価対象にする。

Exit Criteria:
- `baseline_report_path` と `baseline_session_path` が明示されている。
- 以後の評価ログに baseline id が残る。

### Step 2: Confirmed 定義の厳格化
目的:
- 「Potential」が Confirmed に混入しない状態を作る。

実装要件:
- Confirmed は PoC request/response 両方必須。
- 欠損時は強制的に Candidate へ降格する。

Exit Criteria:
- `PoC Request Captured = no` または `PoC Response Captured = no` の finding が Confirmed に存在しない。

### Step 3: PoC 証拠保存の強制
目的:
- 再現可能性を成果物として残す。

実装要件:
- 各 finding に以下を保存する。
  - raw request
  - raw response
  - replay command
  - detector verdict と key signals

Exit Criteria:
- Confirmed finding 全件で evidence artifact が参照可能。

### Step 4: 未成立 Reason Code の必須化
目的:
- 「見つからなかった理由」を次アクションへ接続する。

実装要件:
- 未成立/降格 finding に reason code を必須付与。
- 標準コード:
  - `insufficient_discovery`
  - `insufficient_payload`
  - `insufficient_validation`
  - `insufficient_privilege`
  - `insufficient_state_transition`

Exit Criteria:
- Candidate/Failed の reason code 欠損率 0%。

### Step 5: 攻撃深度の標準強化（汎用）
目的:
- URL数ではなく攻撃成立率を上げる。

実装要件:
- IDOR/BOLA: object A/B 差し替え比較を標準化。
- Mass Assignment: 応答スキーマから候補フィールド抽出を追加。
- AuthZ: `unauth vs authA vs authB` の 3比較を標準化。

Exit Criteria:
- 各対象カテゴリで「比較検証ログ」が残る。
- 単発リクエスト検証のみの比率が減少する。

### Step 6: 実行優先度を成立確率順へ変更
目的:
- 同じ時間で Confirmed を増やす。

実装要件:
- 優先度スコアを導入し、以下を先行する。
  - 更新系メソッド
  - JSON body
  - `id/role/is_admin` 等の高信号パラメータ
  - 既知の auth 境界付近

Exit Criteria:
- 実行ログに priority score が記録される。
- 高優先タスク先行が観測できる。

### Step 7: 高速改善ループを標準化
目的:
- 修正->検証サイクルの待機時間を削減する。

実装要件:
- 運用順を固定:
  1) `focus-tests`
  2) short attack loop
  3) 必要時のみ full scan

Exit Criteria:
- フルスキャン前に focused 検証結果が毎回残る。

### Step 8: HITL/Deferred の着手順固定
目的:
- 人手投入タイミングを最適化する。

実装要件:
- 自動フェーズ完了後に HITL を実行。
- SCN10/12 は初期版では deferred を標準運用とする。
- deferred には operator_input と success_criteria を必須定義。

Exit Criteria:
- SCN10/12 は backlog artifact に記録され、抜け漏れがない。

### Step 9: 最終品質ゲート導入
目的:
- リリース可否を定量ルールで判定する。

実装要件:
- 既定ポリシー:
  - `confirmed_min >= 3`
  - `candidate_max <= 2`
  - `confirmed_poc_missing = 0`
  - `reason_code_missing = 0`

Exit Criteria:
- Gate 判定が PASS/FAIL と理由コード付きで出力される。

## 9. KPI
- `confirmed_count`
- `candidate_count`
- `confirmed_with_poc_rate`
- `candidate_with_reason_code_rate`
- `time_to_first_confirmed`
- `confirmed_per_hour`
- `full_scan_ratio`（全検証に占めるフルスキャン実行割合）

## 10. 受け入れ基準（初期版）
- Confirmed はすべて PoC request/response を持つ。
- Candidate/Failed はすべて reason code を持つ。
- Step 1-9 の順序逸脱がない（または override_reason が残る）。
- SCN10/12 は deferred 運用として明示的に管理される。

## 11. ロールアウト方針
- Phase A: Step 1-4（品質定義と証拠整備）
- Phase B: Step 5-7（成立率と実行効率改善）
- Phase C: Step 8-9（運用固定と最終ゲート）

## 12. リスクと対策
- リスク: Confirmed 数が一時的に減る。  
  対策: 定義厳格化による健全な減少とみなし、PoC充足率を主KPIに移行する。
- リスク: 実装初期にログ量が増える。  
  対策: evidence retention を段階的に圧縮可能な設定で導入する。
- リスク: 高摩擦シナリオの停滞。  
  対策: deferred checklist を運用に組み込み、実施責任を明確化する。

