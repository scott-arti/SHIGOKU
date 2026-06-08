---
task_id: SGK-2026-0240
doc_type: plan
status: done
parent_task_id: SGK-2026-0220
related_docs:
- docs/shigoku/plans/2026-05-19_b-2-ssrf-tester_plan.md
- docs/shigoku/specs/standards/vulnerability_feature_implementation_spec.md
title: SSRF P0 判定品質強化（誤検知抑制・確信度判定）
created_at: '2026-05-23'
updated_at: '2026-05-23'
tags:
- shigoku
- ssrf
- quality
target: src/core/attack/ssrf_tester.py, tests/core/attack/test_ssrf_tester.py
---

# SSRF P0 判定品質強化（誤検知抑制・確信度判定） 統合計画書

## 背景
- SSRF P0 の土台実装（bypass variant、final destination check、IMDSv2系指標、ユニットテスト）は概ね完了済み。
- 未完成領域は「判定品質（FP抑制と説明可能性）」であり、単発シグナル依存から複合シグナル判定へ移行する必要がある。
- 追加で、運用再現性・判定スキーマ安定性・FN抑制・品質ガバナンスの明文化が必要になった。

## 目的
- 誤検知を抑えつつ、成立したSSRFを取りこぼさない判定モデルへ強化する。
- 判定理由を構造化して出力し、運用・調査・レビューで再現可能な状態にする。
- 品質KPIをリリース判定（マージゲート）に接続し、品質劣化を継続的に防ぐ。

## 観点別の要件・懸念・解消方針

### 1) SRE / インフラエンジニア観点
- 要件:
  - 本文痕跡だけでなく、到達経路（最終URL・redirect chain・到達先分類）を観測可能にする。
  - DNS挙動が絡む判定を再現可能にするため、名前解決条件を固定化する。
- 懸念:
  - `resolved_ips` の取得タイミングや再解決有無が曖昧だと、同条件再現が困難。
  - DNSリバインドや一時的ネットワーク挙動で誤判定要因が追跡できない。
- 解消方法:
  - 判定メタデータに `final_url`, `redirect_chain`, `destination_class`, `resolved_ips` を保持。
  - 名前解決ポリシーを固定: 解決回数1、評価直前解決、IPv4/IPv6双方記録、解決タイムアウト固定。
  - metadata endpoint 正規化テーブル（AWS/GCP/Azure）をURL評価に使用。
- 必要性と重要性:
  - 必要性: 高（運用時の再現・事故調査に必須）
  - 重要性: 高（判定の安定性と監査可能性に直結）

### 2) ソフトウェアアーキテクト観点
- 要件:
  - 判定ロジックを説明可能な構造にする（シグナル単位の寄与が分かる）。
  - `confidence_breakdown` のスキーマを固定し、下流互換性を担保する。
- 懸念:
  - `SSRFTester` 内に判定が密結合すると保守性が低下。
  - breakdown形式が毎回揺れると表示層・保存層が破綻。
- 解消方法:
  - `analyzer` 相当の責務分離（収集: tester / 評価: analyzer）を導入。
  - `confidence_breakdown` の必須キーを固定:
    - `signal`, `weight`, `observed`, `subtotal`, `reason_code`
  - `confidence_breakdown` に `schema_version` を追加し、後方互換方針を定義する。
  - 重み・閾値を定数テーブル化し、将来設定ファイル移行可能な構造にする。
- 必要性と重要性:
  - 必要性: 高（継続運用で必ず調整が発生）
  - 重要性: 高（拡張性・回帰耐性・互換性に直結）

### 3) バグハンター観点
- 要件:
  - 弱い単発ヒット（反射・共通404・定型エラー）で vulnerable 化しない。
  - open redirect 経由ケースでFPを抑えつつ、真のSSRFを落とさない救済条件を持つ。
- 懸念:
  - open redirect を一律に弱く扱うとFN（真陽性取りこぼし）が増える。
  - FP抑制を強めすぎると実害あるケースが埋もれる。
- 解消方法:
  - baseline 差分判定を導入し、本文/ステータス/長さの相対差で評価。
  - 強証拠/弱証拠を分離し、単独弱証拠では閾値未達にする。
  - open redirect止まりは減点するが、以下の救済条件があれば復元加点:
    - 内部到達を示す追加証拠（internal IP/class 到達、metadata URL一致、非公開ホスト名一致）
    - redirect chain 後段で強証拠シグナルが発生
- 必要性と重要性:
  - 必要性: 高（品質問題の中心）
  - 重要性: 高（ユーザ信頼と実運用負荷に直結）

### 4) CTO観点
- 要件:
  - 「検出数」より「信頼できる検出」を優先し、判定理由を説明可能にする。
  - KPIをマージ条件に接続し、品質劣化をプロセスで防ぐ。
- 懸念:
  - KPIが運用に紐づかないと形骸化する。
  - 閾値/重み変更が属人的になる。
- 解消方法:
  - KPIを明文化し、PRマージ前検証の必須条件にする。
  - 重み/閾値の変更時は変更理由と影響を作業報告へ必須記録。
- 必要性と重要性:
  - 必要性: 高（ガバナンス実効性の確保）
  - 重要性: 高（プロダクト信頼性と意思決定の基盤）

## 統合実装方針

### 方針A: 判定データの観測性と再現性を先に強化
- `SSRFTester` のレスポンス処理で以下を構造化保持:
  - `final_url`, `redirect_chain`, `destination_class`, `resolved_ips`
  - `status_code`, `response_length`, `indicator_hits`
- DNS解決の実装ポリシーを固定し、テストでも同条件を再現する。

### 方針B: baseline差分 + confidence重み付けを同時導入
- baseline 用比較リクエスト（例: `nonexistent_ssrf_check_404`）を固定手順で取得。
- 以下のシグナルを重み付け:
  - URL到達シグナル（metadata endpoint 到達、internal到達らしさ）
  - 本文シグナル（indicator強度、ノイズ抑制後）
  - 差分シグナル（baselineとの差）
  - ガードシグナル（open redirect止まり、一般的404類似）
- 出力:
  - `confidence_score`, `confidence_level`
  - `confidence_breakdown`（必須キー固定: `schema_version`, `signal`, `weight`, `observed`, `subtotal`, `reason_code`）

### 方針B-1: 強証拠/弱証拠/救済条件の判定表を定数化
- 強証拠:
  - metadata endpoint 一致 + internal destination 到達
  - redirect chain 後段で internal destination + indicator 複合一致
- 弱証拠:
  - 一般的404類似、単独の曖昧 indicator、open redirect のみ
- 救済条件:
  - open redirect 減点後でも internal 到達強証拠がある場合に復元加点
- 目的: ルールの属人化を防ぎ、機械判定可能なポリシーに固定する。

### 方針C: open redirect救済を含む判定ガード
- 原則: open redirect止まりは減点。
- 例外: 内部到達強証拠が追加である場合は復元加点して最終判定に反映。
- 目的: FP抑制とFN抑制を両立。

### 方針D: 判定ロジックの責務分離
- 収集層（tester）と評価層（analyzer）を分ける。
- 第1段階は同一ファイル内関数分離、第2段階で独立モジュール化可能な構造にする。

### 方針E: KPIのマージゲート化
- マージ前にKPI検証が満たされない場合は出荷不可。
- KPI判定結果を作業報告へ記録し、履歴として追跡可能にする。
- 実施主体と実施点:
  - 実施主体: CI必須ジョブ（SSRF quality gate）
  - 実施点: PR更新時・マージ直前の2段階
  - 失敗時動作: ブロック（override はセキュリティ責任者承認が必要）

### 方針F: 閾値/重み変更の承認ルール
- 閾値/重み変更は以下を必須化:
  - 変更理由、影響範囲、KPI差分の記録
  - セキュリティ担当 + モジュールオーナーの2者レビュー承認
- 目的: チューニング起因の品質劣化を防ぐ。

### 方針G: ロールバック条件と手順
- ロールバック発動条件:
  - KPI-1 または KPI-2 が連続失敗
  - 本番同等検証で誤検知急増（直近基準比で閾値超過）
- ロールバック手順:
  - 直前の安定版閾値セットへ復元
  - 復元理由と影響を作業報告へ記録
  - 原因分析完了まで新規閾値変更を凍結

## 実装タスク
1. 現行判定フロー棚卸し
- `src/core/attack/ssrf_tester.py` のシグナル取得点と判定点を明示化。

2. 判定メタデータとDNS再現性拡張
- `final_url`, `redirect_chain`, `destination_class`, `resolved_ips` 収集を追加。
- DNS解決ポリシー（回数/タイミング/timeout/IPv4/IPv6記録）を明文化し実装。

3. baseline差分判定導入
- baseline リクエスト設計と差分シグナル生成を実装。

4. confidence重み付け判定導入
- 重みテーブル・閾値・ガード条件を実装。
- `confidence_breakdown` を固定スキーマ（`schema_version` 含む）で格納。

5. open redirect救済ロジック導入
- 減点ルールと復元加点ルールを実装し、競合時の優先順位を明確化。

6. 責務分離リファクタ（最小）
- 判定処理を評価関数群へ分離（挙動維持・テスト容易化）。

7. テスト拡張とマージゲート整備
- `tests/core/attack/test_ssrf_tester.py` にFP/FN抑制ケースを追加。
- `confidence_breakdown` スキーマ（`schema_version` 含む）検証テストを追加。
- KPI満足を確認するテストセットをマージ必須として定義。
- CI quality gate ジョブの必須化とブロック動作を確認。

## 完了条件
- 単発弱証拠のみで `vulnerable=True` にならない。
- baseline差分が判定シグナルとして反映される。
- `response.url` / redirect chain / destination_class / resolved_ips が判定に利用される。
- `confidence_breakdown` が固定キーで常に出力される。
- `confidence_breakdown.schema_version` が常に出力され、互換方針に従う。
- open redirect止まりで過検知せず、内部到達強証拠がある場合は検出維持される。
- KPIがマージ判定に組み込まれ、検証結果が記録される。
- KPI未達時のロールバック条件・手順が運用可能な状態で定義される。

## 品質KPI（工数以外）
- KPI-1: 既知FPシナリオで誤検知ゼロ。
- KPI-2: 強証拠シナリオで検出維持。
- KPI-3: 判定結果に説明可能な内訳（固定スキーマ）が常に付与される。
- KPI-4: マージ前ゲートでKPI未達の変更がブロックされる。

## 検証
- `.venv/bin/pytest tests/core/attack/test_ssrf_tester.py`
- 必要に応じてSSRF関連統合テスト
- `python3 scripts/sync_shigoku_updated_at.py`
- `python3 scripts/validate_shigoku_docs.py`

## 成果物
- 統合計画書（本書）
- 実装後の作業報告書（`doc_type: work_report`）
- 実装後の作業ログ（`doc_type: work_log`）
