---
task_id: SGK-2026-0416
doc_type: plan
status: done
parent_task_id: null
related_docs:
- workspace/projects/localhost:3000/reports/haddix_report_20260731_201628.md
title: Session evidence summary labeling and Juice Shop VDP readiness assessment
created_at: '2026-07-31'
updated_at: '2026-08-07'
tags:
- shigoku
target: src/reporting/initial_release_gate.py
---

# 実装計画書：Session evidence summary labeling and Juice Shop VDP readiness assessment

## 1. 達成したいゴール（ユーザー視点）
- [x] 初期リリースゲートの補助集計を見ても、提出用に確定した脆弱性の件数と誤解しない。
- [x] Juice Shop 実行の探索範囲、検証の深さ、証拠品質を、VDP実戦投入の基準で説明できる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/reporting/initial_release_gate.py`: セッションの補助集計に、提出用確定とは異なることを示す表示メタデータを追加する。
  - `tests/unit/reporting/test_initial_release_gate.py`: 表示メタデータの回帰テストを追加する。
  - `workspace/projects/localhost:3000/reports/haddix_report_20260731_201628.md`: VDP評価の一次根拠。
- **データの流れ / 依存関係:**
  - `session_*.json` -> セッション補助集計 -> 初期リリースゲートJSON
  - `session_*.json` -> 証拠品質の強制判定 -> Haddix提出用レポート（確定/候補の正本）

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** セッションの生finding（`dict`）、Haddix提出用レポート（Markdown）。
- **出力/結果 (Output):** 後方互換のある件数に加え、補助集計の意味と提出用正本を示すJSON項目。
- **制約・ルール:**
  - 生セッションの補助集計を、提出用の確定数や根拠そのものとして扱わない。
  - 既存の件数キーは変更せず、説明項目を追加する。
  - 実行済みレポートは再生成・改変しない。評価は整合済みの同一レポート/セッションに限定する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: レポート整合性、補助集計、提出用証拠判定の分岐を確認する。
- [x] ステップ2: 補助集計に提出用確定ではない旨の表示メタデータと回帰テストを追加する。
- [x] ステップ3: 構文・実アーティファクト・利用可能なテストを検証する。
- [x] ステップ4: Juice Shop 実行をVDP投入の観点（広さ・深さ・証拠・測定可能性）で評価する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [重要度:高] VDP対象ごとの許可範囲・資産・認証条件に対する到達度を測る仕組みがなく、検出漏れ率を測定できない。`SGK-2026-0418` で対象非依存のベンチマーク仕様を実装する。
- [重要度:高] 今回のセッションは認証状態差・オブジェクト比較・状態変化の証拠を記録しておらず、候補を確定できない。`SGK-2026-0418` で証拠収集契約を実装する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0416-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
