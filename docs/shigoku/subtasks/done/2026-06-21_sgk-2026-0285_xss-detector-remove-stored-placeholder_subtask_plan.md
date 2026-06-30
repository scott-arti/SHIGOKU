---
task_id: SGK-2026-0285
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0244
related_docs:
- docs/shigoku/plans/2026-05-24_sgk-2026-0244_xss-hunter-enhancement_plan.md
- docs/shigoku/subtasks/2026-05-27_sgk-2026-0244-s01_xss-hunter-remaining-implementation_subtask_plan.md
title: xss_detector.py から Stored XSS placeholder を削除
created_at: '2026-06-21'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/core/detection/xss_detector.py, tests/core/detection/
---

# 実装計画書：xss_detector.py から Stored XSS placeholder を削除

## 1. 達成したいゴール（ユーザー視点）
- `xss_detector.py` が Reflected / DOM 専用の汎用エンジンとして明確になる。
- Stored XSS は `stored_xss_detector.py` に責務を一本化し、誤って placeholder 実装を呼ぶ余地をなくす。
- 回帰テストで「generic engine は Stored XSS API を持たない」を固定する。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/detection/xss_detector.py`: Reflected / DOM XSS の汎用検出器。Stored placeholder を削除
  - `src/core/agents/swarm/injection/stored_xss_detector.py`: Stored XSS の専用実装。責務の正本
  - `tests/core/detection/test_xss_detector.py`: API 境界の回帰テスト
- **データの流れ / 依存関係:**
  - Reflected / DOM 検出要求 -> `XSSDetectionEngine`
  - Stored XSS 検出要求 -> `StoredXSSDetector`
  - テスト -> `XSSDetectionEngine` public API の境界確認

## 3. 具体的な仕様と制約条件
- **現状整理:**
  - `xss_detector.py` の `detect_stored_xss()` は保存送信を行わない placeholder だった。
  - `stored_xss_detector.py` にはフォーム検出、保存送信、表示先解決、反射確認、発火確認までを持つ専用実装がある。
- **入力情報 (Input):**
  - `XSSDetectionEngine` への reflected / dom 判定要求
- **出力/結果 (Output):**
  - `XSSDetectionEngine` から Stored XSS API を除去
  - 回帰テストで API 境界を固定
- **制約・ルール:**
  - `stored_xss_detector.py` 側の挙動は変更しない
  - Reflected / DOM API の既存挙動は変えない
  - 変更は最小差分に留める

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `detect_stored_xss()` の参照有無を確認し、未使用であることを確認する
- [x] ステップ2: `xss_detector.py` から Stored XSS placeholder を削除する
- [x] ステップ3: `XSSDetectionEngine` が Stored XSS API を公開しないことを回帰テストで固定する
- [x] ステップ4: targeted test と `py_compile` で検証する

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] `xss_detector.py` と `stored_xss_detector.py` の責務差はコード上で分かったが、利用側の呼び分け戦略はまだ明文化が弱い - XSS orchestration 層の設計時に整理する
- [ ] [重要度:低] API 非公開の回帰テストは public surface を守るには有効だが、実運用フローの保証にはならない - orchestration テストで補完する

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0285-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
