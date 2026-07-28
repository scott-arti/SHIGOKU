---
task_id: SGK-2026-0394
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
- AGENTS.md
- rules/reporting.md
title: Candidate gate FAIL の正常状態を運用文書へ明記
created_at: '2026-07-27'
updated_at: '2026-07-28'
tags:
- shigoku
target: AI coding guardrail for known DVWA low candidate gate state
---

# 実装計画書：Candidate gate FAIL の正常状態を運用文書へ明記

## 1. 達成したいゴール（ユーザー視点）
- [x] AI が DVWA low の既知の候補5件による gate FAIL を見たとき、件数を減らすだけの修正を始めない。
- [x] AI が、追加の証拠取得または明示的なポリシー変更が必要な安全側の保留状態として説明できる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `AGENTS.md`: 全コーディングAIが最初に読む、レポート/セッション判定の必須ガードレール。
  - `rules/reporting.md`: レポート・ゲート関連の変更前に動的ロードされる判断ルール。
- **データの流れ / 依存関係:**
  - consistent な report/session -> gate reason `candidate_above_maximum` -> AI の修正要否判断。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** consistent な DVWA low report/session と gate JSON。
- **出力/結果 (Output):** 既知の候補5件のみなら「正常なFAIL」と説明し、無関係な集成を開始しない。
- **制約・ルール:**
  - `candidate_above_maximum` だけを理由に、候補の昇格・抑制・閾値緩和・タスク数削減を行わない。
  - 後続作業は、新しい reason code、候補数の変化、必須confirmedの欠落、またはユーザーによる明示依頼がある場合に限る。
  - 候補は確定脆弱性として報告しない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: AI必読の `AGENTS.md` と `rules/reporting.md` に既知状態と禁止事項を追加する。
- [x] ステップ2: 最新の consistent report/session と gate JSON で候補数・reason code・gate reason を照合する。
- [x] ステップ3: 台帳・作業記録を更新し、文書検証する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:中] 2アカウント証明、CSRF状態変更、API/CORSの実害確認は未実施。ユーザーが証明を依頼したときのみ個別タスクで扱う。
