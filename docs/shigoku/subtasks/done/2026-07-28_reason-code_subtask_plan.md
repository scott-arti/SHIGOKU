---
task_id: SGK-2026-0398
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/subtasks/done/2026-07-28_high-security_subtask_plan.md
title: 候補重複統合のreason code保持
created_at: '2026-07-28'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/reporting;tests/unit/reporting
---

# 実装計画書：候補重複統合のreason code保持

## 1. 達成したいゴール（ユーザー視点）
- [ ] 同じ候補がレポート作成時に統合されても、各候補に付いていた未成立 reason code が一件も失われず、統合後の候補で確認できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/deduplication/finding_deduplicator.py`: 報告前に走る共通重複統合で、全 finding の reason code メタデータを失わず統合する。
  - `src/reporting/haddix_formatter.py`: 候補の根本原因キーによる重複統合と、統合済みメタデータの保持。
  - `tests/unit/core/deduplication/test_finding_deduplicator.py`: 報告前の統合で標準／evidence-quality reason code が消えないことを検証。
  - `tests/unit/reporting/test_haddix_submission_internal_sections.py`: レポート層の統合でも同じ保持契約を検証。
- **データの流れ / 依存関係:**
  - raw finding candidates -> 共通 `deduplicate_findings()` -> `_deduplicate_candidate_findings()` -> `_merge_candidate_duplicate_metadata()` -> 候補セクションと gate の reason code。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** 同一候補キーを持つ `HaddixFinding` 2件以上と、それぞれの `additional_info` にある標準／evidence-quality reason code。
- **出力/結果 (Output):** 強い候補を本文の主候補として維持しながら、全候補の reason code を順序を保って `reason_codes` に統合する。
- **制約・ルール:**
  - 候補の重複キー、件数、confirmed/candidate の分類、gate 閾値は変更しない。
  - reason code の統合はレポート層の候補メタデータに限定し、raw session を書き換えない。
  - 先に現象を再現する単体テストを追加してから実装する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: 既存の候補重複キー、reason code 正規化、表示経路を確認する。
- [x] ステップ2: 同一候補キーで標準 reason code と evidence-quality reason code が分かれる失敗テストを追加する。
- [x] ステップ3: 統合ヘルパーを最小修正し、全 reason code を正規化・順序保持して残す。
- [x] ステップ4: 対象テストと High の実セッション再評価で、統合後の候補に根拠が残ることを確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:低] 既に生成済みの Markdown レポートは自動更新されない - 次回のレポート生成時、または明示的な再生成時に新しい統合結果を反映する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0398-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
