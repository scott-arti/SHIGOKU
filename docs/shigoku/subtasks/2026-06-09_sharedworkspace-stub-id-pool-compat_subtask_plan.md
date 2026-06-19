---
task_id: SGK-2026-0278
doc_type: subtask_plan
doc_usage: execution_plan
status: done
parent_task_id: SGK-2026-0277
related_docs:
- docs/shigoku/subtasks/2026-06-09_injectionmanager-api-minimal-service-extraction_subtask_plan.md
- docs/shigoku/reports/2026-06-09_sgk-2026-0277_api-probe-runner-extraction_work_report.md
- docs/shigoku/worklogs/2026-06-09_sgk-2026-0277_api-probe-runner-extraction_work_log.md
- docs/shigoku/reports/2026-06-09_sgk-2026-0278_sharedworkspace-stub-compat_work_report.md
- docs/shigoku/worklogs/2026-06-09_sgk-2026-0278_sharedworkspace-stub-compat_work_log.md
title: SharedWorkspace stub解消とID pool互換復旧
created_at: '2026-06-09'
updated_at: '2026-06-11'
tags:
- shigoku
target: src/core/workspace/shared_workspace.py
---

# 実装計画書：SharedWorkspace stub解消とID pool互換復旧

## 1. 達成したいゴール（ユーザー視点）
- [ ] `src/core/workspace/shared_workspace.py` が単なる no-op stub ではなく、既存コード/既存テストが期待する最小互換 API を提供すること。
- [ ] IDOR/BOLA 系の ID pool 操作（登録、取得、承認待ち、承認）が復旧し、`tests/core/security/test_idor_enhancement_phase1.py` が通ること。
- [ ] SGK-2026-0277 の API minimal runner 抽出とは別タスクとして扱い、InjectionManager 側の検出ロジックへ変更を混ぜないこと。
- [ ] `MasterConductor.initialize_workspace()` など既存呼び出し元が期待する `.root` / `workspace_root` の互換を満たすこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/workspace/shared_workspace.py`: （修正）現在の最小 stub を、既存呼び出し元が期待する互換 API を持つ軽量実装へ置き換える。
  - `src/core/workspace/__init__.py`: （確認）package marker として維持する。不要な export 追加はしない。
  - `tests/core/security/test_idor_enhancement_phase1.py`: （既存）ID pool / approval flow / IdorHunter integration の回帰確認に使う。
  - `tests/core/security/test_idor_matrix_secret_phase3.py`: （既存）owner 別 ID pool の回帰確認に使う。
  - `tests/unit/core/agents/test_shared_workspace_integration.py`: （既存）agent.workspace 経由の `.root`, `save_finding`, `save_intel` の回帰確認に使う。
- **データの流れ / 依存関係:**
  - `IdorHunterSpecialist._collect_ids_from_response(...)` -> `SharedWorkspace.register_ids(...)` または `stage_ids_for_approval(...)` -> `id_pool` / pending approval state -> `get_pool_ids(...)` / `approve_staged_ids(...)`
  - `BaseAgent.workspace` / `MasterConductor.initialize_workspace(...)` -> `SharedWorkspace(workspace_root=...)` -> `.root` と `workspace_root` を参照。
  - `agent.save_finding(...)` / `agent.save_intel(...)` -> `SharedWorkspace.save_finding(...)` / `save_intel(...)` -> 既存テストが期待する戻り値 shape を維持。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - `workspace_root: str`
  - `endpoint_pattern: str`
  - `ids: Iterable[str]`
  - `owner: Optional[str]`
  - `exclude: Optional[List[str]]`
  - `exclude_owner: Optional[str]`
  - `limit: Optional[int]`
  - `finding: Any`
  - `type_name: str`, `data: Dict[str, Any]`
- **出力/結果 (Output):**
  - `.root` は `Path` 互換で参照できること。
  - `.workspace_root` は文字列または `Path` として既存利用に耐えること。
  - `register_ids(...)` は重複を排除し、owner を指定されたIDと紐づけられること。
  - `get_pool_ids(...)` は `exclude` / `exclude_owner` / `limit` を反映した list を返すこと。
  - `stage_ids_for_approval(...)` は承認待ち state にIDを置き、poolへ即時投入しないこと。
  - `approve_staged_ids(...)` は承認待ちIDを pool へ移し、投入件数を返すこと。
  - `get_pending_approval_report()` は承認待ちIDを endpoint pattern 単位で参照できる dict を返すこと。
  - `save_finding(...)` / `save_intel(...)` は既存 agent integration test が期待する値を返し、必要な場合のみ最小限の永続化を行うこと。
- **現在確認済みの失敗:**
  - `.venv/bin/pytest tests/core/security/test_idor_enhancement_phase1.py -q` が5件失敗。
  - 失敗理由は `SharedWorkspace` に `register_ids`, `stage_ids_for_approval`, `approve_staged_ids`, `get_pending_approval_report`, `id_pool` が無いため。
- **制約・ルール:**
  - SGK-2026-0277 の API minimal runner / InjectionManager には手を入れない。
  - no-op でテストだけを通すのではなく、既存呼び出し元が期待する最小機能を実装する。
  - ID pool は deterministic に扱い、同じIDの重複登録で件数が増えないようにする。
  - owner フィルタは `exclude_owner` を優先し、異なるrole/userのIDを取り出せるようにする。
  - ファイル永続化を追加する場合は `workspace_root` 配下に限定し、外部パスへ書き込まない。
  - 既存テストの期待を変える場合は、先に呼び出し元を調査して理由を work_report に残す。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: baseline として `.venv/bin/pytest tests/core/security/test_idor_enhancement_phase1.py -q` を実行し、5件失敗が再現することを記録する。
- [ ] ステップ2: `rg -n "SharedWorkspace|register_ids|stage_ids_for_approval|approve_staged_ids|get_pool_ids|get_pending_approval_report|\\.root" src tests scripts` で既存呼び出し元を再確認する。
- [ ] ステップ3: `SharedWorkspace.__init__` に `.root`, `.workspace_root`, `id_pool`, pending approval state, owner map を追加する。
- [ ] ステップ4: `register_ids(...)`, `get_pool_ids(...)`, `stage_ids_for_approval(...)`, `approve_staged_ids(...)`, `get_pending_approval_report()` を最小互換で実装する。
- [ ] ステップ5: `save_finding(...)` / `save_intel(...)` の戻り値と永続化方針を既存テストに合わせて調整する。永続化する場合は `workspace_root` 配下に限定する。
- [ ] ステップ6: targeted tests を実行する。最低限、`.venv/bin/pytest tests/core/security/test_idor_enhancement_phase1.py tests/core/security/test_idor_matrix_secret_phase3.py tests/unit/core/agents/test_shared_workspace_integration.py -q` を通す。
- [ ] ステップ7: 影響範囲確認として `src/core/agents/swarm/logic/idor.py`, `src/core/engine/master_conductor.py`, `src/core/agents/base.py`, `src/core/agents/swarm/base.py` の呼び出しと実装の整合を確認する。
- [ ] ステップ8: `python3 scripts/sync_shigoku_updated_at.py`、`python3 scripts/validate_shigoku_docs.py`、必要に応じて `graphify update .` を実行し、work_report / work_log に結果を記録する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] 現在の `SharedWorkspace` stub は import error を解消する一方で、既存の ID pool / approval API を欠いている。 - 本タスクで最小互換 API を復旧する。
- [ ] [重要度:中] `SharedWorkspace` は specs 上は本格的な共有ワークスペース責務を持つが、本タスクで全機能を作り直すとスコープが膨らむ。 - 既存テストと既存呼び出し元が要求する範囲に限定する。
- [ ] [重要度:中] owner / role 別 ID pool の扱いを誤ると IDOR/BOLA 検証の安全性と再現性が落ちる。 - `exclude_owner` と owner map のテストを必ず通す。
- [ ] [重要度:低] 永続化形式が未確定の場合、将来の本格実装と衝突する可能性がある。 - 永続化は必要最小限とし、形式変更が必要なら別タスクへ送る。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0278-D01
    title: "継続監視: SharedWorkspace 本格永続化と検索API"
    reason: "本タスクは既存テスト互換の復旧を優先し、仕様書にある全ワークスペース機能の再実装までは扱わない"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "SharedWorkspace の findings/intel/artifacts/context 永続化仕様を別タスクで棚卸しする"
```
