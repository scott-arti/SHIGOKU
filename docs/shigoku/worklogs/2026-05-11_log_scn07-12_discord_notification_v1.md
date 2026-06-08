---
task_id: SGK-2026-0212
doc_type: work_log
status: done
parent_task_id: null
related_docs: []
created_at: '2026-05-11'
updated_at: '2026-05-19'
---

# 2026-05-11 作業ログ: SCN07-12 Discord Notification Ver.1

## 目的
- Ver.1 方針として、HITL依存度の高い `SCN07-12` は自動実行で詰めず、通知中心で運用できる状態にする。
- `SCN07-12` の通知漏れをなくし、Discord で手動実行に必要な情報（対象URL、疑いシナリオ、必要アクション）を受け取れるようにする。
- `SCN07-12` が pending HITL タスクとして残って開発・運用を重くする状態を解消する。
- 追記（2026-05-14）: SCN11 は coverage 改善のため例外的に自動実行を許可する。SCN08/10/12 は本ドキュメントどおり手動優先を維持する。

## やったこと
1. **source of truth 確認と調査**
- report/session consistency を再確認し、調査対象を固定。
- `SCN08` / `SCN10` の raw session findings と task params を比較し、重複候補の発生源を確認。
- `scenario probe planning` の seed 収集と選別ロジックを追跡し、`SCN10` が fallback で auth surface を残す条件を特定。

2. **SCN10 target 選別の改善（先行実装）**
- `SCN10` 用に target 選別を scenario-aware 化。
- workflow-like target を優先し、なければ non-auth、さらに fallback の順に選ぶロジックを追加。
- 関連テストを追加・更新して通過確認。

3. **SCN07-12 通知の常時発火**
- `intervention precheck` で `SCN07-12` を検知した際に、必ず通知を送る処理を追加。
- 同一 `task_id + scenario_id` で重複通知しない dedupe を実装。

4. **通知内容を Ver.1 運用向けに変更**
- 旧来の「HITL実行後に re-run」文面から、以下を含む手動検証ガイドへ変更。
  - Scenario 名/ID
  - Target(s)
  - Route/Gate
  - Suspected Signals
  - Why Flagged
  - Required Action（手動での検証と結果記録）

5. **SCN07-12 の pending HITL 化を停止**
- Ver.1 用挙動として `SCN07-12` は `manual_deferred` 扱いに変更。
- 通知後にタスクを `SKIPPED` とし、pending HITL ticket を作らないよう修正。
- 既存の pending HITL 機構は `explicit_requires_human_input` 等（SCN07-12 以外）で維持。
- 追記（2026-05-14）:
  - `SCN11` はこの強制 defer 対象から除外し、`SCN11 Multi-Vector Chain Probe` は実行する。
  - その結果、SCN11 は scenario coverage 上 `covered=true` を狙う運用へ変更。

## 変更ファイル
- `/home/bbb/Documents/App/Shigoku/src/core/engine/master_conductor.py`
- `/home/bbb/Documents/App/Shigoku/tests/core/engine/test_master_conductor_intervention_gate.py`
- `/home/bbb/Documents/App/Shigoku/tests/core/engine/test_master_conductor_hitl_pending.py`
- `/home/bbb/Documents/App/Shigoku/tests/core/engine/test_master_conductor_scenario_probes.py`（SCN10 選別関連）

## 検証
- `./.venv/bin/pytest -q tests/core/engine/test_master_conductor_intervention_gate.py tests/core/engine/test_master_conductor_hitl_pending.py`
- `./.venv/bin/pytest -q tests/core/engine/test_intervention_policy.py`
- いずれも pass を確認。

## この時点の状態
- `SCN07-12` は Discord 通知が発火し、Ver.1 として手動運用へ回せる状態。
- `SCN07-12` が pending HITL として滞留しないため、実行キューの停滞を回避可能。
- `SCN10` の重複候補は一部減少したが、workflow seed が乏しい run では auth fallback が残るため、今後は seed 供給/選別ルールの追加改善余地あり。
- 追記（2026-05-14）:
  - SCN11 は manual_deferred から外し、通知は継続しつつ自動実行で coverage 到達を確認済み。
