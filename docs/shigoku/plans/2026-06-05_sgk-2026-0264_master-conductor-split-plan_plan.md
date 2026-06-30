---
task_id: SGK-2026-0264
doc_type: plan
status: active
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/specs/ARCHITECTURE.md
- docs/shigoku/specs/REQ_tier4_mc_intelligence.md
title: '巨大ファイル分割計画 1/4: MasterConductor 分割'
created_at: '2026-06-05'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/core/engine/master_conductor.py
---

# 実装計画書：巨大ファイル分割計画 1/4: MasterConductor 分割

## 1. 達成したいゴール（ユーザー視点）
- [ ] この文書が「4件中の1件目」であることが明確であり、`src/core/engine/master_conductor.py` の分割境界を先に固定できること。
- [ ] `MasterConductor` の公開挙動を維持したまま、司令塔責務だけに絞る分割順序が定義されていること。
- [ ] 再計画、dispatch、session/HITL、recon後タスク生成の4領域を別モジュールへ切り出す判断基準が共有されていること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: （修正）司令塔本体。最終的に orchestration facade のみに縮小する対象。
  - `src/core/engine/master_conductor/dependencies.py`: （新規）facade から各 service へ渡す依存束ね用 dataclass / protocol を保持する候補。
  - `src/core/engine/master_conductor/state_snapshot.py`: （新規）session / checkpoint / pending HITL の serialize・restore 境界を保持する候補。
  - `src/core/engine/master_conductor/dispatch_service.py`: （新規）`_dispatch` と agent ルーティングを保持する分割先候補。
  - `src/core/engine/master_conductor/session_service.py`: （新規）session save/load、checkpoint、resume を保持する分割先候補。
  - `src/core/engine/master_conductor/hitl_service.py`: （新規）pending HITL ticket と intervention 関連処理を保持する分割先候補。
  - `src/core/engine/master_conductor/recon_execution_service.py`: （新規）`ReconPipeline` 実行と `PhaseGate` 反映を保持する分割先候補。
  - `src/core/engine/master_conductor/recon_attack_task_planner.py`: （新規）recon 結果から attack task を展開する分割先候補。
- **データの流れ / 依存関係:**
  - CLI / interactive bridge -> `MasterConductor` facade -> dependencies / service modules -> task queue / persistence / notification

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `Task`, `ExecutionContext`, session payload, recon classified results
- **出力/結果 (Output):** 既存と同じ task execution result、session persistence payload、HITL state、attack task list
- **制約・ルール:**
  - `MasterConductor` の public API は維持し、呼び出し側の import path をこの計画では変えない。
  - `task_queue`, `context`, `phase_gate`, `event_bus` などの共有状態は一箇所で所有し、分割先へは明示的に渡す。
  - session schema、HITL ticket schema、task result schema は互換維持を優先し、構造変更は別タスクに分離する。

## 3.1 アーキテクト判断: 分割原則と配置方針
- **分割の最優先原則:**
  - `MasterConductor` 自体は最後まで `state owner + orchestration facade` として残し、shared state の所有権は移譲しない。
  - 分割先モジュールは `self` 全体を握らず、必要な依存だけを明示的に受け取る。
  - 機能別分割より先に、責務の種類別分割（dispatch / session persistence / HITL / recon-to-attack planning）を優先する。
- **推奨配置:**
  - `src/core/engine/master_conductor.py`: 外部公開APIを保持する facade。本計画中は import path の互換レイヤとして維持する。
  - `src/core/engine/master_conductor/`: `MasterConductor` 専用の分割先サブパッケージ。engine 直下へ `conductor_*.py` を増やし続けず、責務を局所化する。
  - `src/core/engine/master_conductor/dependencies.py`: facade から各サービスへ渡す依存束ね用 dataclass / protocol 群を置く候補。
  - `src/core/engine/master_conductor/state_snapshot.py`: session / checkpoint / pending HITL の serialize・restore 境界をまとめる候補。
- **推奨ファイル命名:**
  - `dispatch_service.py`: `_dispatch` と agent routing を保持する。
  - `session_service.py`: `save_session` / `load_session` / `start_session` / `_checkpoint` / `resume_session` を保持する。
  - `hitl_service.py`: intervention 判定、pending HITL ticket、承認済み task enqueue を保持する。
  - `recon_execution_service.py`: `ReconPipeline` 実行と `PhaseGate` 反映を保持する。
  - `recon_attack_task_planner.py`: recon classified results から attack task を組み立てる純粋ロジックを保持する。
- **命名規則:**
  - ファイル名は `snake_case`、クラス名は `ConductorDispatchService` のように `対象 + 役割` を明示する。
  - `helper` や `utils` のような曖昧な命名は避け、責務がファイル名だけで判別できるようにする。
- **保守性の判断基準:**
  - shared state の所有者は facade のみとし、分割先は副作用境界ごとにテスト可能にする。
  - recon task 生成は `PhaseGate` 更新などの副作用から切り離し、 task 構築ロジックを優先して純粋化する。
  - session / HITL は CLI と dashboard の双方が読むため、 schema 互換維持を優先し、 serializer 層へ閉じ込める。
  - facade の完了条件は `state owner / public API / thin wrapper / orchestration coordination` のみを残し、domain logic を service 側へ移し終えることとする。

## 3.2 運用・観測性要件
- **ログ / イベント契約:**
  - dispatch / session / HITL / recon execution の各 service は `correlation id` / `task id` / `session id` を受け取り、既存ログキーを維持する。
  - 各 service は開始・終了・失敗を識別できる統一形式の log または event を emit する。
- **エラーハンドリング契約:**
  - service は例外を意味づけした結果または例外として返し、最終的な task state / execution log / failure context の反映は facade 側で一元管理する。
  - session save/load/checkpoint は既存同等の fail-soft を維持し、保存失敗時もプロセス継続・error log emit・session 破損禁止を守る。
- **ランタイム契約:**
  - `ReconPipeline` の isolated thread / event loop 実行方式は互換維持を優先し、 main loop starvation と false timeout cascade を再発させない。
  - 分割後も `pending_hitl_count`、checkpoint 所要時間、`execute_with_replan` の total duration を比較可能に保つ。

## 3.3 依存方向・所有権ルール
- facade が所有する shared state は `task_queue`、`context`、`phase_gate`、`event_bus`、`_state_lock`、`pending_hitl`、`project_manager` とする。
- service は `self` 全体を保持せず、必要な依存だけを `dependencies.py` 経由で受け取る。
- 依存方向は `master_conductor.py -> service -> helper / serializer` の一方向のみを許可し、 service 間の循環 import を禁止する。
- `recon_attack_task_planner.py` は queue mutation を持たず `list[Task]` を返す純粋ロジックとして保つ。
- `recon_execution_service.py` は `PhaseGate` 更新完了後のみ planner を呼び出し、 planner から facade 全体を逆参照させない。

## 4. 実装ステップ（AIに指示する手順）
- [ ] 手順1/8: `__init__` の shared state を棚卸しし、`task_queue` / `context` / `phase_gate` / `event_bus` / `_state_lock` / `pending_hitl` / `project_manager` の所有権を `MasterConductor` facade に固定する。合わせて `src/core/engine/master_conductor/` サブパッケージと `dependencies.py` / `state_snapshot.py` の責務境界を文書化する。
- [ ] 手順2/8: facade から service へ渡す依存を dataclass または protocol で定義し、`master_conductor.py -> service -> helper / serializer` の依存方向を固定する。 service が `self` 全体へ依存しない受け口を先に作り、禁止依存（shared state の直接所有）も明文化する。
- [ ] 手順3/8: observability / runtime 契約を先に固定する。各 service が受け取る `correlation id` / `task id` / `session id`、開始・終了・失敗の log/event 形式、 facade 側の task state / execution log 一元反映ルールを定義し、分割前後で比較する観測項目（`pending_hitl_count`、checkpoint 所要時間、`execute_with_replan` duration）を決める。
- [ ] 手順4/8: `_dispatch` とその周辺 helper を `dispatch_service.py` へ移し、`MasterConductor` からは thin wrapper として呼び出す。agent routing と worker / swarm / recon 分岐の回帰を `tests/core/engine/test_master_conductor_api_candidate_routing.py` で確認し、既存ログキーが維持されることも点検する。
- [ ] 手順5/8: `save_session` / `load_session` / `start_session` / `_checkpoint` / `resume_session` を `session_service.py` と `state_snapshot.py` へ移し、 session schema と pending HITL restore 挙動の互換を維持する。`tests/unit/test_shared_session.py` を優先実行し、 missing field / invalid state / fail-soft 保存の回復系も確認する。
- [ ] 手順6/8: intervention 判定、pending HITL ticket 管理、承認済み task enqueue を `hitl_service.py` へ移す。`pending_hitl` の所有は facade に残しつつ、decision / ticket / approval のロジックだけを分離し、`tests/core/engine/test_master_conductor_hitl_pending.py` と `tests/core/engine/test_master_conductor_hitl_priority.py` で pending / approved / rejected の回帰を確認する。
- [ ] 手順7/8: `ReconPipeline` 実行を `recon_execution_service.py` へ、 recon classified results から attack task を生成する純粋ロジックを `recon_attack_task_planner.py` へ分割する。`PhaseGate` 更新完了後のみ planner を呼ぶ順序を固定し、`tests/core/engine/test_master_conductor_recon_nonblocking.py` と `tests/core/engine/test_master_conductor_recon_step_range.py` で isolated thread/loop と step 範囲の互換を確認する。
- [ ] 手順8/8: `execute_with_replan` の統合動線を点検し、`tests/core/engine/test_master_conductor_scenario_probes.py` と関連回帰を通して facade 化後の挙動差分を確認する。最後に旧ロジックの二重実装が残っていないこと、 compatibility wrapper の削除候補が work_report に列挙できること、観測項目の劣化が許容範囲内であることを exit criteria として確認する。

### 4.1 現在の進捗メモ
- 手順5/8 は着手済み。
- 完了済み slice:
  - `state_snapshot.py` へ `pending_hitl` / `context` / `completed_tasks` / `task_queue` の restore ロジックを分離した。
  - `session_service.py` へ RUNNING task 再実行ポリシー判定、session file 読み込み、save payload builder を分離した。
  - `MasterConductor.load_session()` と `async_save_session()` は対応 helper を呼ぶ thin 化を進めた。
- 今回追加で確認した事項:
  - 旧セッション系テストを現行 `DynamicTaskQueue` / `_deserialize_task_queue()` 仕様へ更新し、 session service 導入後の互換を再固定した。
  - `resume_session()` から到達する `initialize_workspace()` に、 legacy `src.config.settings` と core `src.core.config.settings` の差異で `multi_session` を参照できず落ちる実バグがあったため、安全な settings 解決を追加した。
  - `_checkpoint()` の pending/completed targets と metadata 構築を `build_checkpoint_session_state()` へ切り出し、 legacy session 用 task queue JSON 変換を `serialize_legacy_session_task_queue()` へ共通化した。
  - `resume_session()` の context / pending HITL / task queue 復元を `restore_legacy_resume_session_state()` へ切り出し、 legacy Session からの in-memory state 組み立てを helper 化した。
  - `start_session()` の session create 引数構築を `build_start_session_payload()` へ、`save_session()` の Future 待機ポリシーを `await_session_save_future()` へ切り出した。
  - HITL は `build_pending_hitl_ticket()` を追加し、 pending ticket schema の組み立てを `MasterConductor` から切り離し始めた。
- 手順5/8 の残り:
  - `resume_session` の外側 orchestration を service へさらに寄せる。
  - `resume_session` では workspace 初期化境界をどう扱うかを小さく整理する。
  - `tests/unit/test_shared_session.py` を含む、より広い session 関連回帰を段階的に追加確認する。

## 5. 懸念点と対策
### 5.1 SRE / インフラエンジニア視点
- [ ] [発生確率:高][影響度:大] service 分割後に observability が散り、障害時にどこで落ちたか追跡しづらくなる。
  - 対策: `## 3.2 運用・観測性要件` と手順3で log/event 契約、相関ID、観測項目を先に固定し、分割前後で比較できるようにする。
- [ ] [発生確率:中][影響度:大] `ReconPipeline` の isolated thread / event loop 実行が崩れ、 main loop starvation や false timeout cascade が再発する。
  - 対策: `## 3.2` と手順7で runtime 契約として互換維持を明記し、 recon 非ブロッキング系テストで固定する。
- [ ] [発生確率:中][影響度:中] session/checkpoint 分離で永続化失敗時の振る舞いが曖昧になり、復旧性が落ちる。
  - 対策: `## 3.2` と手順5で fail-soft 保存、error log emit、session 破損禁止を契約として明記し、回復系テストで確認する。
- [ ] [発生確率:中][影響度:中] 分割後の性能劣化を測る比較指標がなく、 checkpoint や再計画の遅延を見逃しやすい。
  - 対策: 手順3と手順8で `pending_hitl_count`、checkpoint 所要時間、`execute_with_replan` duration の比較を exit criteria に組み込む。

### 5.2 ソフトウェアアーキテクト視点
- [ ] [発生確率:高][影響度:中] 旧 `conductor_*.py` 案とサブパッケージ案が混在すると、配置方針がぶれて保守性が落ちる。
  - 対策: `## 2. 全体像` をサブパッケージ構成へ統一し、 service 配置を `src/core/engine/master_conductor/` 配下に固定する。
- [ ] [発生確率:高][影響度:大] facade が保持すべき shared state と service が扱える依存の境界が曖昧だと、再び god object と循環参照を生む。
  - 対策: `## 3.3 依存方向・所有権ルール` と手順1-2で shared state の所有者と禁止依存を明記する。
- [ ] [発生確率:中][影響度:大] recon execution と recon task planning の副作用境界が曖昧だと、 `PhaseGate` 順序や queue mutation が壊れやすい。
  - 対策: `## 3.3` と手順7で planner の純粋性、 `PhaseGate` 更新後のみ planner 実行の順序契約を明記する。
- [ ] [発生確率:中][影響度:中] facade 化の完了条件が弱いと、分割後も domain logic が facade に残る。
  - 対策: `## 3.1` と手順8で facade の完了条件と exit criteria を追加する。

### 5.3 デバッガー視点
- [ ] [発生確率:高][影響度:大] 現行計画の回帰確認範囲が狭く、 dispatch 以外の破壊を見逃しやすい。
  - 対策: 手順5-8に session / HITL / recon の具体テストファイルを追加し、手順ごとに対象テストを明確化する。
- [ ] [発生確率:中][影響度:中] 不具合発生時の切り分け順序がないため、調査時間が伸びやすい。
  - 対策: 本節で切り分け順序を `dependency injection境界 -> serializer境界 -> queue mutation -> phase gate -> external side effects` と定義し、 work_report にも残せるようにする。
- [ ] [発生確率:中][影響度:大] session/HITL の schema 互換は方針だけで、 missing field や未知 state の回復挙動が計画にない。
  - 対策: 手順5-6で invalid state / missing field / pending HITL fallback の回復系テストを明記する。
- [ ] [発生確率:中][影響度:中] 例外時に facade と service のどちらが state 更新と記録を持つか不明確だと、二重記録や記録漏れが起きる。
  - 対策: `## 3.2` と手順3で error handling 契約を定義し、 facade に最終反映を一元化する。

### 5.4 CTO視点
- [ ] [発生確率:中][影響度:中] service を増やす基準がないと、分割後にモジュール乱立へ向かう。
  - 対策: `## 3.1` の分割原則と `## 3.3` の依存ルールを service 追加条件として扱い、 shared state 直所有や曖昧責務の新規 service を禁止する。
- [ ] [発生確率:高][影響度:中] 成功指標が「分割できた」寄りで、変更容易性や検証可能性の向上が測れない。
  - 対策: 手順8の exit criteria に公開挙動維持、主要回帰通過、依存注入境界固定、観測項目比較を含める。
- [ ] [発生確率:中][影響度:大] service 間循環や facade 逆参照を許すと、将来の orchestration 置換や platform 分離が難しくなる。
  - 対策: `## 3.3` で依存方向を一方向に固定し、 `ReconPipeline` や planner から facade 全体を逆参照させない。
- [ ] [発生確率:中][影響度:中] 段階移行後の完了判定が弱いと、旧ロジックの二重実装を残したまま次の巨大ファイル分割へ進んでしまう。
  - 対策: 手順8で二重実装の有無、 compatibility wrapper の削除候補、 exit criteria 充足を確認してから完了扱いにする。

### 5.5 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0264-D01
    title: "継続監視: MasterConductor 分割後の回帰監視"
    reason: "分割後も dispatch / session / HITL / recon planning の挙動監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
