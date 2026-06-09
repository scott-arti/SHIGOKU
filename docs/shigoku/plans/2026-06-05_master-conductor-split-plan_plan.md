---
task_id: SGK-2026-0264
doc_type: plan
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/specs/ARCHITECTURE.md
- docs/shigoku/specs/REQ_tier4_mc_intelligence.md
title: '巨大ファイル分割計画 1/4: MasterConductor 分割'
created_at: '2026-06-05'
updated_at: '2026-06-09'
tags:
- shigoku
target: src/core/engine/master_conductor.py
---

# 実装計画書：巨大ファイル分割計画 1/4: MasterConductor 分割

## 1. 達成したいゴール（ユーザー視点）
- [ ] この文書が「4件中の1件目」であることが明確であり、`src/core/engine/master_conductor.py` の分割境界を先に固定できること。
- [ ] `MasterConductor` の公開挙動を維持したまま、司令塔責務だけに絞る分割順序が定義されていること。
- [ ] 分割効果が高く、既存テストで守りやすい領域から優先して切り出す順序が共有されていること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: （修正）司令塔本体。最終的に orchestration facade のみに縮小する対象。
  - `src/core/engine/master_conductor_state_snapshot.py`: （既存）session / checkpoint / pending HITL の serialize・restore 境界。
  - `src/core/engine/master_conductor_session_service.py`: （既存）session save/load/checkpoint/resume の helper 境界。
  - `src/core/engine/master_conductor_hitl_snapshot.py`: （既存）pending HITL 用 task snapshot helper。
  - `src/core/engine/master_conductor_hitl_ticket.py`: （既存）pending HITL ticket schema builder。
  - `src/core/engine/master_conductor_recon_attack_task_planner.py`: （新規）recon 結果から attack task を展開する分割先候補。
  - `src/core/engine/master_conductor_hitl_service.py`: （新規）pending HITL ticket 管理と承認済み task enqueue の分割先候補。
  - `src/core/engine/master_conductor_dispatch_service.py`: （新規）`_dispatch` と agent routing の分割先候補。ただし safety / scope guard を保護してから着手する。
  - `src/core/engine/master_conductor_recon_execution_service.py`: （新規）`ReconPipeline` 実行と `PhaseGate` 反映の分割先候補。
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
  - 分割効果、既存テストの厚さ、公開挙動リスクの順で優先度を決める。
  - 現時点では `src.core.engine.master_conductor` がファイルモジュールとして解決されるため、同名サブパッケージ `src/core/engine/master_conductor/` は作らない。パッケージ化は import 互換設計が必要な別タスクに分離する。
- **推奨配置:**
  - `src/core/engine/master_conductor.py`: 外部公開APIを保持する facade。本計画中は import path の互換レイヤとして維持する。
  - `src/core/engine/master_conductor_*.py`: 現行 import 互換を保つ平置き helper/service 群。本計画ではこの配置を標準とする。
  - `src/core/engine/master_conductor_dependencies.py`: facade から各 service へ渡す依存束ね用 dataclass / protocol 群を置く候補。
  - `src/core/engine/master_conductor_state_snapshot.py`: session / checkpoint / pending HITL の serialize・restore 境界をまとめる既存 helper。
- **推奨ファイル命名:**
  - `master_conductor_recon_attack_task_planner.py`: recon classified results から attack task を組み立てるロジックを保持する。
  - `master_conductor_hitl_service.py`: intervention 判定、pending HITL ticket、承認済み task enqueue を保持する。
  - `master_conductor_dispatch_service.py`: `_dispatch` と agent routing を保持する。
  - `master_conductor_recon_execution_service.py`: `ReconPipeline` 実行と `PhaseGate` 反映を保持する。
  - `master_conductor_session_service.py`: session save/load/checkpoint/resume helper を保持する既存ファイルを継続利用する。
- **命名規則:**
  - ファイル名は `snake_case`、クラス名は `ConductorDispatchService` のように `対象 + 役割` を明示する。
  - `helper` や `utils` のような曖昧な命名は避け、責務がファイル名だけで判別できるようにする。
- **保守性の判断基準:**
  - shared state の所有者は facade のみとし、分割先は副作用境界ごとにテスト可能にする。
  - recon task 生成は最大行数の削減候補であり、`PhaseGate` 更新や queue mutation から切り離し、 task 構築ロジックを優先して純粋化する。
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

## 3.2.1 分割優先順位
現行 `src/core/engine/master_conductor.py` の method 行数実測では、主な削減候補は `_create_attack_tasks_from_recon` 約1327行、`_dispatch` 約561行、`_execute_single_task_full_flow` 約406行、`execute_with_replan` 約303行である。

| 優先 | 対象 | 主目的 | 理由 | 主な検証 |
|---|---|---|---|---|
| P0 | 配置・依存方針固定 | import 互換維持 | 同名サブパッケージ化は既存 `from src.core.engine.master_conductor import MasterConductor` を壊し得る | import smoke / 既存 master_conductor import 系 |
| P1 | recon attack task planner | 最大行数の削減 | `_create_attack_tasks_from_recon` が最大で、既存の routing / scenario probe テストが厚い | `test_master_conductor_api_candidate_routing.py`, `test_master_conductor_scenario_probes.py` |
| P2 | HITL service | 状態遷移の局所化 | pending/approved/queued/done の ticket 操作を閉じ込めやすい | `test_master_conductor_hitl_pending.py`, `test_master_conductor_hitl_priority.py` |
| P3 | dispatch service | routing 境界の明確化 | 効果は高いが scope guard / worker / swarm / recon / AgentFactory を含むため安全境界テストを先に厚くする | dispatch 専用 character tests, recon nonblocking |
| P4 | execution loop | facade の薄化 | 並列実行、checkpoint、precheck、summary が絡むため最後に寄せる | scenario / timeout / checkpoint 回帰 |
| P5 | session 残り | 既存 helper の仕上げ | 既に helper 化済みで追加削減効果は小さい | session service / persistence / resume 回帰 |

## 3.3 依存方向・所有権ルール
- facade が所有する shared state は `task_queue`、`context`、`phase_gate`、`event_bus`、`_state_lock`、`pending_hitl`、`project_manager` とする。
- service は `self` 全体を保持せず、必要な依存だけを `master_conductor_dependencies.py` または明示引数で受け取る。
- 依存方向は `master_conductor.py -> master_conductor_* service/helper -> serializer/helper` の一方向のみを許可し、 service 間の循環 import を禁止する。
- `master_conductor_recon_attack_task_planner.py` は queue mutation を持たず `list[Task]` を返す。`PhaseGate.can_create_task()`、recon file resolve、history replay など既存 `self` 依存は callable / context object として明示的に渡す。
- `master_conductor_recon_execution_service.py` は `PhaseGate` 更新完了後のみ planner を呼び出し、 planner から facade 全体を逆参照させない。

## 4. 実装ステップ（AIに指示する手順）
- [ ] 手順1/8: import 互換と配置を固定する。`src.core.engine.master_conductor` はファイルモジュールのまま維持し、新規分割先は `src/core/engine/master_conductor_*.py` の平置きに統一する。`__init__` の shared state を棚卸しし、`task_queue` / `context` / `phase_gate` / `event_bus` / `_state_lock` / `pending_hitl` / `project_manager` の所有権を `MasterConductor` facade に固定する。
- [ ] 手順2/8: session 残りを小さく閉じる。既存 `master_conductor_session_service.py` / `master_conductor_state_snapshot.py` を継続利用し、`resume_session` の外側 orchestration と workspace 初期化境界だけを整理する。`tests/core/engine/test_master_conductor_session_service.py`、`tests/core/engine/test_master_conductor_state_snapshot.py`、`tests/core/engine/test_master_conductor_session_payload_builder.py`、`tests/test_session_persistence.py`、`tests/test_session_resume.py`、`tests/unit/test_shared_session.py` を段階的に確認する。
- [ ] 手順3/8: 最大効果の `_create_attack_tasks_from_recon` を `master_conductor_recon_attack_task_planner.py` へ優先分割する。まず category map、low-value target filter、targets file 読み込み、task params builder、scenario probe 追加を小さな純粋 helper へ切る。`PhaseGate` 判定、recon file resolve、history replay、context auth/cookie は callable または依存 object として渡し、planner が facade 全体を保持しないようにする。
- [ ] 手順4/8: recon planner 分割後の routing / scenario probe 回帰を固定する。`tests/core/engine/test_master_conductor_api_candidate_routing.py` と `tests/core/engine/test_master_conductor_scenario_probes.py` を優先し、必要に応じて planner helper 単体テストを追加する。queue mutation は facade の `_add_tasks` 側に残す。
- [ ] 手順5/8: pending HITL の残りを `master_conductor_hitl_service.py` へ分割する。`pending_hitl` の所有は facade に残しつつ、`_build_task_from_hitl_snapshot`、status 更新、approved ticket enqueue、done marking の状態遷移を helper/service に寄せる。`tests/core/engine/test_master_conductor_hitl_pending.py` と `tests/core/engine/test_master_conductor_hitl_priority.py` で pending / approved / rejected / queued / done を確認する。
- [ ] 手順6/8: `_dispatch` 分割前の safety character tests を追加・固定する。post-exploit scope guard、worker route、swarm fallback、recon duplicate skip、AgentFactory fallback、recipe dispatch の公開挙動を確認してから `master_conductor_dispatch_service.py` へ移す。`tests/core/engine/test_master_conductor_recon_nonblocking.py` で isolated thread/loop 互換を守る。
- [ ] 手順7/8: `ReconPipeline` 実行を `master_conductor_recon_execution_service.py` へ分ける。`PhaseGate` 更新完了後のみ planner を呼ぶ順序、`_recon_executed` の重複実行防止、start/end step の扱いを固定し、`tests/core/engine/test_master_conductor_recon_nonblocking.py` と `tests/core/engine/test_master_conductor_recon_step_range.py` を確認する。
- [ ] 手順8/8: `execute_with_replan` と `_execute_single_task_full_flow` の統合動線を最後に点検する。parallel batch timeout、HITL precheck、checkpoint、summary、execution log の差分を確認し、旧ロジックの二重実装が残っていないこと、compatibility wrapper の削除候補が work_report に列挙できること、観測項目の劣化が許容範囲内であることを exit criteria とする。

### 4.1 現在の進捗メモ
- 旧手順5/8（session persistence）は着手済み。新手順2/8として小さく閉じ、以後は分割効果の高い recon planner へ移る。
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
- session persistence の残り:
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
- [ ] [発生確率:高][影響度:大] `master_conductor.py` と同名の `src/core/engine/master_conductor/` サブパッケージを作ると、既存 import path の互換を壊す可能性がある。
  - 対策: 本計画では平置き `src/core/engine/master_conductor_*.py` に統一し、パッケージ化は import re-export 設計と移行テストを含む別タスクに分離する。
- [ ] [発生確率:高][影響度:大] facade が保持すべき shared state と service が扱える依存の境界が曖昧だと、再び god object と循環参照を生む。
  - 対策: `## 3.3 依存方向・所有権ルール` と手順1-2で shared state の所有者と禁止依存を明記する。
- [ ] [発生確率:中][影響度:大] recon task planner は行数削減効果が最大だが、現状は `PhaseGate`、recon file resolve、history replay、context auth/cookie などの facade 依存を多く持つ。
  - 対策: 手順3で callable / context object として依存を明示し、planner から facade 全体を逆参照させない。queue mutation は facade に残す。
- [ ] [発生確率:中][影響度:中] facade 化の完了条件が弱いと、分割後も domain logic が facade に残る。
  - 対策: `## 3.1` と手順8で facade の完了条件と exit criteria を追加する。

### 5.3 デバッガー視点
- [ ] [発生確率:高][影響度:大] dispatch 分割を先に進めると、scope guard / worker / swarm / recon / AgentFactory fallback の破壊を見逃しやすい。
  - 対策: 手順6で dispatch 専用 character tests を先に追加し、`test_master_conductor_api_candidate_routing.py` は recon task planner 側の回帰として扱う。
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
