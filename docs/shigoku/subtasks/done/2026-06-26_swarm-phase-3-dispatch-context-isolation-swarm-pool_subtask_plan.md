---
task_id: SGK-2026-0312
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0291
related_docs:
- docs/shigoku/subtasks/2026-06-23_sgk-2026-0291_swarm-parallelism-review_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-0_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-1-additive-execution-contract-debug-metadata_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-2-scope-admission-per-origin-budget-policy_subtask_plan.md
- docs/shigoku/subtasks/2026-06-27_sgk-2026-0312_phase3-implementation-instruction_manual.md
- docs/shigoku/reports/2026-06-27_sgk-2026-0312_work_report.md
- docs/shigoku/worklogs/2026-06-27_sgk-2026-0312_work_log.md
title: 'Swarm並列化 Phase 3: dispatch context isolation と Swarm pool安全化'
created_at: '2026-06-26'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/core/engine/swarm_dispatcher.py, src/core/agents/swarm/base_manager.py,
  src/core/agents/swarm/injection/manager.py
---

# 実装計画書：Swarm並列化 Phase 3: dispatch context isolation と Swarm pool安全化

## 1. 達成したいゴール（ユーザー視点）
- [ ] 並列度を上げる前に、Swarm / Manager の dispatch 単位コンテキスト汚染を防ぐこと。
- [ ] `current_context`、findings、url_results、auth_headers、cookies が同時dispatch間で混ざらないこと。
- [ ] Swarm pool再利用の条件を `stateless_reusable` / `dispatch_scoped` / `guarded_reuse` に分類すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/swarm_dispatcher.py`: `_swarm_pool`（L75）と `_get_or_create_swarm()`（L93-136）の再利用条件を安全化。shared service injection path（L111-132）は維持し、新規インスタンス生成時に再利用する。
  - `src/core/agents/swarm/base_manager.py`: `current_context`（L66）・`history`（L63）・`total_tools_executed`（L195）のdispatch-local化またはcompatibility shim。
  - `src/core/agents/swarm/injection/manager.py`: InjectionManager の `current_context`（L1863-1870 初期化）・`url_results`（L1948+）・`_phase2_detection_mode`（L1843）・findings集約（30+箇所）の分離。
  - `tests/`: concurrent dispatch isolation regression。
- **継承ベースの stateful 分類（実コード確認済み・分類根拠）:**
  - **stateful（`BaseManagerAgent(SwarmManager)` 継承・`current_context`/`history` を持つ）:** `InjectionManagerAgent` / `AuthManagerAgent` / `LogicManagerAgent` / `DiscoveryManagerAgent`（4 Swarm）→ `dispatch_scoped`（per-dispatch instance）を Phase 3 default とする。
  - **specialist 直列（plain `SwarmManager(ABC)` 継承）:** `SecretSwarm` / `ScannerSwarm` / `IntelligenceSwarm` / `FuzzingSwarm`（4 Swarm）→ `stateless_reusable` 候補。各 Swarm の固有インスタンス状態は Step 0 で個別確認する。
- **データの流れ / 依存関係:**
  - SwarmDispatcher -> Swarm instance selection -> dispatch-local context -> manager execution -> isolated SwarmResult。
  - Phase 5以降の実並列化は本フェーズ完了を前提にする（親計画 4.4 Go条件「dispatch context isolation test」の硬前提）。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** Task、dispatch params、auth headers、cookies、session id、project id、Phase 1 成果物の `correlation_id` / `origin_key` / `auth_context_version`、existing Swarm pool。
- **出力/結果 (Output):** dispatch-local context（`dispatch_id` / `correlation_id` stamp付き）、isolated findings、isolated url_results、isolated history、pool reuse decision（継承ベース分類）。
- **制約・ルール:**
  - SwarmManager specialist内側並列化は本フェーズの対象外。
  - Injection URL処理の並列化は本フェーズの対象外。
  - **【Blocker解消決定】Phase 3 の隔離メカニズムは per-dispatch instance（pool 全廃止）に固定する。** `_get_or_create_swarm()` は dispatch ごとに新規 Swarm インスタンスを生成し、shared service injection path（swarm_dispatcher.py:111-132）で network/llm/event_bus/recipe/rag を注入する。インスタンスが dispatch 単位なので `current_context` / `history` / `total_tools_executed` / `_phase2_detection_mode` は構造上汚染されず、compatibility shim / ContextVar / DispatchContext threading は Phase 3 では不要（Phase 8 内側並列化評価時に導入）。pool 再利用復活（stateless 最適化）は Phase 5 へ deferred。
  - per-dispatch instance は dispatch 後に `try/finally` で `close()` する（`_ephemeral_network_clients` 等の per-manager 一時リソース解放）。ただし shared `network_client` / `llm_client` は `SwarmManager.close()`（base.py:244）および `Specialist.close()`（base.py:150-152「共有リソースのため close しない」）が閉じないため安全。
  - shared immutable service（network_client / llm_client / event_bus / loop / recipe_loader / rag）は必ず shared/injection 維持し、分離対象にしない（性能回帰防止）。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ0（事前調査・Phase 5 入力）: **継承ベース stateful inventory の作成（Phase 0 成果物を入力）**
  - 8 Swarm の継承元（`BaseManagerAgent` vs plain `SwarmManager`）を確認し stateful / specialist直列 を分類する。Phase 3 は per-dispatch-ALL で安全化するため本 inventory は Phase 3 の実行ブロックではなく、Phase 5 で pool 再利用を復活させる Swarm を特定するための入力とする。
- [ ] ステップ1（検証）: **per-dispatch instance で漏れる経路がないかの検証（設計前提の確認のみ）**
  - per-dispatch instance 化で `self.current_context` / `self.history` / `self.total_tools_executed` / `self._phase2_detection_mode` が全て dispatch 単位に隔離されることを確認する。クラスレベル変数や shared service 経由の隠れ状態がないか grep/読解で点検する（隠れ状態があれば Step 2 で個別対応）。
- [ ] ステップ2（実装）: **`_get_or_create_swarm()` を per-dispatch 生成へ変更**
  - `_swarm_pool` へのキャッシュを廃止（または `parallelism.enabled=false` 時のみ従来 pool を維持する切替）し、dispatch ごとに新規 Swarm インスタンスを生成する。shared service injection path（swarm_dispatcher.py:111-132）を再利用して network/llm/event_bus/recipe/rag を注入する。
  - dispatch 後に `try/finally` で `swarm.close()` を呼ぶ（per-manager 一時リソース解放）。shared client は閉じないことを Step 1 で確認済み。
- [ ] ステップ3（検証）: **shared service identity 保持の確認**
  - per-dispatch instance 化しても network_client/llm_client/event_bus の object identity が dispatch 間で同一であることを検証する（性能回帰防止）。
- [ ] ステップ4: **決定的な同時dispatch分離テストを追加**
  - 同一Manager型に2 taskを `asyncio.gather` で同時dispatchし、**バリア/event で汚染窓を強制 interleave** する。per-dispatch instance で各 dispatch が別インスタンスを受けることを assert し、findings / auth_headers / cookies / url_results / history が混ざらないことを検証する。
  - 各 dispatch に固有の marker target / payload を注入し、帰属を検証する。
- [ ] ステップ5: 既存Swarm dispatch（`tests/unit/engine/test_swarm_dispatcher_close.py` 等）とInjectionManager回帰（`tests/core/agents/swarm/injection/test_process_url_dispatcher.py`）を実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] pool再利用禁止で性能が落ちる - per-dispatch instance（pool全廃止）で正しさを優先し、Phase 5 で stateless Swarm だけ pool 再利用を復活させる（Step 0 inventory が入力）。shared service は injection 維持で client 再生成コストは回避済み。
- [ ] [重要度:中] per-dispatch instance の `close()` 呼び忘れで一時リソース（`_ephemeral_network_clients` 等）が漏れる - Step 2 で `try/finally` を必須化し、テストで leak を検出する。
- [ ] [重要度:中] InjectionManagerの文脈が深く、内側並列化には DispatchContext threading が必要 - Phase 3 は per-dispatch instance で外側汚染を防ぐ。完全 threading は Phase 8 内側並列化評価時に導入（D-1）。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0312-D01
    title: "継続監視: per-dispatch instance の性能影響と pool 復活候補"
    reason: "Phase 3 は pool 全廃止で正しさ優先。stateless Swarm の pool 再利用復活は Phase 5"
    impact: medium
    tracking_task_id: SGK-2026-0312
    recommended_next_action: "Phase 5 開始前に Step 0 inventory で stateless Swarm を特定し pool 復活を評価する"
```

---

## 6. 実装前レビュー結果（2026-06-27）

### 6.1 Phase要約
- **目的:** 並列化（Phase 5）前に、Swarm pool再利用と `BaseManagerAgent`/`InjectionManagerAgent` のインスタンス状態（`current_context`/`history` 等）上書きによる同時dispatchコンテキスト汚染を防ぐ。
- **Non-Goals:** SwarmManager specialist内側並列化、Injection URL処理並列化、protective degrade mode（Phase 7）、lane scheduler/mutex（Phase 4）、SwarmDispatcher複数Swarm同時呼び出し（Phase 8）、`TaskState` enum変更（Phase 1でdeferred済み）。
- **前提条件:** Phase 0（並列/直列正本化）・Phase 1（Task.metadata / correlation_id追加）・Phase 2（origin_key/admission/budget）が完了済み。Phase 2成果物は実コードに存在（`admission_policy.py` / `budget_policy.py` / `origin_normalizer.py` / `ParallelismSettings`）。
- **完了条件:** 同一Swarm/Manager型へ2つのtaskを同時dispatchしても findings / url_results / auth_headers / cookies / history が混ざらない。shared immutable serviceのidentityは保持される。既存serial実行が従来互換。

### 6.2 Ready / Not Ready
- **判定（2026-06-27 更新）: Ready — Blocker 4件を per-dispatch instance 決定で最小解消済み。前提Phase（0/1/2）は全て完了済み。**
- 解消経緯: 当初 LB-1（隔離メカニズム/shim設計欠陥）・LB-2（汚染面の拡大）・LB-3（テスト決定性）・LB-4（分類基準）で Not Ready とした。しかし Phase 3 の隔離メカニズムを **per-dispatch instance（pool 全廃止）** に固定すると、共有インスタンスが消滅し汚染経路そのものがなくなるため LB-1/LB-2 は設計上解消され、LB-3 は保証検証に簡素化され、LB-4 は Phase 3 クリティカルパスから外れて Phase 5 pool 復活入力に退化する。
- 最小性: 本決定は `swarm_dispatcher.py` の `_get_or_create_swarm()` と dispatch 呼び出し経路（`try/finally` close 追加）のみへの局所変更で達成可能。manager 内部・他フェーズのコード・計画書は変更不要（DispatchContext/threading は Phase 8、pool 復活は Phase 5 が既に所管）。shared `network_client`/`llm_client` は `SwarmManager.close()`（base.py:244）・`Specialist.close()`（base.py:150-152）が閉じないため injection 維持で安全（実コード確認済み）。
- 残リスク（実装中に No-Go に戻す条件）: per-dispatch instance でも漏れる隠れ共有状態（クラス変数・module global・shared service 経由の mutable cache）が Step 1 で発見された場合、または `close()` 呼び忘れで一時リソース leak が検出された場合は実装を止めて再評価する。

### 6.3 Local Blocker（per-dispatch instance 決定で解消済み）
- [x] **LB-1: 隔離メカニズム未決定 ＋ compatibility shim 設計欠陥 → 解消。** per-dispatch instance（pool 全廃止）により共有インスタンスが消滅し、`self.current_context`（base_manager.py:66）の上書き・`report_finding`（L504）の append も dispatch 単位に隔離される。compatibility shim / ContextVar / DispatchContext threading は不要となり Phase 8 へ defer。shim 経由の自己状態書き戻し問題は存在しなくなる。
- [x] **LB-2: 汚染面が `current_context` だけではない → 解消。** per-dispatch instance で `self.history`（base_manager.py:63/193）・`self.total_tools_executed`（:195）・`self._phase2_detection_mode`（injection:1843）も含む全インスタンス状態が一括隔離される。個別 threading 不要。Step 1 でクラス変数・shared service 経由の隠れ状態がないか点検し残りを確認する。
- [x] **LB-3: 同時dispatch分離テストの決定性未規定 → 簡素化。** per-dispatch instance で各 dispatch が別インスタンスを受けることが構造保証されるため、テストは「別インスタンス受領の assert ＋ 汚染非発生の検証」になる。決定性はバリア強制 interleave ＋ 固有 marker target で担保する（Step 4）。
- [x] **LB-4: pool再利用分類に証拠ベース基準がない → Phase 3 から除外。** Phase 3 は per-dispatch-ALL で安全化するため分類は不要。継承ベース分類（BaseManagerAgent 継承4＝stateful、plain SwarmManager 継承4＝stateless候補）は Step 0 で作成し Phase 5 の pool 復活入力とする。Phase 3 の Go 条件は壊さない。

### 6.4 TDDチェックリスト
- [ ] **T-0.1: `test_serial_dispatch_baseline`** — 現行serial dispatchのfindings結果を固定するcharacterization test（コード変更前に追加し baseline を確保。変更後も serial 結果が同一であることを回帰で使う）。
- [ ] **T-1.1: `test_shared_services_preserved_across_dispatch`** — per-dispatch instance 化しても network_client/llm_client/event_bus の object identity が dispatch 間で保持される（性能回帰防止）。shared service が再生成されない。
- [ ] **T-1.2: `test_inheritance_based_stateful_inventory`** — Step 0 inventory の成果を固定: BaseManagerAgent 継承 Swarm（injection/auth/logic/discovery）が stateful、plain SwarmManager 継承 Swarm（secret/scanner/intelligence/fuzzing）が stateless候補。Phase 3 は per-dispatch-ALL なので本 test は Phase 5 pool 復興の入力データを固定する役割。
- [ ] **T-2.1: `test_concurrent_dispatch_findings_isolation`** — 同一Swarm型へ2 task を gather 同時dispatch、バリアで汚染窓を強制interleave、固有marker target で findings が混ざらない。
- [ ] **T-2.2: `test_concurrent_dispatch_auth_headers_cookies_isolation`** — dispatch A/B に異なる auth_headers/cookies を与え、互いに流入しない。
- [ ] **T-2.3: `test_concurrent_dispatch_url_results_isolation`** — InjectionManager の `url_results` が同時dispatchで混ざらない。
- [ ] **T-2.4: `test_concurrent_dispatch_history_isolation`** — 2つの BaseManagerAgent dispatch で LLM history ターンが交錯しない（汚染窓で履歴を記録するinstrumented tool を挿入）。
- [ ] **T-2.5: `test_per_dispatch_instance_close_on_exception`** — dispatch が途中で例外を出しても per-dispatch instance が `try/finally` で close され、shared client は閉じず次 dispatch に漏れない。
- [ ] **T-3.1: `test_per_dispatch_instance_distinct`** — `_get_or_create_swarm` が同一 swarm_name でも dispatch ごとに別インスタンスを返す（pool キャッシュ廃止の検証）。加えて `test_no_ephemeral_resource_leak` で dispatch 後に `_ephemeral_network_clients` 等の一時リソースが残存しない。
- [ ] **T-4.1: `test_existing_swarm_dispatch_regression`** — `tests/unit/engine/test_swarm_dispatcher_close.py` 等の既存Swarm dispatch test が全 PASS。
- [ ] **T-4.2: `test_injection_process_url_regression`** — `tests/core/agents/swarm/injection/test_process_url_dispatcher.py` 等の InjectionManager 回帰が全 PASS。close() が dispatch-local state を全クリアする。

### 6.5 Go/No-Go Gate
- [ ] **Go:** `_get_or_create_swarm` が dispatch ごとに別インスタンスを返す（pool キャッシュ廃止: T-3.1）。
- [ ] **Go:** 同一Swarm型への2同時dispatchで findings / auth_headers / cookies / url_results / history が混ざらない（forced interleaving で検証: T-2.1〜T-2.4）。
- [ ] **Go:** shared immutable service（network/llm/event_bus）の object identity が保持される（性能回帰なし: T-1.1）。
- [ ] **Go:** dispatch 例外時に per-dispatch instance が close され、shared client は閉じず次 dispatch に漏れない（T-2.5）。一時リソース leak なし（T-3.1）。
- [ ] **Go:** 既存 serial 実行が従来互換（T-0.1 baseline と T-4.1, T-4.2 全 PASS）。
- [ ] **Go:** T-0.1 から T-4.2 の全テストが PASS。
- [ ] **Go:** `python3 scripts/sync_shigoku_updated_at.py` 後に `python3 scripts/validate_shigoku_docs.py` が 0 エラー。
- [ ] **No-Go (未該当確認):** 同一 swarm_name で pool キャッシュが残り同一インスタンスが再利用される（分離不十分: T-3.1 fail）。
- [ ] **No-Go (未該当確認):** history 交錯が再現する（LLMが別dispatchの思考ターンを見る: T-2.4 fail）。
- [ ] **No-Go (未該当確認):** shared client が再生成され性能回転する、または dispatch 後 close で shared client が閉じられる（T-1.1/T-2.5 fail）。
- [ ] **No-Go (未該当確認):** 既存 serial Swarm/Injection dispatch が壊れる（T-4.1/T-4.2 fail）。

### 6.6 Shadow / Differential Testing
- [ ] **S-1: per-dispatch instance shadow** — per-dispatch instance 化を有効化しつつ、実スケジュールは serial のままで T-0.1 baseline と Finding parity / result parity が一致することを確認する。
- [ ] **S-2: pool 有効/無効 differential** — 従来 pool 再利用経路と per-dispatch instance 経路で同一タスクの結果が一致する（分離が意味を変えないことの検証）。`parallelism.enabled=false` で従来 pool に戻せる切替を残す場合の切戻し確認。
- [ ] **S-3: cross-dispatch 漏れ監査** — 各 dispatch に固有 marker を与え、findings に別 dispatch の marker が混入しないことを監査ログ/結果から事後検出可能にする。

### 6.7 Local Deferred（後続Phaseへ送る）
| # | 項目 | Deferred先 | 安全な理由 | 検出方法 |
|---|---|---|---|---|
| D-1 | InjectionManager の完全 DispatchContext threading（30+ current_context 参照の全置換） | Phase 8 (SGK-2026-0317) | Phase 3 は InjectionManager を per-dispatch instance＋直列維持で安全化できる。完全 threading は Phase 8 内側並列化評価時に必要 | Phase 8 で current_context 残存 grep + Injection URL request budget test / partial failure aggregation test |
| D-2 | `_dispatcher` シングルトン second-call overwrite（swarm_dispatcher.py:599-607）の厳密化 | Phase 5 (SGK-2026-0314) | manager 単位の context 分離が主眼。シングルトン再設定競合は外側並列化開始時に顕在化 | Phase 5 で outer parallel dispatch の singleton re-init 回帰テスト |
| D-3 | pool 再利用復活（stateless 最適化）と guarded reuse 実証 | Phase 5 (SGK-2026-0314) | Phase 3 は per-dispatch instance で正確性優先。性能最適化は Phase 5 | Phase 5 で stateless 再利用の performance parity test |

### 6.8 Parent Change Request（親計画へ反映提案）
- [x] **PCR-1: 親計画へ昇格済み（2026-06-27）。** 親計画 4.1「Swarm instance lifecycle」へ継承ベース分類基準（BaseManagerAgent 継承＝dispatch_scoped、plain SwarmManager 継承＝stateless_reusable候補）を統合。Phase 3/4/5/8 共通の分類軸として親計画へ昇格。
- [ ] **PCR-2: 親計画へは不採用（台帳是正へ差し戻し）。** SGK-2026-0311 の `task_ledger.md/.csv` が `active`＋非doneパス（実体は `done/`・`status: done`・registry も done）の不整合は、親計画の設計事項ではなく台帳データの是正であるため親計画へは入れない。SGK-2026-0311 の closeout 修正として `task_ledger.md:330` / `task_ledger.csv:322` の status=`active`→`done`・path→`done/` への修正を別途実施すること。
- [x] **PCR-3: 親計画へ昇格済み（2026-06-27）。** 親計画 4.4 Go条件「dispatch context isolation test」へ finding 帰属を `correlation_id`/`dispatch_id` で同定できる要件を統合。

### 6.9 Out of Scope（本Phaseでは実装しない）
- [ ] InjectionManager URL処理の並列化（Phase 8）
- [ ] SwarmManager specialist 内側並列化（Phase 8）
- [ ] SwarmDispatcher 複数Swarm同時呼び出し（Phase 8）
- [ ] protective degrade mode（Phase 7）
- [ ] lane scheduler / mutex（Phase 4）
- [ ] `TaskState` enum への `admitted` / `invalidated` 等の追加（Phase 1 で deferred 済み）
- [ ] 外部依存ライブラリの追加

### 6.10 Phase順序再レビュー
- **Phase 2 → Phase 3:** ✅ 対象ファイル群が別（Phase 2 は parallel_orchestrator/admission/budget/config、Phase 3 は swarm_dispatcher/managers）。Phase 2 の origin_key/admission は Phase 3 と責務境界が明確。順序正当。
- **Phase 3 → Phase 4:** ✅ Phase 4 shadow decision は Phase 3 の dispatch-scoped 分類を入力に取りうるが、Phase 4 は実行順を変えないため Phase 3 未完でも shadow 記録は可能。Phase 3 の stateful inventory は Phase 4 lane 分類の入力になる（PCR-1）。
- **Phase 3 → Phase 5:** ✅✅ **Phase 3 は Phase 5 Go の硬前提**（親計画 4.4「dispatch context isolation test」が Go 条件）。実並列化前に context 分離が未完だと同時dispatchで確実に汚染。順序は正しく、Phase 3 Blocker 解消が Phase 5 の鍵。
- **結論:** Phase 順序は壊れていない。実際の依存関係にも適合している。

### 6.11 実装可否判定（Blocker解消後）
- **判定: 実装可能（Go）— per-dispatch instance 決定により小規模・局所・低リスクに達成可能。**
- **変更規模（局所）:** `src/core/engine/swarm_dispatcher.py` のみ。
  - `_get_or_create_swarm()`（L93-136）: pool キャッシュ（`self._swarm_pool`）への格納を廃止し、dispatch ごとに新規 Swarm インスタンスを生成。shared service injection path（L111-132）はそのまま再利用し network/llm/event_bus/recipe/rag を注入。
  - dispatch 呼び出し経路（`dispatch` L243-270 / `_dispatch_to_single_swarm` L470-539 / `dispatch_to_all` L561-572）: `result = await swarm.dispatch(...)` を `try/finally` で囲み `await swarm.close()` を呼ぶ。
  - manager 内部・他ファイルは変更不要（`current_context`/`history` の既存 reset ロジックは per-dispatch instance でそのまま機能）。
- **安全性の根拠（実コード確認済み）:**
  - shared `network_client`/`llm_client` は `SwarmManager.close()`（base.py:244-253）が `_specialists` の close のみで client を閉じず、`Specialist.close()`（base.py:150-152）に「共有リソースのため close しない」と明記。per-dispatch instance で `close()` しても shared client は破壊されない。
  - InjectionManager の `_ephemeral_network_clients`（injection/manager.py:3381-3386）は per-manager 一時クライアントで `close()` で解放される → dispatch 後 close が正しく cleanup する。
  - 既存の `llm_for_dispatch = LLMClient(...)` 複製（base_manager.py:206-209）が per-dispatch オブジェクト生成の前例であり、パターンは確立済み。
- **TDD順序:** T-0.1 baseline 固定 → T-3.1（別インスタンス受領/no-leak）→ T-1.1（shared identity 保持）→ T-2.1〜T-2.5（分離検証）→ T-4.1/T-4.2（回帰）。
- **他フェーズへの影響:** なし。DispatchContext/ContextVar threading は Phase 8（SGK-2026-0317）が内側並列化評価時に所管、pool 再利用復活は Phase 5（SGK-2026-0314）が stateless 最適化として所管。本 Phase 3 の決定はこれらの計画書を編集せず、各 Phase の既存スコープ内に収まる。
- **残リスク（実装中に No-Go に戻す条件）:** Step 1 点検でクラス変数・module global・shared service 経由の隠れ mutable 状態が発見された場合、または specialist 再生成コストが許容を超え Phase 5 以前に pool 復活が必要になった場合は実装を止めて再評価する。
