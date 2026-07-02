---
task_id: SGK-2026-0312
doc_type: manual
status: done
parent_task_id: SGK-2026-0291
related_docs:
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-3-dispatch-context-isolation-swarm-pool_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-23_sgk-2026-0291_swarm-parallelism-review_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-0_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-1-additive-execution-contract-debug-metadata_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-2-scope-admission-per-origin-budget-policy_subtask_plan.md
title: 'SGK-2026-0312 Phase 3 実装指示書（dispatch context isolation / per-dispatch instance）'
created_at: '2026-06-27'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/core/engine/swarm_dispatcher.py
---

# SGK-2026-0312 Phase 3 実装指示書（担当者引き継ぎ用）

> 本ファイルは Phase 3（SGK-2026-0312）の**実行指示**です。計画書（`2026-06-26_swarm-phase-3-..._subtask_plan.md`）の Section 6.2 で **Ready** 判定済み。本指示は計画書の Section 4 / 6.4 / 6.5 / 6.11 を実務手順に展開したものです。判断の背景は計画書を参照してください。

## 0. 5秒で分かるあらすじ
- **やること（1つだけ）:** `SwarmDispatcher` が Swarm インスタンスを pool 再利用するのをやめ、**dispatch ごとに新規インスタンスを生成して dispatch 後に close する**。これで同時 dispatch で `current_context` / `history` / findings / url_results / auth_headers / cookies が混ざるのを構造的に防ぐ。
- **変更ファイル:** `src/core/engine/swarm_dispatcher.py` のみ（manager 内部・他ファイルは触らない）。
- **前提:** Phase 0/1/2 完了済み（origin_key / admission / budget は実装済み）。本 Phase は Phase 5（実並列化）の硬前提。
- **やってはいけない:** DispatchContext / ContextVar / compatibility shim の導入（→ Phase 8）、pool 再利用復活（→ Phase 5）、manager 内部変更、他 Phase 計画書の編集。

---

## 1. 目的と前提
- **目的:** 並列化（Phase 5）前に、Swarm pool 再利用と `BaseManagerAgent` 系 manager のインスタンス状態上書きによる同時 dispatch コンテキスト汚染を防ぐ。
- **決定済みメカニズム（変更不要）:** per-dispatch instance（pool 全廃止）。理由は計画書 6.2 / 6.11 参照。
- **前提確認（実施前に1回だけ）:**
  - `git status` がクリーンであること。
  - `.venv/bin/python -m pytest tests/unit/engine/test_swarm_dispatcher_close.py tests/core/agents/swarm/injection/test_process_url_dispatcher.py -q` が現状 GREEN であること（baseline）。

## 2. 実装しないこと（Out of Scope）
- [ ] DispatchContext / `contextvars.ContextVar` / compatibility shim の導入（Phase 8 SGK-2026-0317）
- [ ] pool 再利用復活・guarded reuse（Phase 5 SGK-2026-0314）
- [ ] SwarmManager specialist 内側並列化・Injection URL 並列化（Phase 8）
- [ ] manager 内部（base_manager.py / injection/manager.py / auth/manager.py / logic/manager.py）の改修。**現状の `self.current_context = {...}` reset ロジックは per-dispatch instance でそのまま機能するため触らない。**
- [ ] `config/shigoku.yaml` や `parallelism` 設定の変更（Phase 2 で枠は完成済み）。
- [ ] 親計画・他 Phase 計画書の編集。

---

## 3. 変更対象と変更内容（行番号は 2026-06-27 時点）

**変更ファイル:** `src/core/engine/swarm_dispatcher.py`（単一ファイル）

### 変更 A: `_get_or_create_swarm()` を per-dispatch 生成へ（L93-136）

**現状:** `self._swarm_pool`（L75）にキャッシュし、2回目以降は同じインスタンスを返す。
**変更:** キャッシュせず、呼び出しごとに新規インスタンスを生成して返す。shared service injection はそのまま。

変更後イメージ（既存構造・ logging・`requires_llm` チェックを維持）:
```python
def _get_or_create_swarm(self, swarm_name: str) -> Any:
    """Swarm Manager を新規生成（Phase 3: per-dispatch instance / pool 再利用廃止）。

    shared service (network/llm/event_bus/recipe/rag) を注入するが、インスタンスは
    キャッシュしない。呼び出し元は dispatch 後に try/finally で close() すること。
    """
    swarm = None
    swarm_classes = _get_swarm_classes()
    if swarm_name in swarm_classes:
        swarm_class = swarm_classes[swarm_name]
        requires_llm = swarm_name in ["injection", "auth", "logic", "secret", "intelligence"]
        if requires_llm and not self.llm_client:
            logger.warning(f"[_get_or_create_swarm] Skipping {swarm_name}: LLM client not available")
            return None
        swarm = swarm_class(self.config)

    if swarm:
        if self.network_client and hasattr(swarm, 'set_network_client'):
            swarm.set_network_client(self.network_client)
        if self.llm_client and hasattr(swarm, 'set_llm_client'):
            swarm.set_llm_client(self.llm_client)
        if self.loop and hasattr(swarm, 'set_event_loop'):
            swarm.set_event_loop(self.loop)
        if self.event_bus and hasattr(swarm, 'set_event_bus'):
            swarm.set_event_bus(self.event_bus)
        if hasattr(self, '_recipe_loader') and self._recipe_loader:
            swarm.set_recipe_loader(self._recipe_loader)
        if self._rag:
            swarm.set_rag(self._rag)
        # Phase 3: self._swarm_pool[swarm_name] = swarm は行わない（キャッシュ廃止）

    return swarm  # NOTE: 呼び出し元が try/finally で close() する
```
- 冒頭の `if swarm_name in self._swarm_pool: return self._swarm_pool[swarm_name]`（L95-96）を削除。
- 末尾の `self._swarm_pool[swarm_name] = swarm`（L134）を削除。
- `return self._swarm_pool.get(swarm_name)`（L136）を `return swarm` に変更。

### 変更 B: dispatch 経路3箇所に `try/finally close` を追加

`swarm.dispatch(...)` / `swarm.execute(...)` を呼ぶ3箇所で、生成したインスタンスを `finally` で close する。

#### B-1: `dispatch()` の for ループ内（L243-297 付近）
```python
for swarm_name in swarm_names:
    swarm = None
    try:
        swarm = self._get_or_create_swarm(swarm_name)
        # ... 既存の SwarmTask 構築 / ledger 記録 ...
        result = await swarm.dispatch(swarm_task)
        # ... 既存の結果集計 ...
    except Exception as e:
        logger.error("[SwarmDispatcher] Error dispatching to %s: %s", swarm_name, e)
        all_execution_logs.append({"swarm": swarm_name, "error": str(e)})
        statuses.append("failed")
        # ... 既存の ledger 記録 ...
    finally:
        if swarm is not None and hasattr(swarm, "close"):
            try:
                await swarm.close()
            except Exception as ce:
                logger.error("[SwarmDispatcher] Error closing swarm %s: %s", swarm_name, ce)
```
- 既存の `try/except`（L256-308）を `try/except/finally` に拡張。`swarm` 変数をループ先頭で `None` 初期化し、`_get_or_create_swarm` の戻り値を代入。

#### B-2: `_dispatch_to_single_swarm()`（L470-539 付近）
```python
swarm = None
try:
    swarm = self._get_or_create_swarm(swarm_name)
    if not swarm:
        swarm = swarm_class(self.config)
        if self.network_client and hasattr(swarm, 'set_network_client'):
            swarm.set_network_client(self.network_client)
    # ... 既存の task 構築 / ledger / result = await swarm.execute(task) ...
    return result
except Exception as e:
    # ... 既存 ...
    return SwarmResult(...)
finally:
    if swarm is not None and hasattr(swarm, "close"):
        try:
            await swarm.close()
        except Exception as ce:
            logger.error("[_dispatch_to_single_swarm] Error closing %s: %s", swarm_name, ce)
```
- 既存の `try/except`（L470-539）に `finally` を追加。**注意:** 既存の `finally: await self._aggressive_limiter.release(is_aggressive)`（L537-539）があるので、close 用の finally はネストまたは統合する。aggressive_limiter.release は維持すること。

#### B-3: `dispatch_to_all()`（L561-572 付近）
```python
for swarm_name in swarm_classes:
    swarm = None
    try:
        swarm = self._get_or_create_swarm(swarm_name)
        swarm_task = SwarmTask(...)
        result = await swarm.dispatch(swarm_task)
        results.append(result)
    except Exception as e:
        logger.error(f"[SwarmDispatcher] Error in {swarm_name}: {e}")
    finally:
        if swarm is not None and hasattr(swarm, "close"):
            try:
                await swarm.close()
            except Exception as ce:
                logger.error("[dispatch_to_all] Error closing %s: %s", swarm_name, ce)
```

### 変更不要（確認だけ）
- `_swarm_pool` 属性（L75）は残してよい（空のままで OK）。`set_recipe_loader`（L81-85）/ `set_rag`（L87-91）/ `close()`（L181-201）は `self._swarm_pool.values()` を iterate するが、空でも安全。**念のため `rg "_swarm_pool" src/` で全参照を確認し、空でも壊れないことを担保すること。**
- `close()`（L181-201）は pool が空でも singleton reset が働くため変更不要。

---

## 4. 実装順序（TDD・この順序を守る）

1. **baseline 固定（コード変更前）:** テスト T-0.1 を追加して現行 serial dispatch の findings 結果を固定する。この時点で GREEN を確認。
2. **変更 A 実装:** `_get_or_create_swarm()` を per-dispatch 生成へ。この時点で既存テストが通るか確認（serial なら per-dispatch でも結果は同じはず）。
3. **変更 B 実装:** 3 dispatch 経路に `try/finally close` を追加。
4. **T-3.1 追加:** per-dispatch で別インスタンスが返ること / no-leak を検証。
5. **T-1.1 追加:** shared service identity が保持されることを検証。
6. **T-2.1〜T-2.5 追加:** 同時 dispatch 分離検証（forced interleaving）。
7. **T-4.1 / T-4.2:** 既存回帰テストを走らせ GREEN 確認。
8. **隠れ状態点検（計画書 Step 1）:** `rg "self\._shared|^[A-Z_]+ = |class " src/core/agents/swarm/` 等でクラス変数・module global の mutable 状態がないか確認。発見したら **即停止・報告**（No-Go 条件）。

## 5. テスト実装（骨組み）

テストは `tests/unit/engine/` 配下に新規ファイル（例: `test_swarm_dispatcher_per_dispatch_isolation.py`）で追加。既存 `tests/unit/engine/test_swarm_dispatcher_close.py` の fixture 利用を前提。

### T-0.1 baseline（変更前）
```python
async def test_serial_dispatch_baseline_findings_fixed():
    # 現行 serial dispatch で既知の minimal タスクを走らせ、findings 結果を固定。
    # 変更 A/B 適用後も同一結果になることを回帰で使う。
    ...
```

### T-3.1 per-dispatch 別インスタンス / no-leak
```python
async def test_get_or_create_swarm_returns_distinct_instance_per_call():
    dispatcher = SwarmDispatcher(config={}, llm_client=object(), network_client=object())
    a = dispatcher._get_or_create_swarm("scanner")
    b = dispatcher._get_or_create_swarm("scanner")
    assert a is not b                      # pool キャッシュ廃止
    assert dispatcher._swarm_pool == {}    # pool に溜まらない

async def test_no_ephemeral_resource_leak_after_close():
    # InjectionManager 等 _ephemeral_network_clients を持つ manager を
    # dispatch → close し、一時クライアントが全解放されることを検証。
    ...
```

### T-1.1 shared service identity
```python
async def test_shared_services_preserved_across_instances():
    net, llm, eb = object(), object(), object()
    dispatcher = SwarmDispatcher(config={}, llm_client=llm, network_client=net, event_bus=eb)
    a = dispatcher._get_or_create_swarm("scanner")
    b = dispatcher._get_or_create_swarm("scanner")
    assert a.network_client is net and b.network_client is net   # 同一 shared client
    assert a.llm_client is llm and b.llm_client is llm
```

### T-2.1 同時 dispatch 分離（findings / history）
- 方針: `BaseManagerAgent` は LLM think loop を回すため、テスト用に **stub LLM** を注入し、1ターン目に `report_finding(marker=A/B)` する action を返すよう固定する。`asyncio.gather(dispatch(A), dispatch(B))` を走らせ、**汚染窓でバリアを挟んで強制 interleave** した上で、各結果が自分の marker だけを持つことを検証。
- LLM stub の既存パターンは `tests/e2e/test_swarm_llm.py` / `tests/core/agents/swarm/injection/test_process_url_dispatcher.py` を参考にする。
- history 交錯（T-2.4）は stub LLM が複数ターン返すよう固定し、dispatch A の history に B のターンが混入しないことを検証。
```python
async def test_concurrent_dispatch_findings_isolation():
    # markerA / markerB を持つ2 task を gather 同時 dispatch。
    # 各 result.findings が自分の marker のみ含むことを検証。
    ...

async def test_concurrent_dispatch_history_isolation():
    # 2 dispatch の LLM history ターンが交錯しないことを検証。
    ...
```
- `auth_headers` / `cookies` / `url_results` も同様に、dispatch A/B に異なる値を与えて交叉流入がないことを検証（T-2.2 / T-2.3）。
- **決定性:** 素朴な `gather` は偶然の interleaving 依存になるため、必ずバリア（`asyncio.Event` 等で片方の dispatch を汚染窓で待機させる）を挟むこと。

### T-2.5 例外時 close
```python
async def test_per_dispatch_instance_closed_on_exception():
    # dispatch 内で例外を発生させ、finally で swarm.close() が呼ばれ、
    # かつ shared network_client が閉じられないことを検証。
    ...
```

---

## 6. 完了条件（Go Gate・全てチェック）
- [ ] `_get_or_create_swarm` が dispatch ごとに別インスタンスを返す（pool キャッシュ廃止: T-3.1）。
- [ ] 同一 Swarm 型への2同時 dispatch で findings / auth_headers / cookies / url_results / history が混ざらない（T-2.1〜T-2.4）。
- [ ] shared service（network/llm/event_bus）の object identity が dispatch 間で保持される（T-1.1）。
- [ ] dispatch 例外時に per-dispatch instance が close され、shared client は閉じない・一時リソース leak なし（T-2.5 / T-3.1）。
- [ ] 既存 serial 実行が従来互換（T-0.1 baseline 一致 + T-4.1 / T-4.2 GREEN）。
- [ ] 隠れ共有状態（クラス変数・module global・shared service 経由 mutable cache）が点検で発見されない。

## 7. 検証コマンド（完了時に実行）
```bash
# 対象テスト
.venv/bin/python -m pytest tests/unit/engine/test_swarm_dispatcher_close.py \
  tests/unit/engine/test_swarm_dispatcher_per_dispatch_isolation.py \
  tests/core/agents/swarm/injection/test_process_url_dispatcher.py -q

# 広めの回帰（Swarm 周り）
.venv/bin/python -m pytest tests/unit/engine/ tests/core/agents/swarm/ tests/core/engine/ -q

# ドキュメント検証（最後に必須・AGENTS.md §9/§15）
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py   # 0 エラーであること
```

## 8. 引き継ぎ後の報告手順（AGENTS.md §15 準拠）
1. `docs/shigoku/reports/2026-MM-DD_sgk-2026-0312_work_report.md`（doc_type: work_report）を作成。`deferred_tasks` があれば実タスクID紐付けで記載（Phase 5/8 送り分け）。
2. `docs/shigoku/worklogs/2026-MM-DD_sgk-2026-0312_work_log.md`（doc_type: work_log）を作成。
3. `docs/shigoku/registry/task_registry.yaml` で SGK-2026-0312 の `status` を `done` に更新。
4. `docs/shigoku/registry/task_ledger.md` / `task_ledger.csv` で SGK-2026-0312 を `done` に更新。
5. 計画書 `2026-06-26_swarm-phase-3-..._subtask_plan.md` の front matter `status` を `done` にし、`docs/shigoku/subtasks/done/` へ移動。移動後、`related_docs` のパスを全程更新（AGENTS.md §14 / shigoku-docs.md）。
6. `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py` が 0 エラーであることを確認。

## 9. エスカレーション（即停止・報告条件）
以下の場合は実装を止めて計画書 6.11 の No-Go 条件として記録し、レビュアーに戻す:
- 変更 A/B 後に既存 serial テストが RED になる（serial 互換破壊）。
- Step 8 の点検でクラス変数・module global・shared service 経由の隠れ mutable 状態を発見した（per-dispatch instance では隔離できない汚染経路）。
- `close()` で shared client が閉じられて後続 dispatch が壊れる（base.py:150-152/244-253 の「共有 client は close しない」前提が崩れた）。
- specialist 再生成コストが大きく、Phase 5 以前の pool 復活が必要と判明した。

## 10. 参照ルール（本作業で遵守した AGENTS.md §17 ルールファイル）
- `rules/lessons.md`（共有表面破壊 CAUTION・docs validation・deferred_tasks 実ID紐付け・`.venv/bin/python` 使用）
- `rules/shigoku-docs.md`（Front Matter 必須・done/ 移動時の related_docs 更新）
- `rules/task-ledger.md`（報告手順 §15）
- 実装時は更に `rules/codingrules.md` / `rules/python-tests.md` を参照すること。
