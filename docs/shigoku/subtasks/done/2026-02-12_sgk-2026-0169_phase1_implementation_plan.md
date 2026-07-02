---
task_id: SGK-2026-0169
doc_type: subtask_plan
status: backlog
parent_task_id: null
related_docs: []
created_at: '2026-02-12'
updated_at: '2026-07-02'
---

# IMPLEMANTATION PLAN: Phase 1 Refactor (Swarm & TargetAsset)

**Spec**: `docs/specs/2026-02-12_phase1_refactor.md`
**Date**: 2026-02-12

## 1. Core Domain Foundation

- [ ] **TargetAsset Implementation**
  - [ ] Create `src/core/domain/model/target.py`
    - [ ] Define `TargetType` Enum (WILDCARD_DOMAIN, SINGLE_URL_PUBLIC, etc.)
    - [ ] Define `TargetAsset` dataclass.
    - [ ] Implement `TargetAsset.create(input_str)` factory with `_classify`.
    - [ ] Implement helper `_is_internal(hostname)`.
  - [ ] **Test**: Create `tests/domain/test_target_asset.py` and pass all cases.

- [ ] **ScopeManager Integrated with TargetAsset**
  - [ ] Refactor `src/core/domain/scope/scope_manager.py`
    - [ ] Load `scope.txt`/`INPUT_TARGET` and convert each line to `TargetAsset`.
    - [ ] Apply exclude logic to `TargetAsset` list.

## 2. Worker Infrastructure

- [ ] **Base Worker Classes**
  - [ ] Create `src/core/swarm/worker/base.py` (Abstract BaseWorker).
  - [ ] Create `src/core/swarm/worker/procedural.py` (ProceduralWorker for subprocess).
    - [ ] Implement `run_command` with timeout and stdout capture.
  - [ ] Create `src/core/swarm/worker/llm_worker.py` (LLMWorker for reasoning).
  - [ ] **Test**: Create `tests/swarm/test_workers.py` to verify command execution.

## 3. Worker Migration (Iterative)

Migrate intelligence from independent agents to Swarm Workers.

- [ ] **InjectionSwarm Migration**
  - [ ] Create `src/core/swarm/injection/workers/taint_analysis.py` (Procedural) <- from `TaintAnalysisAgent`
  - [ ] Create `src/core/swarm/injection/workers/graphql.py` (Hybrid) <- from `GraphQLNavigator`

- [ ] **DiscoverySwarm Migration**
  - [ ] Create `src/core/swarm/discovery/workers/js_mine.py` (Procedural) <- from `JSMineAgent`
  - [ ] Create `src/core/swarm/discovery/workers/api_spec.py` (LLM) <- from `APISpecReconstructor`

- [ ] **InfrastructureSwarm (New)**
  - [ ] Create `src/core/swarm/infrastructure/workers/port_scan.py` (Procedural)
  - [ ] Create `src/core/swarm/infrastructure/workers/service_identify.py` (LLM)

- [ ] **Agents Cleanup**
  - [ ] Remove `src/agents/taint_analysis_agent.py` etc.
  - [ ] Remove `GeneralAgent`.

## 4. Master Conductor Integration

- [ ] **Dispatcher Refactor**
  - [ ] Modify `src/core/engine/action_dispatcher.py` to remove hardcoded agent dispatch.
  - [ ] Ensure all tasks route through `SwarmManager.assign_task()`.

## 5. Verification

- [ ] **E2E Test**
  - [ ] Run `python -m src.main --target example.com --dry-run`
  - [ ] Verify logs show correct Swarm/Worker initialization.
