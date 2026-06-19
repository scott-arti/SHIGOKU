---
task_id: SGK-2026-0075
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-01-26'
updated_at: '2026-05-19'
---

# Phase 1.3 & 1.4: Infrastructure Integration Specification

## 概要

Phase 3 で追加された各種 Specialist に対し、Shigoku のコアセキュリティ基盤（Proxy Chain, Guardrails）を適用し、安全かつ匿名性の高い実行環境を確立する。

## Roadmap

- **Target**: Phase 1.3 (Proxy Chain), Phase 1.4 (Guardrails)
- **Priority**: Critical (These must be integrated before running real attacks)

---

## 1. Phase 1.3: Proxy Chain Integration

**目的**: 全ての HTTP リクエストを `AsyncNetworkClient` 経由にし、プロキシローテーションと一元的なリトライ制御を適用する。
**仕様変更**: ユーザー要請により、プロキシ利用は **Opt-in（デフォルトOFF）** とする。

### 変更対象

- **Target File**: `src/core/agents/swarm/injection/llm_specialists.py`, `src/core/infra/network_client.py`
- **Dependency**: `src/core/infra/proxy_manager.py`

### 実装詳細

1. **Network Client 改修**:
   - `AsyncNetworkClient` の `__init__` または `request` メソッドでのプロキシ利用デフォルト値を `False` にする。
   - `target_info` や `mode` を参照し、`mode == 'ctf'` の場合は強制的に `use_proxy=False` とするロジックを追加（または呼び出し側で制御）。

2. **Specialist Integration**:
   - `LLMBasedSpecialist` 等で `AsyncNetworkClient` を生成する際、Config (`use_proxy`) を参照するようにする。
   - デフォルトは `use_proxy=False`。
   - `Task.params` に `use_proxy=True` が含まれている場合のみ有効化。

---

## 2. Phase 1.4: Guardrails Integration

**目的**: 全ての Specialist の実行前に入力値（Task parameters）を検査し、Prompt Injection や危険なコマンドインジェクションを未然に防ぐ。
**現状**: `EthicsGuard` は各 Specialist に実装されているが、`Input/Output Guardrail` は未実装のため、今回の作業で実装・適用する。

### 変更対象

- **New File**: `src/core/security/middleware.py`
- **Target File**: `src/core/agents/swarm/base.py`

### 実装詳細

1. **Middleware 作成**:
   - `src/core/security/middleware.py` を作成。
   - デコレータ `@with_input_guard` を実装。
   - `src/core/security/guardrails.py` の `InputGuardrail.check()` を呼び出し、違反時は `SecurityError` を発生させる。

2. **Base Integration**:
   - `src/core/agents/swarm/base.py` の `Specialist.execute` メソッド（またはラッパー）に `@with_input_guard` を適用。
   - これにより、既存・および将来追加される全ての Specialist が自動的に保護される。

---

## Verification Plan

### Automated Tests

```bash
# Test Proxy Integration (Default OFF check)
pytest tests/unit/agents/swarm/test_llm_specialists_proxy.py

# Test Guardrails
pytest tests/unit/security/test_middleware.py
```

### Manual Verification

1. **Proxy**:
   - 通常実行時: プロキシが使われないことをログで確認。
   - オプション指定時 (`--use-proxy`): プロキシが使われることを確認。
   - CTFモード: オプション指定があっても強制OFFになることを確認。
2. **Guardrails**: `task.params` に `Ignore previous instructions` 等を含め、実行がブロックされることを確認。
