---
task_id: SGK-2026-0036
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# EthicsGuard

**現行モジュールパス**

- `src/core/security/ethics_guard.py`
- `src/core/security/enhanced_ethics_guard.py`

## 概要

EthicsGuard はスコープ制御と実行前チェックを行う安全レイヤーです。URL・アクション種別・ログ記録を基に許可判定を返します。

## 現行の主要構成

- `ActionType`
- `ActionResult`
- `ScopeDefinition`
- `ActionLog`
- `EthicsGuard`
- `get_ethics_guard()`
- `check_before_action()`

## 現行仕様

- 許可されたスコープかを判定する
- IDOR cross-test や batch utility からも再利用される
- `src/core/tools/context_runner.py` の実行ガードとして注入できる
- enhanced 版は別ファイルに分離されている

## 主な呼び出し元

- `src/core/security/idor_cross_tester.py`
- `src/core/utils/batch_utils.py`
- `src/core/tools/context_runner.py`

## 注意点

- 旧仕様書にあった長い YAML 例は現行の canonical 仕様ではない
- 実際の運用上は `RequestGuard` と併用されることが多い
