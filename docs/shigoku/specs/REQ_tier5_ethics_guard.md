---
task_id: SGK-2026-0097
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Tier 5: EthicsGuard 強化仕様書 (REQ_tier5_ethics_guard)

## 概要

ロードマップの Tier 5 に基づき、SHIGOKU の安全装置である `EthicsGuard` を強化します。
続く Tier 6 で導入される高度な攻撃（JWT Swap, Chain Attack など）を実行する際、意図せぬシステム破壊や許可されていないスコープへの攻撃を防ぐため、実行前の「ユーザー承認フロー（HITL: Human-in-the-Loop）」と、「複数ホストを横断するリクエストの厳格なスコープ検証」を実装します。

## 変更範囲

- `src/core/security/ethics_guard.py` [MODIFY]:
  - `ActionType` に高リスクアクションを追加
  - 承認要求ステータス (`ActionResult.REQUIRES_APPROVAL`) の追加
  - リアルタイムスコープ検証ロジックの強化
- `src/interactive_bridge.py` [MODIFY/NEW]:
  - ユーザーへのインタラクティブな承認プロンプト（`Y/n` 入力待ち）機能の実装（SHIGOKUアーキテクチャに準拠）
- `tests/unit/core/security/test_ethics_guard_enhanced.py` [NEW]:
  - 追加ロジック（承認フロー、厳格なスコープ判定）のテスト

## 挙動 (Input / Output)

### 1. 破壊的テスト承認フロー (Human-in-the-Loop)

- **Input**: エージェントが破壊的な操作や高リスク・エクスプロイト（データベースの更新、特権昇格を伴うトークン入れ替えなど）を試みる。
- **処理**: `EthicsGuard` のルーターまたはエージェント呼び出し元で、対象アクションの高リスク度を判定。リスクが高い場合は `InteractiveBridge` 経由でユーザーに警告文と承認プロンプトを提示する。
- **Output**: ユーザーが `Y` (許可) を選択した場合は実行を継続し、`n` (拒否) またはタイムアウトした場合は `ActionResult.BLOCKED` となり安全に処理を中断する。

### 2. リアルタイムスコープ検証の強化

- **Input**: リダイレクト先URLのチェックや、SSRFによるサーバーサイドリクエスト先など、間接的・多段的なリクエスト。
- **処理**: リクエストの連鎖においても `EthicsGuard` がすべてのホストに対してチェックを実施。必要であれば `strict_mode` フラグを設け、サブドメインすら許可しない完全一致検証をサポートする。
- **Output**: 設定された「In-Scope」外へ1歩でも踏み出したリクエストは即座に `BLOCKED` とする。

## 制約

- `safety-first.md` ポリシーに従い、`EthicsGuard` は**いかなる場合もバイパス不可能**な堅牢な設計を維持する。
- 自動化の妨げにならないよう、承認プロンプトが発生する対象は「明らかな状態変更や深刻なエクスプロイト操作」に厳選する。（Reconや自動Fuzzingで都度止まらないようにする）
- アーキテクチャルールに基づき、エージェントが直接 `input()` を呼ぶのではなく、必ず `InteractiveBridge`（インタラクティブ層）を介してやり取りを行う。
