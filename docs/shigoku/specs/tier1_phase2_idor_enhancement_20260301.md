---
task_id: SGK-2026-0162
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-03-01'
updated_at: '2026-05-19'
---

# Spec: Tier 1 (Phase 2) - `IdorHunterSpecialist` 強化 (HPP & 動的プロパティ抽出)

## 概要

SHIGOKU 実装ロードマップ「Tier 1: クイックウィン」の Phase 2 (IDOR 検知路線の完全体化) を実施する。
前フェーズで強化した `BodyMutator` を活用し、`IdorHunterSpecialist` に高度な攻撃ロジックを追加する。

1. **HPP (HTTP Parameter Pollution) 攻撃ロジックの実装**: リクエストパラメータの配列化や重複送出を自動で行い、サーバー側の権限チェックの不備を突く。
2. **動的なプロパティ候補抽出の高度化**: OpenAPI 定義の解析や、既存のレスポンス等のコンテキストから「未知の特権キー（admin, role, is_active 等）」を推測し、IDOR/BOLA テストの網羅性を向上させる。

## 変更範囲

- **`src/core/agents/swarm/logic/idor.py`** (クラス `IdorHunterSpecialist`)
  - `test_hpp` メソッドの完全実装。
  - プロパティ抽出ロジックの強化（OpenAPI クライアントまたは RAG コンテキストの活用）。
  - `BodyMutator` を用いた HPP ペイロードの生成と実行。
- **`src/core/agents/swarm/logic/body_mutator.py`**
  - 必要に応じて、HPP 向けのパラメータ複製ロジックの微調整。

## 挙動 (Input/Output)

### 1. HPP 攻撃ロジック

- **Input**: オリジナルの `Task` (Target URL, Tags, Params)。
- **処理**:
  - `BodyMutator.duplicate_param` を使用し、`id=123` を `id=123&id=456` や `id[]=123&id[]=456` に変異させる。
  - 第一パラメータと第二パラメータを入れ替える（User A's ID と User B's ID）等のバリエーションを生成。
  - レスポンスのステータスコードやボディを比較し、バイパスを検知する。
- **Output**: 成功したバイパスを `Finding` として報告。

### 2. 動的プロパティ抽出

- **Input**: ターゲットの URL または過去のレスポンスボディ。
- **処理**:
  - RAG または OpenAPI 定義（あれば）から、そのエンドポイントが受け入れ可能な隠しパラメータを紐解く。
  - `admin`, `internal_id`, `privilege`, `is_staff` などの典型的なキーをバイパス候補として `inject_properties` に渡す。
- **Output**: 権限昇格の兆候がある `Finding` を生成。

## 制約

1. **セマフォの遵守**
   - 強化された攻撃ロジックも、前フェーズで導入した `SwarmManager` のセマフォ制御下で実行されること。
2. **EthicsGuard の遵守**
   - パラメータの汚染（Pollution）が意図しない破壊的アクションを引き起こさないよう、`is_aggressive` フラグを適切に管理する。
