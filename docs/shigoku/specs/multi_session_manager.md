---
task_id: SGK-2026-0137
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Feature Specification: Tier 3 IDOR 完全体 (MultiSessionManager & OpenAPI Privilege Guesser)

## 概要 (Overview)

SHIGOKUのIDOR/BOLA（Broken Object Level Authorization）検出能力を根本的に強化するため、同一ターゲットに対する複数ユーザー（Admin, UserA, UserB, Unauthenticated など）のセッションやプロファイルを統合管理する `MultiSessionManager` を新設します。さらに、OpenAPI定義等から特権パラメータを動的に抽出し、高度な権限昇格テストを行うエンジンを追加します。

## 変更範囲 (Scope)

- **[NEW]** `src/core/session/multi_session_manager.py`: 複数ロールのセッション（ヘッダー/Cookie等）を管理・提供するマネージャクラス。
- **[MODIFY]** `src/core/agents/swarm/logic/idor.py`: `MultiSessionManager` を用いて、`_test_cross_session_access` に対して自動的に `alt_sessions` を生成し渡すように修正。
- **[MODIFY]** `src/core/attack/openapi_tester.py` (または同等の新規抽出モジュール): OpenAPIやベースラインリクエストから `is_admin`, `role` などの特権プロパティを動的に抽出するロジックの実装。
- **[NEW]** `tests/unit/core/session/test_multi_session_manager.py`: 新マネージャのユニットテスト。

## 挙動 (Behavior)

### 1. MultiSessionManager の責務

既存の `SessionManager` はハンティング完了状態などの「長期間状態の永続化」を担当していますが、`MultiSessionManager` は **「通信時の認証状態（複数プロファイル）」** に特化します。

- `add_session(role: str, headers: dict)`: "Admin", "UserB" などのロールごとにHTTPヘッダーや認証情報を登録・保持。
- `get_session(role: str) -> dict`: 指定ロールのヘッダー情報を取得。
- `get_all_alternative_sessions(exclude_role: str) -> dict`: 現在のロール以外の全セッション（検証用マトリクス）を取得。

### 2. IdorHunterSpecialist 側の自動化

- 現在は `params.get("alternative_sessions")` で外部からベタ書きされたプロファイルを渡す必要がありますが、これを `MultiSessionManager` から自動取得するように変更します。これにより、完全自動で BOLA Matrix Testing が実行可能になります。

### 3. OpenAPI / Baseline 特権抽出エンジン

- スキーマ定義やベースラインのGETレスポンスを解析し、「自分にはないが他のロールには存在するプロパティ」や「Admin権限を示唆するキー（`is_admin`, `role`, `permission` 等）」を自動抽出します。
- これらを `BodyMutator` を通じて `_test_mass_assignment` 等のペイロードに自動注入します。

## 制約 (Constraints)

1. **EthicsGuard 連携**: 各セッション（特に別ユーザーのセッション）を用いる際は、引き続き `EthicsGuard` および `safe_mode` のルールに従い、破壊的変更（POST/PUT/DELETE）には注意を払います（GET中心の検証へのフォールバック等）。
2. **既存 `SessionManager` との分離**: `SessionManager` (ハンティング状態管理) と `MultiSessionManager` (通信認証情報管理) の関心事を明確に分離し、過度な結合を避けます。

## 検証計画 (Verification)

1. **Pytest (Unit Testing)**: `test_multi_session_manager.py` にて、セッションの登録・取得・除外取得ロジックが正しく機能するかテスト。
2. **Integration / E2E**: IDORテストにおいて、自セッション (`UserA`) と代替セッション (`Admin` や `UserB`) を用いたクロスセッション検証が自動発火し、`EventBus` や `LearningRepository` と連動して Finding を正しく生成することを確認。
