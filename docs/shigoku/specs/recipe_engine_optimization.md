---
task_id: SGK-2026-0156
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs:
  - docs/shigoku/subtasks/2026-06-03_recipe-auth-jwt-oauth_subtask_plan.md
created_at: '2026-05-19'
updated_at: '2026-06-18'
---

# Specification: Recipe Execution Engine Optimization

## 1. 目的

SHIGOKUのレシピ実行エンジンを、従来の逐次実行から、依存関係を考慮した非同期並列実行（DAGベース）へとアップグレードする。これにより、診断時間の短縮とリソース利用の効率化を図る。

## 2. 実装詳細

### 2.1 データモデルの変更

`src/core/engine/recipe_loader.py` 内の `RecipeStep` を以下のように拡張する：

```python
@dataclass
class RecipeStep:
    id: str  # 一意なID
    name: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)  # 依存するステップのID
```

### 2.2 グラフ解析ロジック

`networkx.DiGraph` を使用する。

1. 各 `RecipeStep` をノードとして追加。
2. `dependencies` に基づいてエッジを追加。
3. `networkx.is_directed_acyclic_graph()` で循環参照がないかチェック。
4. `networkx.topological_sort()` または `lexicographical_topological_sort` でトポロジカル順序を取得。

### 2.3 並列実行アルゴリズム

`asyncio.Semaphore(max_workers)` を使用して同時実行数を制御しつつ、準備ができたタスク（依存関係が解消されたタスク）から順次実行を開始する。

### 2.4 キャッシュ機構

- 実行中の `Runner` インスタンス内に `_tool_cache` を保持。
- キー: `f"{target}:{step.id}:{action}:{hash(json.dumps(params))}"`
- 同一セッション内でのみ有効とする。

## 3. Stage-Aware Execution (SGK-2026-0259)

### 3.1 概要

Recipe に `stages` が定義されている場合、`probe -> confirm -> evidence` の3段階実行を採用する。
各段階は、前段階が `min_success` 閾値を満たした場合のみ実行される。
全件実行ではなく、シグナルが揃った高価値Recipeのみを注入・実行する。

### 3.2 Recipe Schema 拡張

Recipe YAML に以下のフィールドを追加：

- `trigger.required_signals`: 必須シグナル（ALL match）
- `trigger.optional_signals`: 加点シグナル（スコアリングに使用）
- `stages[]`: 実行段階定義（probe/confirm/evidence の3段固定）
- `success_signals[]`: 成功判定シグナル
- `failure_signals[]`: 失敗判定シグナル
- `stop_conditions[]`: 即時停止条件（rate_limit, waf_block 等）
- `evidence_policy`: エビデンス収集ポリシー（max_items, redact_secrets）

### 3.3 Score-Based Matching

`match_recipes_to_context()` はシグナルベースのスコアリングで上位N件のみを返す：

```python
score = BASE_MATCH_SCORE(10) + optional_signal_matches(1pt each) + priority_bonus
```

### 3.4 Verdict Classification

エビデンスの密度・信頼性に基づき verdict を分類：
- `confirmed`: 複数の高信頼度・再現性あるエビデンス
- `draft`: 弱いシグナルのみ
- `no_signal`: 意味のあるエビデンスなし
- `inconclusive`: 混合または曖昧なシグナル

### 3.5 単一セッション高額検出ユースケース

Recipe は特に以下の認証不備検出に最適化されている：

1. **OAuth Binding Drift**: state/nonce/redirect バインディング破綻
2. **Session Invariant**: ログイン・リフレッシュ前後の token/capability/role 不整合
3. **JWT Claim Enforcement**: aud/iss/nbf/typ/kid 検証漏れ
4. **Refresh Rotation**: 旧token継続利用・scope drift・revocation 不備
5. **Hidden Admin Capability**: 同一セッションで UI 非表示だが直接アクセス可能な管理API

## 4. 制約事項

- `EthicsGuard` によるスコープチェックは、各ステップの実行直前に必ず行うこと。
- レート制限 (`AdaptiveRateLimiter`) を遵守すること。
- Blind 依存、OOB 依存、複数アカウント前提の Recipe は本スコープ外。
- Recipe の trigger は deterministic に評価し、曖昧な LLM 判定単独では発火させない。
