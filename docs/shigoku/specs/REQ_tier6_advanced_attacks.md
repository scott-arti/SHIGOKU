---
task_id: SGK-2026-0098
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# REQ: Tier 6 高度攻撃能力 (Advanced Attacks)

## 1. 概要 (Overview)

SHIGOKU ロードマップ「Tier 6: 高度攻撃能力」の実装仕様です。
本フェーズでは、これまでに構築された基盤（KB, LearningRepository, EthicsGuard等）をフル活用し、単一のリクエストでは発見が困難な「脆弱性連鎖（Attack Chain）」や「複雑な承認/ビジネスロジックの不備」を動的に検出する能力を実装します。

## 2. 実装対象スコープ (Scope)

以下の4つの主要コンポーネントを実装・強化します。

1. **Attack Chain Builder (攻撃チェーン生成)**
   - 複数の些細な脆弱性や情報漏洩を繋ぎ合わせ、深刻なエクスプロイトシナリオを生成・実行するコンポーネント。
   - 実装パス: `src/core/attack/chain_builder.py` (新規)

2. **AuthNinja 権限昇格テスト強化 (JWT swap / OAuth 不備)**
   - JWTヘッダー/ペイロードの改ざん（`none` アルゴリズム、鍵の混同など）や、OAuthフロー（`state`欠如、リダイレクトURI検証不備など）のテスト強化。
   - 実装パス: `src/core/agents/swarm/auth_ninja.py` (拡張)
   - 実装パス: `src/core/attack/jwt_tester.py` (新規)

3. **BizLogicHunter ビジネスロジック脆弱性強化**
   - 決済フロー、ステートマシンの順序バイパス、競合状態 (Race Condition - Tier 1からさらに高度化) などの検証ロジック。
   - 実装パス: `src/core/agents/swarm/biz_logic_hunter.py` (拡張)

4. **Playwright ベース IDOR・ロジック検証**
   - DOMベースの操作が必要なフロントエンド連携のIDORとビジネスロジックの検証。(これまでのAPIベース検証に加え、SPA/フロントエンドでの見え方を検証)
   - 実装パス: `src/tools/browser/playwright_validator.py` (既に存在する機能を活用し、IDOR連携を強化)

## 3. 期待される挙動 (Behavior)

### Attack Chain Builder

- **Input**: `KnowledgeBase` に蓄積された複数エンドポイントの情報や、微細な Finding のリスト。
- **Output**: 脆弱性を連鎖させた `ExploitChain` オブジェクトと、それを実証した複合的な `Finding`。

### AuthNinja 拡張 (JWT)

- **Input**: キャプチャされた JWT トークン。
- **Output**: 署名アルゴリズムのダウングレードや改ざんペイロードを用いたリクエスト実行。成功時に `Finding` 生成。対象APIをEthicsGuardで事前チェックし、高リスクの場合は `REQUIRES_APPROVAL` として扱う。

### BizLogicHunter 拡張 (State Machine)

- **Input**: マルチステップのAPIシーケンス（例: 1.カート追加 -> 2.決済 -> 3.完了）。
- **Output**: アクションの順序入れ替え（例: 1 -> 3）による状態検証。

## 4. 制約事項 (Constraints)

- **EthicsGuard徹底**: Tier 5で実装された `REQUIRES_APPROVAL` ステータスを積極的に活用する。特に 攻撃チェーンの実行時や、複数システムをまたぐOAuthなどの認可操作、リソースに対するWrite操作が含まれる場合、必ず `InteractiveBridge` を経由して実行の承認を得る。
- **Core (共通部分) → Edge (末端) の順序**: `ChainBuilder` や `JWTTester` などのコアロジックを先に作成したのち、Agent（Ninja, Hunter）でそれを組み込む順序で実装する。

## 5. 影響を受けるファイル

- **[NEW]** `src/core/attack/chain_builder.py`
- **[NEW]** `src/core/attack/jwt_tester.py`
- **[NEW]** `tests/unit/attack/test_chain_builder.py`
- **[NEW]** `tests/unit/attack/test_jwt_tester.py`
- **[MODIFY]** `src/core/agents/swarm/auth_ninja.py`
- **[MODIFY]** `src/core/agents/swarm/biz_logic_hunter.py`
- **[MODIFY]** `src/tools/browser/playwright_validator.py`
