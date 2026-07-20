---
task_id: SGK-2026-0349
doc_type: plan
status: done
parent_task_id: null
related_docs:
  - config/shigoku.yaml
  - src/core/models/llm.py
  - src/core/config/llm_resolver.py
  - src/core/engine/master_conductor.py
  - src/main.py
  - src/core/agents/specialized/scope_parser.py
  - src/core/agents/swarm/injection/smart_xss.py
  - docker-compose.yml
  - src/config.py
  - src/core/config/settings.py
created_at: 2026-07-10
updated_at: '2026-07-21'
---

# SGK-2026-0349: MasterConductor Model Fix & Hardcoded Elimination

## 1. 背景と目的

### 1.1 問題概要

SHIGOKU の LLM 設定は `config/shigoku.yaml` の `llm` セクションに一元化されている（AGENTS.md ルール18）。しかし、実コードの複数箇所でハードコードされたモデル名や非推奨フラット config が残存しており、以下の問題を引き起こしている:

1. **MasterConductor のモデル誤割当**: 設計上は `planner` role（reasoning_api = deepseek-v4-pro）を使うべきだが、全 main.py パスで `LLMClient(role="specialist_light")`（cheap_api = deepseek-v4-flash）が渡されている。最も戦略的な意思決定を行うコンポーネントが、意図より弱いモデルで動いている。
2. **`deepseek/deepseek-chat` ハードコード**: このレガシーモデルIDは **2026-07-24 15:59 UTC に完全廃止**される。現在は v4-flash にルーティングされているが、廃止後は動作しない。
3. **OpenAI モデルのハードコード**: `smart_xss.py` が `openai/gpt-4o-mini` / `openai/gpt-4o` を直接指定しており、role system をバイパスしている。
4. **`model="default"` の不透明な解決**: `auth_ninja.py` / `biz_logic_hunter.py` が `model="default"` を指定しており、実際の解決先が不明。

### 1.2 影響範囲

- **切迫度**: `deepseek-chat` 廃止まで残り14日（2026-07-24）
- **品質影響**: MasterConductor が弱いモデルを使用 → 動的リプランの品質低下 → 脆弱性発見率の低下
- **コスト影響**: XSS 再判定に OpenAI モデルをハードコード → 予期せぬコスト発生

### 1.3 目標

1. MasterConductor が設計通りの `planner` role（deepseek-v4-pro）を使用するように修正する
2. 全ハードコードモデル参照を role-based config 経由に移行する
3. `deepseek-chat` への参照を完全に排除する
4. 非推奨フラット config フィールドを移行する

---

## 2. 現状調査: 全ハードコード参照一覧

### 2.1 LLMClient フォールバック (llm.py:88)

```python
# 現状: role も model も未指定の場合のフォールバック
self.model = os.getenv("SHIGOKU_MODEL") or "deepseek/deepseek-chat"
```

**問題**: `deepseek-chat` が最終フォールバック。`SHIGOKU_MODEL` env も非推奨。

**修正方針**: `LLMRoleResolver` 経由で `default_role`（specialist_light → cheap_api → v4-flash）にフォールバックする。`SHIGOKU_MODEL` env は非推奨マークの上、段階廃止。

### 2.2 MasterConductor の llm_client (main.py)

```python
# main.py:3187, 3345, 4020, 4126, 4220 — 全パスで specialist_light
llm_client = LLMClient(role="specialist_light")
mc = MasterConductor(llm_client=llm_client)
```

**問題**: 5箇所すべてで `specialist_light`（v4-flash）を使用。`planner` role（v4-pro）が config に定義されているのに使われていない。

**修正方針**: 全箇所を `LLMClient(role="planner")` に変更。

### 2.3 scope_parser.py:48 — レガシーフォールバック

```python
# config 未渡し時のフォールバック
model="deepseek/deepseek-chat",
```

**問題**: `deepseek-chat` 直書き。`lessons.md` 行34の「model= を渡すと role が無視される」問題の典型例。

**修正方針**: `model=` を削除し、role-based にする。新規 role `scope_parser` を追加するか、既存 role を利用。

### 2.4 smart_xss.py:113, 117-121 — env + OpenAI ハードコード

```python
# 113: env var fallback
model = os.getenv("SHIGOKU_MODEL") or "deepseek/deepseek-chat"

# 117-121: OpenAI モデル直書き
rejudge_model = getattr(settings, "llm_xss_rejudge_model", "openai/gpt-4o-mini")
final_model = getattr(settings, "llm_xss_final_model", "openai/gpt-4o")
```

**問題**: 3つのモデルがハードコード/env 経由。role system を完全バイパス。

**修正方針**:
- `primary_model`: 既存の `self.llm = LLMClient(role="xss_specialist")` を使う（131行目で既に role-based client を作成しているので、`self.primary_model` は参照専用に残すか削除）
- `rejudge_model` / `final_model`: 新規 role `xss_rejudge` / `xss_final` を config に追加し、role-based に移行

### 2.5 docker-compose.yml:25-27 — 非推奨 env defaults

```yaml
# [DEPRECATED Phase 4] とマーク済みだが、デフォルト値が deepseek-chat
- SHIGOKU_MODEL=${SHIGOKU_MODEL:-deepseek/deepseek-chat}
- SHIGOKU_MODEL_OUTPUT=${SHIGOKU_MODEL_OUTPUT:-deepseek/deepseek-chat}
- SHIGOKU_MODEL_LIGHTWEIGHT=${SHIGOKU_MODEL_LIGHTWEIGHT:-deepseek/deepseek-chat}
```

**問題**: デフォルト値が `deepseek-chat`。

**修正方針**: `llm_resolver.py:182` のコメント「Legacy env vars SHIGOKU_MODEL_OUTPUT / SHIGOKU_MODEL_LIGHTWEIGHT are no longer supported」に従い、これらの env 行を削除するか、デフォルト値を `deepseek/deepseek-v4-flash` に更新。

### 2.6 フラット config (config.py:164-165, settings.py:404-405)

```python
# config.py と settings.py の両方に存在（重複）
llm_xss_rejudge_model: str = "openai/gpt-4o-mini"
llm_xss_final_model: str = "openai/gpt-4o"
```

**問題**: AGENTS.md ルール18 で非推奨化されたフラット config が残存。

**修正方針**: `smart_xss.py` を role-based に移行した後、これらのフィールドを `[DEPRECATED]` マーク → 段階削除。`getattr` コンシューマを `rg` で確認してから削除。

### 2.7 auth_ninja.py / biz_logic_hunter.py — model="default"

```python
# auth_ninja.py: 5箇所, biz_logic_hunter.py: 1箇所
model="default",
```

**問題**: `"default"` という文字列が LLMClient に渡される。`llm.py:82-83` では `if model:` が真になるため、`self.model = "default"` となり、API 呼び出しで `"default"` という存在しないモデル名が使われる可能性がある。

**修正方針**: `model="default"` を削除し、role-based に移行。`auth_ninja` は `swarm_manager` role、`biz_logic_hunter` は `specialist_light` または専用 role。

---

## 3. 修正計画

### Phase 1: config/shigoku.yaml の拡充 (P0)

新規 role を追加し、XSS 再判定/最終判定を role-based にする:

```yaml
# config/shigoku.yaml の llm.roles に追加:
xss_rejudge:
  profile: cheap_api
  fallback_profile: reasoning_api
  system_prompt_template: roles/xss_specialist.md  # 再利用
xss_final:
  profile: reasoning_api
  fallback_profile: cheap_api
  system_prompt_template: roles/xss_specialist.md  # 再利用
scope_parser:
  profile: cheap_api
  fallback_profile: reasoning_api
  system_prompt_template: agents/scope_parser.md
```

**検証**: `LLMRoleResolver.resolve("xss_rejudge")` / `resolve("scope_parser")` が正しく解決すること。

### Phase 2: MasterConductor の llm_client 修正 (P0)

`src/main.py` の5箇所を修正:

```python
# 変更前 (5箇所: 3187, 3345, 4020, 4126, 4220):
llm_client = LLMClient(role="specialist_light")

# 変更後:
llm_client = LLMClient(role="planner")
```

**注意**: `lessons.md` 行34 — `model=` を同時に渡さないこと。`role=` のみ渡す。

**検証**: MasterConductor インスタンスの `self.llm_client.model` が `deepseek/deepseek-v4-pro` になることを確認。

### Phase 3: ハードコード参照の排除 (P0)

#### 3.1 llm.py:88 — フォールバック修正

```python
# 変更前:
self.model = os.getenv("SHIGOKU_MODEL") or "deepseek/deepseek-chat"

# 変更後: default_role 経由で解決
elif role and not model:
    self._resolve_from_role(role, _llm_config)
else:
    # role も model も未指定 → default_role で解決
    self._resolve_from_role(
        _get_default_role_name(_llm_config), _llm_config
    )
```

**注意**: `SHIGOKU_MODEL` env の後方互換性を完全に切るか、警告ログ付きで残すかは要検討。`llm_resolver.py:182` で既に `SHIGOKU_MODEL_OUTPUT / SHIGOKU_MODEL_LIGHTWEIGHT` は「no longer supported」と宣言されているため、`SHIGOKU_MODEL` も同様に扱うのが整合的。

#### 3.2 scope_parser.py:48 — role-based 化

```python
# 変更前:
model="deepseek/deepseek-chat",

# 変更後: model= を削除し、BaseAgent 側で role-based 解決に任せる
# または明示的に role を指定:
# model= を完全に削除（AgentFactory 経由の場合は config.model が使われる）
```

#### 3.3 smart_xss.py:113, 117-121 — role-based 化

```python
# 変更後:
# primary_model は self.llm (role="xss_specialist") を参照
from src.core.models.llm import LLMClient
self.rejudge_client = LLMClient(role="xss_rejudge")
self.final_client = LLMClient(role="xss_final")
# getattr(settings, "llm_xss_rejudge_model", ...) は削除
```

#### 3.4 auth_ninja.py / biz_logic_hunter.py — model="default" 排除

```python
# 変更前:
config = AgentConfig(name="AuthAgent", model="default", ...)

# 変更後: model を削除するか、role-based にする
# BaseAgent が role-based 解決に対応している場合は model= を省略
```

### Phase 4: 非推奨フラット config のクリーンアップ (P1)

1. `config.py:164-165` の `llm_xss_rejudge_model` / `llm_xss_final_model` を `[DEPRECATED]` マーク
2. `settings.py:404-405` の同じフィールドを `[DEPRECATED]` マーク
3. `rg "getattr.*llm_xss_rejudge_model|getattr.*llm_xss_final_model"` で全コンシューマを確認
4. 全コンシューマを role-based に移行した後、フィールドを削除

### Phase 5: docker-compose.yml 更新 (P1)

```yaml
# 変更前:
- SHIGOKU_MODEL=${SHIGOKU_MODEL:-deepseek/deepseek-chat}
- SHIGOKU_MODEL_OUTPUT=${SHIGOKU_MODEL_OUTPUT:-deepseek/deepseek-chat}
- SHIGOKU_MODEL_LIGHTWEIGHT=${SHIGOKU_MODEL_LIGHTWEIGHT:-deepseek/deepseek-chat}

# 変更後: 非推奨 env を削除、または説明コメント付きで残す
# config/shigoku.yaml の llm section が正本である旨を明記
# SHIGOKU_MODEL は不要（LLMClient は default_role で解決する）
```

---

## 4. リスク分析

### 4.1 リスクサマリ

| リスク | 深刻度 | 対策 |
|---|---|---|
| MasterConductor を v4-pro に変更で API コスト増加 | 中 | v4-pro は高価だが、プランニング頻度は低い（エピソード単位）。`fallback_profile: cheap_api` でコスト上限を担保。コスト試算と1週間のモニタリングを追加 |
| `model="default"` 削除で auth_ninja が動作しない | 高 | **Step 0 で事前調査を実施**: `AgentConfig.model` が実際に消費されている箇所を `rg` で特定。`BaseAgent` が `config.model` を無視して `LLMClient(role="specialist_light")` をハードコードしている事実を確認済みのため、調査結果に基づき対応を決定 |
| `SHIGOKU_MODEL` env 廃止で既存デプロイが壊れる | 中 | 廃止前に deprecation warning ログを1リリース分出す。docker-compose.yml に移行ガイドを記載。ただし `llm.py:498`/`701` の認証エラーフォールバックパスも同時に修正する（本計画で網羅） |
| role 追加で LLMRoleResolver のテストが壊れる | 低 | 新規 role 定義は additive。既存テストへの影響なし。新規 role の resolve テストを追加 |

### 4.2 SRE/インフラエンジニア視点の懸念

| # | 懸念 | 発生確率 | 影響度 | 対策 |
|---|---|---|---|---|
| SRE-1 | `llm.py:498`/`701` の認証エラーフォールバックパスに `SHIGOKU_MODEL` env 参照が残存し、line 88 だけ修正しても一貫性のない動作になる（計画書 2.1 は line 88 のみ言及） | 高 | 大 | Phase 3.1 に対象行として `llm.py:498` と `llm.py:701` を明記。grep 検証に `rg "SHIGOKU_MODEL" src/ --type py` を追加し 0 件を達成条件とする |
| SRE-2 | `SHIGOKU_MODEL` env フォールバック除去後、`default_role` が `LLMRoleResolver` で解決できない場合（config 破損等）、`LLMClient()` インスタンス化自体が失敗しプロセス起動不能になる。現在は最低限 `deepseek-chat` 文字列にフォールバックして litellm 側のエラーハンドリングに委ねられる | 中 | 大 | `_resolve_from_role` 呼び出しを try/except で囲み、`LLMResolutionError` 時にクリティカルログを出力して `RuntimeError` を再送出（fail-fast）。代替として `SHIGOKU_MODEL` env を「非推奨だが最終フォールバック」として `logger.warning` 付きで 1 リリース分残す選択肢を明記 |
| SRE-3 | MasterConductor の v4-pro 一斉切り替えで、応答レイテンシ増大や推論品質の変化が全負荷に同時波及。問題発生時の切り戻しにコード再デプロイが必要 | 中 | 大 | 環境変数 `SHIGOKU_MC_MODEL_ROLE`（デフォルト: `planner`）による feature flag を導入。`specialist_light` に設定するだけで即時切り戻し可能にする |
| SRE-4 | docker-compose.yml の env 行削除/維持の方針が曖昧で、削除した場合に既存 `.env` で `SHIGOKU_MODEL` を設定している環境が破壊される。残した場合も「設定しても無視される死んだ変数」となり運用者の混乱を招く | 高 | 中 | **方針確定**: 削除する。`docker-compose.yml` に破壊的変更であることを明記するコメントと移行ガイド（`config/shigoku.yaml` の `llm.default_role` で制御する旨）を記載。CHANGELOG に破壊的変更として記載 |

### 4.3 ソフトウェアアーキテクト視点の懸念

| # | 懸念 | 発生確率 | 影響度 | 対策 |
|---|---|---|---|---|
| ARCH-1 | `AgentConfig.model` は Pydantic 必須フィールド（`base.py:16`）だが、`BaseAgent.__init__`（`base.py:48`）は `config.model` を完全に無視し `LLMClient(role="specialist_light")` をハードコードしている。計画書 Phase 3.4 は「model= を削除する」としているが必須フィールドは削除不可能で、AgentConfig スキーマ変更が必要 | 高 | 大 | Step 0 で `AgentConfig.model` の全コンシューマを `rg` で調査。結果に基づき `AgentConfig.model` を `Optional[str] = None` に変更するステップを Phase 3.4 の前提条件として追加。または「`model="default"` は無害なデッドコードであり本計画のスコープ外」と明記 |
| ARCH-2 | `scope_parser` role の `system_prompt_template` が、`BaseAgent._initialize_system_prompt()` によって既に system メッセージが設定されているため、`_maybe_inject_system_prompt` に到達しても注入されない（既存 system メッセージがある場合はスキップ）。さらに template ファイルが存在しなくても `logger.debug` でサイレントに失敗 | 中 | 中 | scope_parser role の `system_prompt_template` を `null` に設定し「モデル解決のみに使用し、プロンプトはエージェント側で制御」と YAML コメントで明記 |
| ARCH-3 | `smart_xss.py:817-825` の `self.llm.model = decision_model` 直接代入パターンが、role-based client への移行と衝突。`_choose_decision_model()` はモデル文字列を返す設計であり、別クライアントを使うパターンへのリファクタリングが必要だが計画書に手順が明記されていない | 中 | 大 | `_choose_decision_model()` を `_get_decision_client()` にリファクタリングし、戻り値を `Tuple[LLMClient, str]` に変更。呼び出し側の `self.llm.model` 直接代入を削除し、返却されたクライアントの `agenerate()` を直接使用する |
| ARCH-4 | `xss_rejudge`/`xss_final` が `roles/xss_specialist.md` を再利用するが、再判定/最終判定は「評価・判断」であり「ペイロード生成・WAF 回避」の指示とは役割が異なるため、LLM 出力品質が低下する可能性 | 低 | 中 | 再利用を意図的に行う場合、YAML に `# reuses xss_specialist prompt intentionally — rejudge/final use same evaluation criteria` と根拠コメントを記載。または専用 prompt を新規作成 |

### 4.4 デバッガー視点の懸念

| # | 懸念 | 発生確率 | 影響度 | 対策 |
|---|---|---|---|---|
| DBG-1 | `LLMRoleResolver.resolve()` は role 未定義時に `final_judgement` 以外は **警告もログも出さず** `default_role` にフォールバック。`role="planner"` が typo 等で未解決の場合、MasterConductor がサイレントに `specialist_light`（v4-flash）で動作し、計画書が修正しようとしている問題が再発する | 中 | 大 | `LLMRoleResolver.resolve()` に WARNING レベルのログを追加（role が default_role にフォールバックした場合）。Phase 5 検証に「起動時の role 整合性セルフチェック（コード内参照 role 名と config 定義の突合）」を追加 |
| DBG-2 | `_maybe_inject_system_prompt`（`llm.py:300-316`）が prompt template のロード失敗を `logger.debug` で捕捉。本番運用では DEBUG ログ無効が一般的であり、template 不在に誰も気づかないまま LLM がシステムプロンプトなしで呼ばれ出力品質が劣化 | 中 | 中 | 例外捕捉レベルを `logger.warning` に引き上げる。Phase 1 検証に全 role の `system_prompt_template` が実ファイルとして存在することを確認するテストを追加 |
| DBG-3 | `model="default"` の実際の挙動が未調査のまま修正着手。`BaseAgent` が `config.model` を無視しているため `model="default"` は無害なデッドデータである可能性が高いが、`auth_ninja.py` 内で `config.model` を読んで別の `LLMClient` を生成している箇所があれば真の修正対象。調査なしの修正は無害な箇所を触って回帰を生むか、危険な箇所を見落とす | 高 | 大 | **Step 0（事前調査）を追加**: `rg "config\.model\|\.config\.get\(.*model" auth_ninja.py biz_logic_hunter.py` で `model="default"` の実際の消費箇所を特定。調査結果を計画書 2.7 に追記し、発見に基づいて Phase 3.4 の方針を確定 |
| DBG-4 | `llm.py:498`/`701` の認証エラーフォールバックパスが `SHIGOKU_MODEL` env を読む。本番環境で過去に `SHIGOKU_MODEL=deepseek/deepseek-chat` が設定されたまま残っていると、認証エラー発生時（非決定的パス）にのみ廃止予定の deepseek-chat が使われ、再現困難なバグになる | 低 | 中 | `llm.py:498`/`701` を role-based client の場合は `self._resolver.resolve(self._resolver.default_role).model` に変更。非 role client では `deepseek/deepseek-v4-flash` に固定 |
| DBG-5 | grep 検証（5.2節）が `--type py` に限定されており、`config/shigoku.yaml`、`docker-compose.yml`、CI/CD 設定、スクリプト類のハードコード参照を捕捉しない | 低 | 中 | `rg "deepseek-chat" --type yaml --type yml` と `rg "SHIGOKU_MODEL" config/ scripts/ docker-compose.yml` を検証に追加 |

### 4.5 CTO視点の懸念

| # | 懸念 | 発生確率 | 影響度 | 対策 |
|---|---|---|---|---|
| CTO-1 | v4-pro 切り替えのコスト影響が定性評価のみで具体的試算がない。v4-pro は v4-flash の約4〜8倍の API 単価であり、月間数百エピソードの環境では無視できないコスト増 | 高 | 大 | コスト試算セクションを追加（現行と移行後の推定トークン数×単価の差分）。Phase 2 完了後に 1 週間のコストモニタリング期間を設け、想定比 +50% 超過で自動アラート |
| CTO-2 | 切り戻し手順が一切記載されていない。MasterConductor のモデル変更が脆弱性検出率低下や API コスト急騰を引き起こした場合、コード再デプロイ以外に戻す手段がない | 中 | 大 | ロールバック計画セクションを追加: feature flag（`SHIGOKU_MC_MODEL_ROLE=specialist_light`）による即時切り戻し、判断基準（コスト+50%、エラーレート+10%、検出数-20%）、docker-compose 切り戻し手順 |
| CTO-3 | XSS 再判定モデルを OpenAI（gpt-4o-mini/gpt-4o）から DeepSeek（v4-flash/v4-pro）に切り替えることで、false positive/negative のバランスが変化し検出品質に影響する可能性 | 中 | 中 | 既知の XSS テストケース（陽性/陰性各 N 件）を修正前後のモデルで実行し判定一致率を比較する回帰テストを追加。一致率 95% 未満の場合、provider を openai に設定するフォールバック方針を記載 |
| CTO-4 | 全 Phase が deepseek-chat 廃止デッドライン（7/24）に依存。Phase 1-3 のいずれかが予期せぬ複雑さで遅延した場合、全修正が間に合わない | 低 | 中 | コンティンジェンシー計画を追加: 7/20 時点で Phase 1-3 未完了の場合、最小限ホットフィックス（`llm.py:88`/`498`/`701` の `deepseek-chat`→`deepseek-v4-flash` 置換のみ）を緊急デプロイ。role 追加や `model="default"` 修正は後続タスクに切り離し |
| CTO-5 | 変更の「完了」定義がユニットテストと grep 検証のみで、ビジネスレベルの受け入れ基準（脆弱性検出率維持、API コスト許容範囲、既存ワークフロー非破壊）が定義されていない | 中 | 中 | 受け入れ基準サブセクションを追加: 全テストパス、エンドツーエンドスキャン正常完了、MC ログに v4-pro 記録、脆弱性レポート正常生成。（オプショナル）修正前後スキャンで検出数 ±10% 以内 |

---

## 5. 検証計画

### 5.1 ユニットテスト

| テスト | 内容 |
|---|---|
| `test_llm_resolver` | `resolve("planner")` が `reasoning_api` profile / `deepseek-v4-pro` を返すこと |
| `test_llm_resolver` | `resolve("xss_rejudge")` / `resolve("xss_final")` / `resolve("scope_parser")` が正しく解決すること |
| `test_llm_client` | `LLMClient(role="planner").model` が `deepseek/deepseek-v4-pro` であること |
| `test_llm_client` | `LLMClient()` (引数なし) が `default_role` 経由で解決し、`deepseek-chat` を使わないこと |
| `test_master_conductor` | MasterConductor インスタンスの `llm_client.model` が v4-pro であること |

### 5.2 グレップ検証

修正後に以下を満たすこと:

```bash
# deepseek-chat への参照が残っていない（テストデータ/ドキュメント除く）
rg "deepseek-chat" src/ --type py -g '!*test*'
# → 0 matches

# model="default" が残っていない
rg 'model="default"' src/ --type py
# → 0 matches

# model="deepseek/" のハードコードが残っていない
rg 'model="deepseek/' src/ --type py
# → 0 matches

# getattr.*llm_xss_rejudge_model のコンシューマ確認
rg "llm_xss_rejudge_model|llm_xss_final_model" src/ --type py
# → DEPRECATED マークのみ or 0 matches
```

### 5.3 統合テスト

- MasterConductor の `_plan_with_llm` が v4-pro で実行されることをログで確認
- smart_xss の rejudge/final が role-based モデルで実行されることを確認
- scope_parser が role-based モデルで実行されることを確認

---

## 6. 実装順序

### Step 0: 事前調査 — `model="default"` の実際の消費箇所特定 [DBG-3, ARCH-1]

`auth_ninja.py` / `biz_logic_hunter.py` の `model="default"` が実際にコード内で消費されているかを調査する。調査なしの修正は無害な箇所を触って回帰を生むか、危険な箇所を見落とすリスクがある。

**アクション**:
1. `rg "config\.model|\.config\.get\(.*model" src/core/agents/swarm/auth_ninja.py src/core/agents/swarm/biz_logic_hunter.py` で `AgentConfig.model` が読み取られている箇所を特定
2. `rg "LLMClient\(" src/core/agents/swarm/auth_ninja.py src/core/agents/swarm/biz_logic_hunter.py` で `AgentConfig.model` を引数に取る LLMClient 生成を特定
3. 調査結果を計画書 2.7 に追記し、発見に基づいて Step 7 の方針を確定する
4. 併せて `rg "config\.model|\.config\.model" src/ --type py` で `AgentConfig.model` の全コンシューマを横断調査し、`model: str` から `model: Optional[str] = None` への変更可否を判断する

### Step 1: config/shigoku.yaml — 新規 role 追加 [Phase 1]

新規 role `xss_rejudge`, `xss_final`, `scope_parser` を追加する。

**アクション**:
1. `config/shigoku.yaml` の `llm.roles` に以下を追加:
   ```yaml
   xss_rejudge:
     profile: cheap_api
     fallback_profile: reasoning_api
     system_prompt_template: roles/xss_specialist.md  # reuses xss_specialist prompt intentionally — rejudge uses same evaluation criteria
   xss_final:
     profile: reasoning_api
     fallback_profile: cheap_api
     system_prompt_template: roles/xss_specialist.md  # reuses xss_specialist prompt intentionally — final uses same evaluation criteria
   scope_parser:
     profile: cheap_api
     fallback_profile: reasoning_api
     system_prompt_template: null  # prompt is controlled by ScopeParserAgent, role is for model resolution only
   ```
2. `scope_parser` role の `system_prompt_template` を `null` に設定する理由: `BaseAgent._initialize_system_prompt()` が既に system メッセージを設定するため、`_maybe_inject_system_prompt` は注入をスキップする。`null` にすることで意図を明確化する [ARCH-2]
3. **prompt template 存在確認**: 全 role の `system_prompt_template` が `null` でない場合、`src/prompts/<template>` が実ファイルとして存在することを確認するテストを追加 [DBG-2]:
   ```python
   # test_llm_resolver に追加:
   def test_all_role_prompt_templates_exist():
       for role_name, role in llm_settings.roles.items():
           if role.system_prompt_template:
               assert Path(f"src/prompts/{role.system_prompt_template}").exists(), \
                   f"Prompt template missing for role '{role_name}': {role.system_prompt_template}"
   ```
4. `LLMRoleResolver.resolve("xss_rejudge")` / `resolve("xss_final")` / `resolve("scope_parser")` が正しく解決することを手動またはテストで確認

### Step 2: llm_resolver.py — role fallback に WARNING ログ追加 [DBG-1]

`LLMRoleResolver.resolve()` が要求された role を見つけられず `default_role` にフォールバックする際、現在は完全にサイレントである。`planner` role が typo 等で未解決の場合に MasterConductor が無警告で弱いモデルにフォールバックするのを防ぐ。

**アクション**:
1. `llm_resolver.py` の `resolve()` メソッド（74-90行目付近）で、`role is None` のブロックに以下を追加:
   ```python
   logger.warning(
       "Role '%s' not found in config, falling back to default_role '%s'. "
       "This may indicate a configuration error or typo in the role name.",
       role_name, self._default_role
   )
   ```
2. **起動時 role 整合性セルフチェック**: コード内で参照される全 role 名を静的解析または実行時検証で列挙し、config に定義されていることを確認するテストを Step 10 に追加

### Step 3: llm.py — 全 SHIGOKU_MODEL フォールバック修正 + ログレベル変更 [SRE-1, DBG-4, DBG-2]

`llm.py` 内の **3箇所** の `SHIGOKU_MODEL` env 参照をすべて修正する（計画書 2.1 は line 88 のみ言及していたが、line 498 と line 701 も対象）。

**アクション**:
1. **llm.py:88** — `__init__` のフォールバックを default_role 解決に変更:
   ```python
   # 変更前:
   self.model = os.getenv("SHIGOKU_MODEL") or "deepseek/deepseek-chat"
   # 変更後:
   self._resolve_from_role(
       _get_default_role_name(_llm_config), _llm_config
   )
   ```
   `_resolve_from_role` 呼び出しを try/except `LLMResolutionError` で囲み、解決失敗時はクリティカルログを出力して `RuntimeError` を送出（fail-fast）[SRE-2]

2. **llm.py:498** — `generate()` の認証エラーフォールバック:
   ```python
   # 変更前:
   fallback_model = os.getenv("SHIGOKU_MODEL") or "deepseek/deepseek-v4-flash"
   # 変更後 (role-based client の場合):
   if self._resolver is not None:
       fallback_model = self._resolver.resolve(self._resolver.default_role).model
   else:
       fallback_model = "deepseek/deepseek-v4-flash"
   ```

3. **llm.py:701** — `agenerate()` の認証エラーフォールバック: line 498 と同様の修正

4. **llm.py:300-316** — `_maybe_inject_system_prompt` の例外捕捉レベルを `logger.debug` から `logger.warning` に引き上げ:
   ```python
   # 変更前:
   logger.debug("Failed to render system prompt template '%s': %s", ...)
   # 変更後:
   logger.warning("Failed to render system prompt template '%s': %s", ...)
   ```

### Step 4: main.py — MasterConductor の llm_client 修正 + feature flag [SRE-3, CTO-2]

`main.py` の 5 箇所を `role="planner"` に変更し、同時に即時切り戻し用の環境変数 feature flag を導入する。

**アクション**:
1. `main.py` の 5 箇所（3187, 3345, 4020, 4126, 4220 行目付近）を修正:
   ```python
   # 変更前:
   llm_client = LLMClient(role="specialist_light")
   # 変更後:
   _mc_role = os.getenv("SHIGOKU_MC_MODEL_ROLE", "planner")
   llm_client = LLMClient(role=_mc_role)
   ```
2. `lessons.md` 行34 に従い、`model=` を同時に渡さないこと
3. 検証: MasterConductor インスタンスの `self.llm_client.model` が `deepseek/deepseek-v4-pro` になることを確認。`SHIGOKU_MC_MODEL_ROLE=specialist_light` で v4-flash に切り戻せることも確認

### Step 5: scope_parser.py — model= ハードコード削除 [Phase 3.2]

**アクション**:
1. `scope_parser.py:48` の `model="deepseek/deepseek-chat"` を削除。レガシーフォールバックパス（`config` 未渡し時）では `model=` を省略し、BaseAgent 側の role-based 解決に任せる
2. ScopeParserAgent が直接 `LLMClient(role="scope_parser")` を使用するよう変更（必要な場合）
3. `scope_parser` role の `system_prompt_template: null`（Step 1 で設定済み）により、モデル解決のみ行いプロンプトはエージェント側の `get_agent_prompt("scope_parser")` に委ねる

### Step 6: smart_xss.py — role-based 化 + mutation pattern リファクタリング [ARCH-3, CTO-3]

`smart_xss.py` のモデル参照を role-based に移行し、`self.llm.model = decision_model` の直接代入パターンを排除する。

**アクション**:
1. `__init__` 内のハードコードモデル参照を削除し、role-based クライアントに置き換え:
   ```python
   # 削除:
   model = os.getenv("SHIGOKU_MODEL") or "deepseek/deepseek-chat"
   rejudge_model = getattr(settings, "llm_xss_rejudge_model", "openai/gpt-4o-mini")
   final_model = getattr(settings, "llm_xss_final_model", "openai/gpt-4o")
   # 追加:
   self._rejudge_client = None  # lazy init
   self._final_client = None    # lazy init
   ```
2. `self.rejudge_model` / `self.final_model` 文字列プロパティを削除し、`_get_rejudge_client()` / `_get_final_client()` メソッドを追加（遅延初期化で `LLMClient(role="xss_rejudge")` / `LLMClient(role="xss_final")` を返す）
3. `_choose_decision_model()` を `_get_decision_client()` にリファクタリング:
   - 戻り値を `Tuple[LLMClient, str]`（クライアントインスタンスとステージ名）に変更
   - 内部で `_get_rejudge_client()` / `_get_final_client()` を呼び出す
4. 呼び出し側（~807-825行目）の `self.llm.model = decision_model` 直接代入を削除し、返却されたクライアントの `agenerate()` を直接使用:
   ```python
   # 変更前:
   original_model = self.llm.model
   self.llm.model = decision_model
   try:
       response = await self.llm.agenerate([...])
   finally:
       self.llm.model = original_model
   # 変更後:
   decision_client, decision_stage = self._get_decision_client()
   response = await decision_client.agenerate([...])
   ```
5. `self.primary_model` は `self.llm`（`role="xss_specialist"`）で代替。文字列として必要な場合は `self.llm.model` を参照
6. **XSS 回帰テスト** [CTO-3]: 既知の XSS テストケース（陽性/陰性各 N 件）を修正前後のモデルで実行し、判定一致率を比較。一致率 95% 未満の場合、`xss_rejudge`/`xss_final` role の provider を `openai` に設定するフォールバックを検討

### Step 7: auth_ninja.py / biz_logic_hunter.py — model="default" 対応 [DBG-3, ARCH-1]

**Step 0 の調査結果に基づいて方針を決定し、実行する。**

調査結果のパターン別対応:
- **パターン A**: `model="default"` が `AgentConfig` に渡されるのみで、実際には `BaseAgent` の `LLMClient(role="specialist_light")` が使われている（デッドコード）→ `model="default"` を削除し、`AgentConfig.model` を `Optional[str] = None` に変更
- **パターン B**: `auth_ninja.py` 内で `config.model` を読んで別の `LLMClient` を生成している → 該当箇所を `LLMClient(role="swarm_manager")` 等の role-based 呼び出しに変更
- **パターン C**: `AgentConfig.model` が他のパスでも必須フィールドとして使われている → `model` フィールドを Optional 化できないため、`model=""` または `model=None` に変更し、`LLMClient` 側で空文字列を無視するロジックを追加

**アクション**:
1. Step 0 の調査結果を計画書 2.7 に追記
2. 上記パターンに基づき修正を実施
3. 修正後、`rg 'model="default"' src/ --type py` が 0 件になることを確認

### Step 8: config.py / settings.py — フラット config DEPRECATED マーク [Phase 4]

**アクション**:
1. `config.py:164-165` の `llm_xss_rejudge_model` / `llm_xss_final_model` に `# [DEPRECATED] — use LLMClient(role="xss_rejudge") / LLMClient(role="xss_final") instead` コメントを追加
2. `settings.py:404-405` の同フィールドにも同様の DEPRECATED マークを追加
3. `rg "getattr.*llm_xss_rejudge_model|getattr.*llm_xss_final_model" src/ --type py` で全コンシューマを確認し、Step 6 で対応済みであることを検証
4. 全コンシューマが role-based に移行済みであればフィールドを削除。未移行があれば削除を deferred_tasks に記録

### Step 9: docker-compose.yml — env 行削除 + 移行ガイド [SRE-4]

**アクション**:
1. `docker-compose.yml` から以下の行を削除:
   ```yaml
   - SHIGOKU_MODEL=${SHIGOKU_MODEL:-deepseek/deepseek-chat}
   - SHIGOKU_MODEL_OUTPUT=${SHIGOKU_MODEL_OUTPUT:-deepseek/deepseek-chat}
   - SHIGOKU_MODEL_LIGHTWEIGHT=${SHIGOKU_MODEL_LIGHTWEIGHT:-deepseek/deepseek-chat}
   ```
2. 削除箇所に以下の移行ガイドコメントを追加:
   ```yaml
   # [BREAKING] SHIGOKU_MODEL / SHIGOKU_MODEL_OUTPUT / SHIGOKU_MODEL_LIGHTWEIGHT env vars removed.
   # LLM model selection is now controlled via config/shigoku.yaml → llm section.
   # To change the default model, edit llm.default_role or the corresponding role's profile.
   # See docs/shigoku/plans/2026-07-10_sgk-2026-0349_*.md for migration details.
   ```

### Step 10: ユニットテスト追加・実行

**アクション**:
1. 計画書 5.1 の全テストを実装し、`.venv/bin/pytest` でパスを確認
2. 以下を追加実装:
   - `test_all_role_prompt_templates_exist` — 全 role の system_prompt_template ファイル存在確認（Step 1 参照）
   - `test_role_fallback_logs_warning` — role 未定義時に WARNING ログが出力されることの確認（Step 2 参照）
   - `test_llm_client_no_args_resolves_default_role` — `LLMClient()` 引数なしで default_role 経由で解決されること
   - `test_master_conductor_feature_flag` — `SHIGOKU_MC_MODEL_ROLE` 環境変数で role が切り替わること
3. `LLMRoleResolver` の既存テストが全パスすることを確認

### Step 11: グレップ検証（拡張スコープ）[DBG-5]

修正後に以下を **全件 0 matches** で満たすこと:

```bash
# deepseek-chat への参照が残っていない（テストデータ/ドキュメント除く）
rg "deepseek-chat" src/ --type py -g '!*test*'
# → 0 matches

# SHIGOKU_MODEL env var への参照が残っていない
rg "SHIGOKU_MODEL" src/ --type py
# → 0 matches

# model="default" が残っていない
rg 'model="default"' src/ --type py
# → 0 matches

# model="deepseek/ のハードコードが残っていない
rg 'model="deepseek/' src/ --type py
# → 0 matches

# getattr.*llm_xss_rejudge_model のコンシューマ確認
rg "llm_xss_rejudge_model|llm_xss_final_model" src/ --type py
# → DEPRECATED マークのみ or 0 matches

# 設定ファイル・スクリプトにも deepseek-chat が残っていない
rg "deepseek-chat" --type yaml --type yml config/ docker-compose.yml
# → 0 matches

# 設定ファイル・スクリプトに SHIGOKU_MODEL 参照が残っていない（コメント除く）
rg "SHIGOKU_MODEL[^_]" config/ scripts/ docker-compose.yml
# → 0 matches
```

### Step 12: 統合テスト + 回帰テスト

**アクション**:
1. MasterConductor の `_plan_with_llm` が v4-pro で実行されることをログで確認
2. smart_xss の rejudge/final が role-based クライアントで実行されることを確認
3. scope_parser が role-based モデルで実行されることを確認
4. **XSS 回帰テスト** [CTO-3]: 既知の XSS テストケース（陽性/陰性各最低 10 件）を修正前後の smart_xss で実行し、判定一致率を比較。95% 未満の場合は要調査
5. 代表的なターゲットに対するエンドツーエンドスキャンが正常完了し、脆弱性レポートが正常に生成されることを確認

### Step 13: コストモニタリング + ロールバック計画ドキュメント化 [CTO-1, CTO-2, CTO-5]

**アクション**:
1. **コスト試算**: 現行（v4-flash × 推定プランニング呼び出し数/日）と移行後（v4-pro × 同数、thinking tokens 込み）の推定コスト差分を算出し、計画書に追記
2. **コストモニタリング**: Phase 2 デプロイ後 1 週間、プランニング API コストとレイテンシをログ収集。想定比 +50% 超過でアラート
3. **ロールバック計画**を計画書に明記:
   - 即時切り戻し: `SHIGOKU_MC_MODEL_ROLE=specialist_light` を設定して `docker compose up -d`
   - 判断基準: コスト +50%、エラーレート +10%、脆弱性検出数 -20% のいずれか
   - docker-compose の具体的切り戻し手順
4. **受け入れ基準**を明文化:
   - 全ユニットテスト・grep 検証パス（必須）
   - エンドツーエンドスキャン正常完了（必須）
   - MasterConductor ログに `deepseek/deepseek-v4-pro` が記録されること（必須）
   - 脆弱性レポート正常生成（必須）
   - （オプショナル）修正前後スキャンで検出数 ±10% 以内

### Step 14: コンティンジェンシー計画確認（7/20 ゲート）[CTO-4]

**アクション**:
1. 2026-07-20 時点で Step 0〜7（P0 相当）の進捗を確認
2. **未完了の場合**: 最小限ホットフィックスを緊急デプロイ:
   - `llm.py:88`/`498`/`701` の `deepseek-chat` → `deepseek-v4-flash` への置換のみ
   - `SHIGOKU_MODEL` env 参照は `deepseek-v4-flash` にフォールバック
   - role 追加、model="default" 修正、smart_xss リファクタリングは後続タスクに切り離し
3. ホットフィックス用の独立 SGK タスクを事前に定義し、`deferred_tasks` にプレースホルダーとして記録

---

## 7. 関連ルール・教訓

- **AGENTS.md ルール18**: LLM設定統一ルール — 新規コードは `LLMClient(role="...")` のみ
- **lessons.md 行34**: `model=` を渡すと role が無視される（サイレントダウングレード）
- **llm_resolver.py:182**: `SHIGOKU_MODEL_OUTPUT / SHIGOKU_MODEL_LIGHTWEIGHT` は既に「no longer supported」

---

## 8. deferred_tasks

| タスク | 条件 | 内容 |
|---|---|---|
| SGK-2026-XXXX（ホットフィックス用、事前定義） | 7/20 時点で Step 0〜7 未完了の場合 [CTO-4] | `llm.py:88`/`498`/`701` の `deepseek-chat`→`deepseek-v4-flash` 置換のみ。role 追加・`model="default"` 修正・smart_xss リファクタリングは後続タスクに切り離し |
| `config.py` / `settings.py` の DEPRECATED フィールド完全削除 | Step 8 で全コンシューマの移行完了後 | `llm_xss_rejudge_model` / `llm_xss_final_model` フィールドを削除 |
| `SHIGOKU_MODEL` env の完全廃止 | 1 リリース分の deprecation warning 期間経過後 [SRE-2] | コード・設定からの `SHIGOKU_MODEL` 参照を完全除去 |
| `AgentConfig.model` フィールド Optional 化 | Step 7 でパターン A が確認された場合 | `model: str` → `model: Optional[str] = None` に変更し、全サブクラスの `model=` 必須指定を解除 |
