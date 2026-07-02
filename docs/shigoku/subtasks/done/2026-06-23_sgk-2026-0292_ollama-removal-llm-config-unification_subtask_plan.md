---
task_id: SGK-2026-0292
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0289
related_docs:
- docs/shigoku/plans/2026-06-21_sgk-2026-0289_commonization-technical-debt-roadmap_plan.md
title: Ollama廃止とLLM設定統一 設計議論計画
created_at: '2026-06-23'
updated_at: '2026-07-02'
tags:
- shigoku
target: config/shigoku.yaml, config/features.yaml, src/core/config/settings.py, src/config.py, src/core/models/llm.py, src/core/llm/, src/prompts/, src/core/agents/, src/core/engine/, src/core/rag_module/rag.py, src/intelligence/proxy_log_analyzer.py, tests/, docs/shigoku/manuals/, docs/shigoku/specs/
---

# 実装計画書：Ollama廃止とLLM設定統一 設計議論計画

## 1. 達成したいゴール（ユーザー視点）
- [ ] Ollama 依存をやめ、APIベースの複数LLMを用途やサブエージェントごとに使い分けられる設計にすること。
- [ ] 一気に全面改修せず、まず Ollama を安価なAPIモデルへ置き換えられること。
- [ ] LLM設定を一元化し、ユーザーが設定ファイルだけで role/model/provider/base_url/api_key_env/timeout/temperature/fallback を調整できるようにすること。
- [ ] Swarm、Worker、Custom AI、Conductor、RAG圧縮、tool output analysis などの用途別に最適な LLM role を割り当てられること。
- [ ] 各 role の system prompt を一元管理し、コード内の直書き system prompt を段階的にテンプレート化できること。
- [ ] `AutoRoute` や `TaskComplexityClassifier` による暗黙分岐を減らし、役割別の明示設定へ寄せること。

## 2. 全体像とアーキテクチャ
- **設定正本の決定:**
  - 正本は `config/shigoku.yaml` とする。
  - schema と読み込みは `src/core/config/settings.py` の `Settings` / nested `LLMSettings` に集約する。
  - `src/config.py` は互換ラッパーに降格し、`model`, `model_lightweight`, `model_output`, `llm_fallback_model`, `local_llm_*`, `any_llm_*` などの LLM 設定値を直接保持し続けない。
  - `config/features.yaml` は feature flag / 品質ゲート設定に限定し、`phase3.micro_agent.model` / `ollama_url` は `config/shigoku.yaml` の `llm.roles.tool_output_analysis` に移す。
  - `.env.example` と `docker-compose.yml` は API key env と env override 例だけを持ち、Ollama 前提の env 例を削除または非推奨化する。
- **system prompt の置き場所と規則:**
  - prompt 本文の正本は `src/prompts/` 配下とする。
  - role と prompt template の対応は `config/shigoku.yaml` の `llm.roles.<role>.system_prompt_template` で管理する。
  - `src/prompts/agents/` は agent/manager 系、`src/prompts/conductor/` は conductor 系、共通片は `src/prompts/_partials/` に置く。
  - 新規の用途別 prompt は `src/prompts/roles/` または既存カテゴリに追加し、コード内に長い system prompt を直書きしない。
  - テスト用の短い system prompt 以外は、`{"role": "system", "content": "..."}` の直書きを段階的に template 参照へ移す。
  - role 名は snake_case とし、`planner`, `advisor`, `swarm_manager`, `worker_llm`, `specialist_light`, `tool_output_analysis`, `rag_compression`, `reporting`, `final_judgement`, `vision_analysis` を初期候補にする。
- **対象コンポーネント/ファイル一覧:**
  - `config/shigoku.yaml`, `config/shigoku.yaml.example`: LLM role/profile/prompt mapping の正本。
  - `src/core/config/settings.py`: `LLMSettings`, `LLMProfileSettings`, `LLMRoleSettings` を追加する schema 正本。
  - `src/core/config_manager.py`: 明示パス読み込みと再読み込みの互換確認。
  - `src/config.py`: 旧 `Settings` の LLM 設定を `get_settings()` 参照の deprecated alias へ移行。
  - `src/core/models/llm.py`: `LLMClient` の local/cloud/auto_route 判定を role/profile 解決へ移行。
  - `src/core/llm/local_provider.py`, `src/core/llm/__init__.py`: Ollama専用 provider と `TaskComplexityClassifier` の廃止/互換退避。
  - `src/core/llm/micro_agent.py`: Ollama `/api/generate` 直叩きを `LLMClient` role `tool_output_analysis` 経由へ変更。
  - `src/core/utils/log_translator.py`: Ollama翻訳を廃止、または role `log_translation` 経由の任意API実装へ変更。
  - `src/core/agents/specialized/visual_recon.py`: Ollama/LLaVA 前提を `vision_analysis` role または別 adapter へ分離。
  - `src/core/gpu_accelerator.py`: Ollama CLI 管理を削除/非推奨化し、GPU検出・embedding/hashcat補助に責務を限定。
  - `src/core/rag_module/rag.py`: `LocalLLMProvider` 圧縮を `rag_compression` role に移行。
  - `src/intelligence/proxy_log_analyzer.py`: `GPUAccelerator.query_ollama()` ranking を role `tool_output_analysis` へ移行。
  - `src/core/agents/swarm/base_manager.py`: turn別 `model_lightweight`/`model_output` 選択を role resolver へ移行し、system prompt template を設定から解決可能にする。
  - `src/core/swarm/worker/llm_worker.py`, `src/core/swarm/worker/factory.py`: Worker の role/model/system prompt 解決を統一する。
  - `src/core/agents/general_agent.py`, `src/core/engine/master_conductor.py`, `src/recon/parallel_tasks.py`: `ollama/qwen3.5:latest` fallback と旧 model 設定参照を削除する。
  - `src/core/agents/swarm/*/llm_specialists.py`, `src/core/agents/swarm/injection/smart_*.py`, `src/core/agents/swarm/biz_logic_hunter.py`: 直接 `settings.model_output` / `LLMClient(model=...)` / `SYSTEM_PROMPT` を role/prompt mapping へ移行する。
  - `src/prompts/__init__.py`, `src/core/utils/prompt_renderer.py`, `src/legacy_prompts.py`, `src/core/engine/conductor_prompts.py`, `src/core/conductor/conductor_prompts.py`: prompt 解決の重複と legacy fallback の整理対象。
  - `src/cli/commands.py`, `src/cli/messages.py`, `src/tools/custom/ffuf.py`: UI/ヘルプ/API provider 選択肢から Ollama 前提を削除または一般 provider 表記へ変更。
  - `.env.example`, `docker-compose.yml`: Ollama env / host service 前提を削除または非推奨コメントへ変更。
  - `tests/core/llm/test_llm_client.py`, `tests/core/test_settings.py`, `tests/core/test_config_yaml.py`, `tests/core/agents/swarm/test_base_manager.py`, `tests/integration/test_gpu_features.py`, `tests/core/test_factory_registry.py`: router/settings/prompt/Ollama未導入環境の回帰テスト更新。
  - `docs/shigoku/manuals/MANUAL_JA.md`, `docs/shigoku/specs/TECHNICAL_SPEC_JA.md`, `docs/shigoku/specs/llm_optimization.md`, `docs/shigoku/specs/any-llm-integration.md`, `docs/shigoku/roadmaps/future_functions.md`: ユーザー向け設定説明と既存仕様の更新対象。
- **データの流れ / 依存関係:**
  - `config/shigoku.yaml` -> `Settings.llm` -> `LLMRoleResolver` / `LLMRouter` -> `LLMClient` -> 各エージェント/MC/Swarm/Worker/MicroAgent/RAG。
  - `config/shigoku.yaml` -> `llm.roles.<role>.system_prompt_template` -> `PromptRenderer` -> system message。
  - 現状は `LLMClient` 経由で切り替わる部分と、Ollama API/CLI を直接呼ぶ部分が混在している。
  - 置き換え第一段階では、直叩き箇所を `LLMClient` または新 `LLMRouter` に寄せ、Ollama固有のURL/model名を設定正本から消していく。
  - 互換期間中は旧 flat 設定を読み取って role/profile に変換するが、新規コードは `Settings.llm` だけを参照する。

### 2.1 `config/shigoku.yaml` の LLM 設定ルール案
```yaml
llm:
  schema_version: 1
  default_role: specialist_light
  providers:
    deepseek:
      api_key_env: DEEPSEEK_API_KEY
      base_url: null
    openai:
      api_key_env: OPENAI_API_KEY
      base_url: null
    any_llm:
      api_key_env: ANY_LLM_API_KEY
      base_url: http://localhost:8000/v1

  profiles:
    cheap_api:
      provider: deepseek
      model: deepseek/deepseek-v4-flash
      timeout_seconds: 300
      max_retries: 2
      max_concurrency: 4
      rate_limit_per_minute: 60
      temperature: 0.0
    reasoning_api:
      provider: deepseek
      model: deepseek/deepseek-v4-pro
      timeout_seconds: 300
      max_retries: 2
      max_concurrency: 2
      rate_limit_per_minute: 30
      temperature: 0.0
      extra:
        thinking:
          type: enabled
        reasoning_effort: high
    vision_api:
      provider: openai
      model: openai/gpt-4o
      timeout_seconds: 300

  roles:
    planner:
      profile: reasoning_api
      fallback_profile: cheap_api
      system_prompt_template: conductor/planning.md
    swarm_manager:
      profile: cheap_api
      fallback_profile: reasoning_api
      system_prompt_template: agents/manager_base.md
    tool_output_analysis:
      profile: cheap_api
      fallback_profile: reasoning_api
      system_prompt_template: roles/tool_output_analysis.md
    rag_compression:
      profile: cheap_api
      system_prompt_template: roles/rag_compression.md
    final_judgement:
      profile: reasoning_api
      fallback_profile: cheap_api
      system_prompt_template: roles/final_judgement.md
```

設定規則:
- `schema_version` は必須とし、初期値は `1` とする。
- 設定優先順位は `explicit init args > env override > config/shigoku.yaml > defaults` とする。
- `profiles` は provider/model/base_url/api_key_env/timeout/temperature/provider固有extraだけを持つ。
- `roles` は用途名、profile、fallback、system prompt template、role単位の上書きだけを持つ。
- `api_key` の生値は YAML に置かず、必ず `api_key_env` で参照する。
- `base_url` は provider または profile に置き、role には置かない。
- `max_retries`, `max_concurrency`, `rate_limit_per_minute` は profile 単位で定義し、roleから直接変更しない。
- `fallback_profile` は循環参照を禁止する。
- role が未定義の場合は `default_role` を使う。ただし security-critical な role は未定義時に fail closed とする。
- legacy flat env (`SHIGOKU_MODEL`, `SHIGOKU_MODEL_OUTPUT`, `SHIGOKU_MODEL_LIGHTWEIGHT`) は互換期間のみ profile 生成に使い、実装完了後の正本にはしない。

## 2.2 現状認識
- [ ] `LLMClient` は `llm_use_local` と `llm_auto_route` を見て、単純タスクを Ollama に回す仕組みを持つ。
- [ ] `LocalLLMProvider` は `ollama/{model}` を litellm に渡す Ollama専用 provider。
- [ ] `MicroAgent`、`log_translator`、`VisualRecon`、`gpu_accelerator` などは Ollama 前提が強く、設定変更だけでは置換できない。
- [ ] 既存の `model_lightweight` / `model_output` / `llm_fallback_model` は方向性として有用だが、用途別/エージェント別の粒度が足りない。
- [ ] `config/features.yaml`、`config/shigoku.yaml`、`.env.example`、`docker-compose.yml`、`src/config.py`、`src/core/config/settings.py` に設定の正本候補が分散している。
- [ ] `src/prompts/` のテンプレート、`src/legacy_prompts.py`、`src/core/engine/conductor_prompts.py`、各 agent の `SYSTEM_PROMPT` / inline system message が混在している。

## 2.3 Ollama依存箇所の洗い出し
- **API直叩き:**
  - `src/core/llm/micro_agent.py`: `self.config.ollama_url + "/api/generate"` を直接POST。
  - `src/core/utils/log_translator.py`: `requests.post(.../api/generate)` でログ翻訳。
  - `src/core/agents/specialized/visual_recon.py`: `OLLAMA_API_BASE` と `/api/generate`、LLaVA/BakLLaVA pull 前提。
- **CLI直叩き:**
  - `src/core/gpu_accelerator.py`: `ollama list`, `ollama pull`, `ollama run`。
  - `tests/integration/test_gpu_features.py`: `ollama list` がある前提の integration test。
- **Ollama provider / auto route:**
  - `src/core/llm/local_provider.py`: `ollama/{model}` と `OLLAMA_API_BASE` を設定。
  - `src/core/llm/__init__.py`: `LocalLLMProvider`, `TaskComplexityClassifier` を公開。
  - `src/core/models/llm.py`: `llm_use_local`, `llm_auto_route`, `LocalLLMProvider`, `TaskComplexityClassifier` を利用。
- **Ollama前提の呼び出し元:**
  - `src/core/rag_module/rag.py`: RAG context compression で `LocalLLMProvider` を生成。
  - `src/intelligence/proxy_log_analyzer.py`: low confidence ranking で `GPUAccelerator.query_ollama()` を利用。
  - `src/core/agents/swarm/base_manager.py`, `src/core/agents/general_agent.py`, `src/core/engine/master_conductor.py`, `src/recon/parallel_tasks.py`: `ollama/qwen3.5:latest` fallback や `model_lightweight` 依存。
- **設定・配布・UI・docs/tests:**
  - `config/features.yaml`: `phase3.micro_agent.model`, `ollama_url`。
  - `.env.example`, `docker-compose.yml`: `OLLAMA_API_BASE`, `SHIGOKU_LOCAL_LLM_MODEL`, Ollama host service コメント。
  - `src/cli/commands.py`, `src/cli/messages.py`, `src/tools/custom/ffuf.py`: Ollama選択肢/説明。
  - `docs/shigoku/manuals/MANUAL_JA.md`, `docs/shigoku/specs/TECHNICAL_SPEC_JA.md`, `docs/shigoku/specs/FEATURE_EXPANSION_PLAN.md`, `docs/shigoku/specs/llm_optimization.md`, `docs/shigoku/roadmaps/future_functions.md`: ユーザー向け/仕様上の Ollama 記述。
  - `docs/shigoku/worklogs/*`: 歴史ログのため原則書き換え対象外。ただし計画上は「歴史的記録」と明記する。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** LLM role、agent_type、model alias、provider、base_url、api_key env、timeout、temperature、fallback。
- **出力/結果 (Output):** 用途別モデル選択、Ollama非依存のLLM呼び出し、設定一元化、prompt一元化、移行対象一覧。
- **制約・ルール:**
  - 既存挙動を一度に壊さない。まずは Ollama直叩きを routing 経由へ寄せる。
  - ユーザーが安価モデルを設定ファイルで選べるようにし、暗黙の complexity 判定に頼らない。
  - role例: `planner`, `advisor`, `swarm_manager`, `worker_llm`, `specialist_light`, `tool_output_analysis`, `rag_compression`, `react`, `reporting`, `final_judgement`, `vision_analysis`。
  - API key は直接ファイルに書かず、env参照または既存secret管理方針に合わせる。
  - provider差異は `LLMClient` / router で吸収し、呼び出し元は role だけを渡す。
  - prompt本文は `src/prompts/` に置き、roleとの対応は `config/shigoku.yaml` だけで変える。
  - active probing / scope enforcement / report schema はこのタスクで変更しない。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 上記 `2.3` の棚卸しを `rg` で再確認し、Ollama 依存を `API直叩き`, `CLI直叩き`, `provider/auto_route`, `fallback文字列`, `docs/tests` に分類する。
- [ ] ステップ2: `from src.config import settings`, `settings.model*`, `settings.local_llm*`, `LLMClient(model=...)`, `SYSTEM_PROMPT`, `{"role": "system"}` の利用箇所を棚卸しし、LLM設定移行対象とprompt移行対象に分類する。
- [ ] ステップ3: 移行フェーズを `Phase 1: 設定schema/validator`, `Phase 2: Ollama直依存除去`, `Phase 3: Swarm/Worker/custom AI移行`, `Phase 4: prompt統一/docs更新` に分け、各Phaseのacceptance criteriaとrollback条件を計画書または作業ログに記録する。
- [ ] ステップ4: 設定優先順位を `explicit init args > env override > config/shigoku.yaml > defaults` と定義し、`llm.schema_version: 1` と失敗モード表（未定義role/profile、API key env未設定、fallback循環、prompt template欠落）を追加する。
- [ ] ステップ5: `src/core/config/settings.py` に nested `LLMSettings` / `LLMProfileSettings` / `LLMRoleSettings` を追加し、`config/shigoku.yaml` と `config/shigoku.yaml.example` に初期 `llm` ブロックを追加する。
- [ ] ステップ6: `profiles` に `timeout_seconds`, `max_retries`, `max_concurrency`, `rate_limit_per_minute`, `temperature`, provider固有 `extra` を持たせ、role側は profile/prompt/fallback/role単位override に限定する。
- [ ] ステップ7: 設定validatorを追加し、fallback循環、未定義profile、security-critical roleの未定義、`api_key_env` 未設定、prompt templateファイル欠落を起動時または設定読み込み時に明示エラーにする。
- [ ] ステップ8: `src/config.py` の LLM 設定を deprecated alias として `get_settings().llm` へ委譲し、旧 `SHIGOKU_MODEL_*` / `model_lightweight` / `model_output` は互換期間だけrole/profileへ変換して警告する。
- [ ] ステップ9: `LLMRoleResolver` / `LLMRouter` / `PromptRenderer` / `LLMClient` の責務境界を定義し、role -> profile -> provider/model/base_url/api_key_env/system_prompt_template/fallback を `LLMRoleResolver` で解決する。
- [ ] ステップ10: `LLMClient` を role-aware にし、`llm_use_local` / `llm_auto_route` / `TaskComplexityClassifier` / `LocalLLMProvider` 依存を廃止または互換層に退避する。
- [ ] ステップ11: LLM呼び出しログに role/profile/provider/model/timeout/fallback発生有無/correlation id を記録し、API keyやsystem prompt本文をログ・例外・キャッシュキーに出さないredactionを追加する。
- [ ] ステップ12: LLMキャッシュや再試行がある場合は、cache key / retry context に role/profile/provider/model/prompt_template_pathまたはhashを含め、role変更後に古い結果が混ざらないようにする。
- [ ] ステップ13: `MicroAgent`, `RAG compress_context`, `proxy_log_analyzer`, `log_translator`, `VisualRecon`, `GPUAccelerator.query_ollama()` を role経由に移し、Ollama API/CLI直叩きをなくす。
- [ ] ステップ14: Swarm manager/Worker/custom AI の `model_lightweight` / `model_output` / `LLMClient(model=...)` を role resolver へ移行する。
- [ ] ステップ15: system prompt 直書き箇所を `src/prompts/` template へ移し、各templateのrequired variablesを定義して、`config/shigoku.yaml` の `llm.roles.*.system_prompt_template` から解決する。
- [ ] ステップ16: `.env.example`, `docker-compose.yml`, CLI/help/docs/tests を更新し、Ollamaを標準前提から外す。manualには旧設定から新設定へのbefore/after、必須env、role別モデル例を追加する。
- [ ] ステップ17: テスト方針を実装する。router単体、設定読み込み、旧flat設定互換、prompt解決、Ollama未導入環境、fallback、rate limit/retry、cache key、secret非露出、observabilityを対象にする。
- [ ] ステップ18: 検索ベースの完了ゲートを実行し、`localhost:11434`, `/api/generate`, `subprocess.*ollama`, `ollama run/list/pull`, `LocalLLMProvider`, `TaskComplexityClassifier`, inline system prompt の未分類残存を0にする。

## 5. 懸念点と対策
※責任者と工数は本計画では扱わない。各対策は `## 4. 実装ステップ` の対応ステップへ組み込む。

### 5.1 SRE/インフラエンジニア視点
- [ ] [SRE-1][発生確率:高][影響度:大] 設定優先順位が曖昧で、環境変数・`config/shigoku.yaml`・既存 `src/config.py` のどれが勝つかで本番挙動が揺れる。対策: 設定優先順位を明文化し、validatorで不整合を検出する（対応: ステップ4, 7, 8）。
- [ ] [SRE-2][発生確率:高][影響度:大] Ollama削除後、既存デプロイが `OLLAMA_*` や `localhost:11434` 前提のまま起動失敗する。対策: 互換期間中は旧設定をrole/profileへ変換して警告し、変換不能な場合は明示エラーにする（対応: ステップ3, 8, 16, 18）。
- [ ] [SRE-3][発生確率:中][影響度:大] Swarm/Workerの並列LLM呼び出しで外部APIのrate limit、timeout、コスト増が起きる。対策: profileにtimeout/retry/concurrency/rate limitを持たせ、role解決後の呼び出しで適用する（対応: ステップ6, 9, 10, 17）。
- [ ] [SRE-4][発生確率:中][影響度:中] 障害時にどのrole/profile/modelで失敗したか追跡できない。対策: secretとprompt本文を除いたLLM呼び出しメタデータとfallback有無をログに残す（対応: ステップ11, 17）。

### 5.2 ソフトウェアアーキテクト視点
- [ ] [ARCH-1][発生確率:高][影響度:大] `LLMRouter` / `LLMClient` が設定解決、prompt解決、API呼び出しを抱え込み巨大化する。対策: `LLMRoleResolver`, `LLMRouter`, `PromptRenderer`, `LLMClient` の責務境界を明記して実装する（対応: ステップ9, 10, 15）。
- [ ] [ARCH-2][発生確率:高][影響度:大] `src/config.py` 利用箇所が広く、互換ラッパー化だけでは移行漏れが残る。対策: import/flat設定参照を棚卸しし、LLM関連のみ先に移して非LLM設定は別タスク扱いにする（対応: ステップ2, 8, 18）。
- [ ] [ARCH-3][発生確率:中][影響度:大] prompt templateのrequired variablesが不明で、role移行後に実行時エラーになる。対策: templateごとのrequired variablesを定義し、render testで検証する（対応: ステップ15, 17）。
- [ ] [ARCH-4][発生確率:中][影響度:中] 設定スキーマの将来変更時に後方互換が壊れる。対策: `llm.schema_version: 1` を導入し、移行判断の基準にする（対応: ステップ4, 5）。

### 5.3 デバッガー視点
- [ ] [DBG-1][発生確率:高][影響度:大] 文字列検索だけではHTTP直叩きやsubprocess経由のOllama依存を見落とす。対策: API URL、CLI、provider、fallback文字列、inline promptを検索ゲートに含め、未分類残存を0にする（対応: ステップ1, 2, 18）。
- [ ] [DBG-2][発生確率:高][影響度:中] 設定ミス時のエラー種別が曖昧で原因特定が遅れる。対策: 失敗モード表を作り、validatorのエラーをrole/profile/template単位で具体化する（対応: ステップ4, 7, 17）。
- [ ] [DBG-3][発生確率:中][影響度:大] LLMキャッシュや再試行がある場合、role/model/prompt変更後に古い結果が混ざる。対策: cache key / retry contextにrole/profile/provider/model/prompt template情報を含める（対応: ステップ12, 17）。
- [ ] [DBG-4][発生確率:中][影響度:中] ハードコードされたsystem promptが一部残っても動いてしまい、統一ルール違反に気づきにくい。対策: inline system prompt検索とrender/golden testを完了ゲートに入れる（対応: ステップ2, 15, 18）。

### 5.4 CTO視点
- [ ] [CTO-1][発生確率:高][影響度:大] Ollama廃止、設定統一、prompt統一、Swarm/Worker移行を一括で進めるとリリースリスクが大きい。対策: Phase 1-4に分割し、各Phaseのacceptance criteriaとrollback条件を記録する（対応: ステップ3）。
- [ ] [CTO-2][発生確率:中][影響度:大] ユーザー向け移行手順が不足し、導入時に設定ミスや問い合わせが増える。対策: manualに旧設定から新設定へのbefore/after、必須env、role別モデル例を追加する（対応: ステップ16）。
- [ ] [CTO-3][発生確率:中][影響度:大] 特定プロバイダ名に設計が寄ると、将来のモデル変更やコスト最適化が難しくなる。対策: roleは用途名、profileは `cheap_api`, `reasoning_api`, `vision_api` など用途別aliasを正にし、vendor差異はprovider/profileに閉じ込める（対応: ステップ5, 6, 9）。
- [ ] [CTO-4][発生確率:低][影響度:大] system prompt外出しにより、セキュリティ方針やスキャン挙動が意図せず変わる。対策: active probing / scope enforcement / report schemaは本タスクで変更しない方針を維持し、prompt変更は差分テスト対象にする（対応: ステップ15, 17）。

### 5.5 既存リスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] Ollama直叩きが残ると設定統一しても実行時にOllamaへ接続する - 直叩き一覧を移行チェックリストにする。
- [ ] [重要度:中] role別モデルが増えると設定が複雑になる - まず必須roleだけに絞る。
- [ ] [重要度:中] 既存の `model_lightweight` 等との互換 - deprecated alias として一定期間残す。
- [ ] [重要度:中] providerごとのAPI差異 - litellm互換を優先し、例外は adapter に閉じ込める。
- [ ] [重要度:中] prompt template と role mapping がずれるとエージェント挙動が変わる - roleごとの golden prompt/render test を追加する。
- [ ] [重要度:中] `src/config.py` 利用箇所が多く、一括削除は危険 - まず LLM 関連だけを移し、非LLM設定は別タスクで扱う。
- [ ] [重要度:低] docs/worklogs の歴史的 Ollama 記述まで消すと監査履歴が壊れる - worklogs は原則そのまま、manual/spec/env/docker を更新対象にする。

## 6. 検証方針
- **対象ユニットテスト:**
  - `.venv/bin/pytest -q tests/core/llm/test_llm_client.py`
  - `.venv/bin/pytest -q tests/core/test_settings.py tests/core/test_config_yaml.py`
  - `.venv/bin/pytest -q tests/core/agents/swarm/test_base_manager.py`
- **追加/更新するテスト:**
  - role/profile 設定読み込みと env override。
  - `api_key_env` がログ・例外・キャッシュキーに生値として出ないこと。
  - role未定義時の `default_role` fallback と security-critical role の fail closed。
  - system prompt template の解決、存在しないtemplate時の明示エラー。
  - Ollama未導入環境でも `LLMClient`, `MicroAgent`, RAG圧縮, Proxy log ranking, VisualRecon初期化がOllamaへ接続しないこと。
  - 旧 `SHIGOKU_MODEL_*` / `model_lightweight` / `model_output` 互換が設定された期間だけ効くこと。
- **検索ベースの検証:**
  - `rg -n "Ollama|ollama|OLLAMA|OLLAMA_API_BASE|localhost:11434|/api/generate|ollama run|ollama list|ollama pull|subprocess.*ollama|LocalLLMProvider|TaskComplexityClassifier" src config tests .env.example docker-compose.yml`
  - `rg -n '"role": "system"|SYSTEM_PROMPT|system_prompt|You are|あなたは' src tests`
  - 残存箇所は「廃止予定の互換層」「歴史的docs」「テスト名」のいずれかに分類して、未分類を0にする。
- **ドキュメント検証:**
  - `python3 scripts/sync_shigoku_updated_at.py`
  - `python3 scripts/validate_shigoku_docs.py`

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0292-D01
    title: "継続監視: LLM role/model 設定の実運用チューニング"
    reason: "本タスクでは設計方針を固め、具体モデルの最適化は実運用を見て継続調整する"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "初期role設定で数回実行し、コスト・品質・遅延を比較して設定を更新する"
```
