---
task_id: SGK-2026-0311
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0291
related_docs:
- docs/shigoku/subtasks/2026-06-23_sgk-2026-0291_swarm-parallelism-review_subtask_plan.md
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-0_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-1-additive-execution-contract-debug-metadata_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-3-dispatch-context-isolation-swarm-pool_subtask_plan.md
- docs/shigoku/reports/2026-06-27_sgk-2026-0311_work_report.md
- docs/shigoku/worklogs/2026-06-27_sgk-2026-0311_work_log.md
title: 'Swarm並列化 Phase 2: scope admission と per-origin budget policy'
created_at: '2026-06-26'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/core/engine/parallel_orchestrator.py, src/core/security/ethics_guard.py,
  config/shigoku.yaml
---

# 実装計画書：Swarm並列化 Phase 2: scope admission と per-origin budget policy

## 1. 達成したいゴール（ユーザー視点）
- [ ] 並列化前に、scope / admission / per-origin budget を共通policyとして導入すること。
- [ ] `ParallelOrchestrator` が Task object文字列ではなく正規化originでrate limitできること。
- [ ] scope unknown / out-of-scope / origin_key欠落の active・mutating・aggressive 実行をfail closedにすること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/parallel_orchestrator.py`: `ParallelTask` のtarget/origin明示化とrate limit接続。
  - `src/core/security/ethics_guard.py`: scope unknown時のactive操作fail closed方針。
  - `config/shigoku.yaml`: `parallelism` 設定正本。
  - `src/core/config/` / `src/config.py`: config validation 接続候補。
  - `tests/`: admission / budget / config validation の単体テスト。
- **データの流れ / 依存関係:**
  - Task metadata -> ActionAdmissionPolicy -> ExecutionBudgetPolicy -> ParallelOrchestrator rate limiter -> execution / rejection audit。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `origin_key`、`target_key`、lane、scope verdict、target risk tier、parallelism config。
- **出力/結果 (Output):** admission decision、budget decision、reject reason、rate limit wait、protective degrade signal（Phase 2 では signal 検出と structured 記録に留め、protective degrade mode の回路遮断実装は Phase 7 へ deferred）。
- **制約・ルール:**
  - `read_only` 以外は scope unknown でfail closed。
  - `mutating` / `aggressive_exclusive` は allowlist、explicit flag、audit trail が揃うまで実行不可。
  - `parallelism.enabled=false`、`shadow_mode=true`、`mutating.enabled=false`、`aggressive_exclusive.enabled=false` を初期defaultにする。
  - `config/shigoku.yaml` の `parallelism` セクション不在時は全 default 安全値で起動する（fail-safe startup）。不正な値（workers=0 等）で起動時 validation error にする。
  - 403/406/429等のblocking signalは検出・structured記録し、protective degrade mode への信号を emit する。回路遮断の action 実装は Phase 7 に deferred。
- **橋渡し契約（Task ↔ ParallelTask）:**
  - Phase 1 で `Task.metadata["origin_key"]` が追加済みだが、`ParallelOrchestrator` が使う `ParallelTask` は別構造体で `origin_key` も `metadata` も持たない（explorer 実コード確認済み）。
  - `create_parallel_task()` の全呼び出し箇所で `Task.metadata` → `ParallelTask` への origin_key / target_key / lane / scope 伝播を実装する。
  - origin_key は `normalize_origin_key(url: str) -> str` で正規化する: scheme（lowercase）+ host（lowercase）+ port（default port は省略）、path/fragment/query を含まない。例: `"HTTPS://Example.COM:443/path"` → `"https://example.com"`。

## 4. 実装ステップ（AIに指示する手順）

### 4.0 最小影響アプローチ（設計方針・必須遵守）
本 Phase は以下5原則で実装し、既存コード・呼び出し元・後続フェーズへの波及を最小化する:
1. **additive-only**: 既存 field・シグネチャは変更せず、default 付き追加のみ。`ParallelTask` への field 追加、`create_parallel_task()` の kwargs 追加は全て default 値付き。
2. **新規層の分離**: `ethics_guard.py` / `enhanced_ethics_guard.py` は一切触らない。`ActionAdmissionPolicy` / `ExecutionBudgetPolicy` / `normalize_origin_key()` は新規クラス・新規モジュールとして分離し、既存 fail-open 挙動と既存テストを保持する。
3. **compat-first bridge**: `create_parallel_task()` に default 付き kwargs（`origin_key=None`, `target_key=None`, `lane=None`, `scope_verdict="unknown"`）を追加し、既存呼び出し元（MasterConductor 等）は一行も変更しない。`origin_key` が渡されない既存パスは後方互換で動く。
4. **category → lane 自動推論**: 呼び出し元に lane 指定を強要しない。`create_parallel_task()` 内部で既存 `category` から lane を推論する。`mutating`/`aggressive` に倒れる category は Phase 2 default（`mutating.enabled=false`）で自動 reject され、fail-closed が効く。
5. **fail-safe startup**: `parallelism` セクション不在でも `ParallelismSettings` の Pydantic default で起動する。

**category → lane マッピング（Step 1 で実装）:**
```python
CATEGORY_TO_LANE = {
    "intel_passive":   "read_only",
    "intel_active":    "read_only",      # passive と同格で安全側
    "attack_auth":     "mutating",
    "attack_inject":   "mutating",
    "local":           "read_only",
    "default":         "read_only",
}
# create_parallel_task() 内: lane = lane or CATEGORY_TO_LANE.get(category, "read_only")
```

**影響範囲マッピング:**
- 変更（既存ファイル）: `parallel_orchestrator.py`（field 追加 + admission 呼び出し + origin_key 渡し）、`settings.py`（`ParallelismSettings` 追加）
- 新規ファイル: admission policy、budget policy、origin normalizer、テストファイル群
- 一切触らない: `ethics_guard.py`、`enhanced_ethics_guard.py`、MasterConductor、EntryGateFacade、既存 config、既存 `create_parallel_task()` 呼び出し元全部、Phase 3-9 計画書

**実装順序（TDD・各ステップ独立）:**
1. T-0.1 characterization test 追加（baseline 固定、コード変更なし）
2. `normalize_origin_key()` + T-1.2（新規モジュール、既存コード触らない）
3. `ParallelTask` field 追加 + `create_parallel_task()` default kwargs + category→lane map（LB-1解消）
4. `ParallelismSettings` + T-3.1/T-3.2/T-3.3（LB-7解消）
5. `ActionAdmissionPolicy` + T-2.1〜T-2.8（LB-2/LB-4解消、EthicsGuard 非変更）
6. `ExecutionBudgetPolicy` + T-4.1〜T-4.3（origin_key 渡しを rate limiter へ接続）
7. `BlockingSignalEvent` 記録フック + T-5.1/T-5.2（LB-6解消、回路遮断なし）
8. T-6.1/T-6.2 で Phase 1 回帰確認

- [ ] ステップ0（事前調査）: **EthicsGuard 影響範囲の列挙と admission policy 配置設計**
  - `src/core/security/ethics_guard.py` で scope unknown 時に `ALLOWED` を返す全呼び出し箇所（`check_action`、`_check_rate_limit`、`_check_http_request`、`_check_dns_lookup`）を列挙する。
  - `ActionAdmissionPolicy` を新設の独立層にするか、既存 `EthicsGuard` に `scope_verdict: Literal["in_scope","out_of_scope","unknown"]` を追加するかの設計判断を行う。
  - 決定基準: 既存 `EthicsGuard` の呼び出し元（`_trigger_post_exploit()`、`_dispatch_scope_verification_fast_path()`）に admission を差し込むと scope 未設定の serial 実行全体がブロックされるリスクがあるため、原則として `ActionAdmissionPolicy` は `create_parallel_task()` 内に独立層として配置する。
  - 既存 `ParallelOrchestrator` の category-based rate limit + semaphore 挙動を固定する **characterization test** を追加する（`test_existing_parallel_orchestrator_baseline`）。
- [ ] ステップ1: **`origin_key` / `target_key` の橋渡しと正規化（最小影響）**
  - `create_parallel_task()` の全呼び出し箇所を grep で特定するが、**呼び出し元は変更しない**。シグネチャに `origin_key: str | None = None`、`target_key: str | None = None`、`lane: str | None = None`、`scope_verdict: str = "unknown"` を default 付きで追加し、既存呼び出し（`category` のみ指定）は後方互換で動く。
  - `lane` が未指定の場合は `CATEGORY_TO_LANE.get(category, "read_only")` で自動推論する（4.0 のマッピング表参照）。
  - `normalize_origin_key(target_url: str) -> str` を新規モジュール（例: `src/core/engine/origin_normalizer.py`）に実装する（scheme + host lowercase + port、default port は省略、path/fragment/query を含まない）。`tests/` に正規化のユニットテストを追加する（T-1.2）。
  - `origin_key` 渡し時のみ正規化を適用し、既存の `ptask.kwargs.get("target")` → `str(target)` パスは compat fallback として残す。`test_parallel_task_origin_key_bridge`（T-1.1）で、`Task(metadata={"origin_key":"https://example.com"})` → `ParallelTask.origin_key` への伝播と、metadata 欠落時の None fallback を検証する。
- [ ] ステップ2: **`ActionAdmissionPolicy` と `ExecutionBudgetPolicy` の実装（新規独立層）**
  - `ActionAdmissionPolicy` は**新規クラス**として実装し、`ethics_guard.py` は一切変更しない（LB-2 の最小影響解消）。`create_parallel_task()` 本体内で admission check を呼び、fail-fast かつ queue slot 消費前に reject する（LB-4 の最小影響解消: 呼び出し元を変えずに fail-fast を両立）。
  - `ActionAdmissionPolicy.check(origin_key, target_key, lane, scope_verdict) -> AdmissionDecision` を新規ファイル（例: `src/core/engine/admission_policy.py`）に配置する。
  - `AdmissionDecision` は `allowed: bool`、`reason_code: str`（`"scope_unknown"`、`"out_of_scope"`、`"origin_key_missing"`、`"mutating_not_allowlisted"`、`"aggressive_not_allowlisted"`）、`message: str` を含む dataclass とする。
  - lane 別判定: `read_only` は scope unknown/origin_key 欠落でも allow。その他（`stateful_read`、`mutating`、`aggressive_exclusive`）は scope unknown または out-of-scope または origin_key 欠落で reject。`mutating`/`aggressive_exclusive` はさらに allowlist + explicit flag の確認を必須にする。
  - `ExecutionBudgetPolicy.consume(origin_key: str) -> BudgetDecision` を新規ファイル（例: `src/core/engine/budget_policy.py`）に実装し、per-origin の rpm/burst/max_inflight 予算と cooldown を管理する。`BudgetDecision` は `allowed: bool`、`wait_seconds: float`、`reason_code: str` を含む。serial mode 前提で thread-safe は保証不要（D-6 で Phase 5 に deferred）。
- [ ] ステップ3: **`config/shigoku.yaml` に `parallelism` セクション追加**
  - `src/core/config/settings.py` に `ParallelismSettings` Pydantic モデルを追加する。フィールド: `enabled: bool = False`、`shadow_mode: bool = True`、`default_executor: str = "serial"`、`lane_workers: dict[str, int] = {}`、`per_origin_budget: PerOriginBudgetSettings`、`kill_switch: KillSwitchSettings`、`risk_tier_defaults: dict[str, RiskTierDefault]`。
  - `PerOriginBudgetSettings`: `rpm: int = 30`、`burst: int = 10`、`max_inflight: int = 2`、`cooldown_seconds: float = 1.0`。
  - `mutating: MutatingLaneSettings(enabled: bool = False, allowlist: list[str] = [])`。
  - `aggressive_exclusive: AggressiveLaneSettings(enabled: bool = False, allowlist: list[str] = [])`。
  - `parallelism` セクション不在時は全 default 安全値で起動する（fail-safe startup）。不正な値で起動時 validation error（fail-closed）。`extra="ignore"` のままでは unknown key が無視されるため、モデル追加後に Pydantic が型検証を行う。
- [ ] ステップ4: **`ParallelOrchestrator` rate limiter 入力を正規化 origin へ変更**
  - 既存 `ptask.kwargs.get("target")` からの target 抽出（parallel_orchestrator.py:197-198）を、`ptask.origin_key` を使用するように変更する。
  - `AdaptiveRateLimiter.wait()` の `target` パラメータに `ptask.origin_key`（正規化文字列）を渡す。既存の `str(target)` 渡しとの互換性を保つ fallback を入れる。
  - `max_inflight` の runtime enforcement は Phase 5（実並列化開始時）に deferred。Phase 2 では config schema の定義のみ。
- [ ] ステップ5: **reject reason の structured 記録と protective degrade signal 検出**
  - scope unknown / out-of-scope / origin_key欠落 / budget超過 / mutating not allowlisted / aggressive not allowlisted の reject reason を `AdmissionDecision.reason_code` と `BudgetDecision.reason_code` に enum-like な定数で記録する。
  - 403/406/429 の blocking signal を `BlockingSignalEvent(status_code: int, origin_key: str, timestamp: float)` として structured に記録する。protective degrade mode の回路遮断 action は Phase 7 に deferred。
- [ ] ステップ6: **テスト実行と回帰確認**
  - TDDチェックリスト（Section 6.3）の全テストを実装・実行する。
  - Phase 1 回帰テスト（`Task.metadata` serialization、session reader、report reader）が全 PASS することを確認する。
  - `python3 scripts/sync_shigoku_updated_at.py` + `python3 scripts/validate_shigoku_docs.py` を実行し 0 エラーを確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
### 5.1 SRE / インフラ観点
- [ ] [重要度:高] scope unknown で fail open すると実害が大きい - active 以上は fail closed をテストで固定する。
- [ ] [重要度:高] origin_key 欠落時に default bucket へ集中する - 欠落時は read_only 以外 reject し、read_only も明示的な safe fallback のみ許可する。
- [ ] [重要度:高] `Task.metadata["origin_key"]`（Phase 1 成果物）が `ParallelTask` に伝播しないと budget も admission も機能しない - `create_parallel_task()` の全呼び出し箇所で橋渡しを実装する（explorer 調査で両者が別構造体であることを確認済み）。
- [ ] [重要度:高] admission policy の配置場所を誤ると EthicsGuard の scope 未設定時に既存 serial 実行全体がブロックされる - Step 0 で影響範囲を列挙し、`ActionAdmissionPolicy` を独立層として配置する。
- [ ] [重要度:高] origin_key 正規化が曖昧だと rate limit が効かない - `normalize_origin_key()` の仕様（scheme+host+port、lowercase、default port 省略）を Step 1 で固定する。
- [ ] [重要度:中] config が増えて運用ミスが起きる - default deny と validation error message を明確にする。`parallelism` セクション不在時は safe default で起動する。
- [ ] [重要度:中] `AdaptiveRateLimiter` が `time.sleep()` で blocking している - Phase 2 では既存のまま正規化 origin 渡しで対応し、async 化は Phase 5 に deferred。

### 5.2 ソフトウェアアーキテクト観点
- [ ] [重要度:高] `ActionAdmissionPolicy` と既存 `EthicsGuard` の責務境界が曖昧 - `ActionAdmissionPolicy` は pre-execution admission（scope/lane/origin 判定）、`EthicsGuard` は per-action runtime check（HTTP request、DNS lookup、command execution）と明確に分離する。
- [ ] [重要度:高] `ExecutionBudgetPolicy` の状態管理（per-origin カウンタ）が thread-safe でないと将来の並列化で破綻する - シングルスレッド serial mode 前提で設計し、Phase 5 で thread-safe 化することを明記する。
- [ ] [重要度:中] `parallelism` config の `extra="ignore"` がモデル追加前の unknown key を無視する - `ParallelismSettings` を Settings クラスの field に追加するまで YAML の `parallelism:` ブロックは無視されることを認識する。
- [ ] [重要度:中] `max_inflight` の runtime enforcement は Phase 2 では不要（serial mode 前提）。config schema 定義だけ行い、enforcement は Phase 5 に送る。

### 5.3 デバッガー観点
- [ ] [重要度:高] admission / budget reject 時に reason code が空だと原因追跡が困難 - `AdmissionDecision.reason_code` と `BudgetDecision.reason_code` を enum-like 定数で必須記録する。
- [ ] [重要度:高] 既存 `ParallelOrchestrator` にテストがゼロのまま admission/budget を導入すると baseline が失われる - Step 0 で characterization test を先に追加する。
- [ ] [重要度:中] protective degrade signal が記録されても action が追跡できない - `BlockingSignalEvent` を structured に保存し、Phase 7 で action 実装時に過去 signal を参照できるようにする。
- [ ] [重要度:中] `origin_key` が metadata dict 経由のため、欠落・誤値が runtime まで検出されない - Phase 2 admission gate で明示的に reject し、欠落時は structured reason を残す。

### 5.4 ハッカー / バグバウンティツール開発者観点
- [ ] [重要度:高] admission で reject された task が黙って消えると coverage gap に気づけない - reject reason + origin_key + task_id を session/debug record に保存し、Phase 4 shadow decision で事後検証可能にする。
- [ ] [重要度:中] per-origin budget が厳しすぎると有効な attack path を探索できない - 初期 default（rpm=30, burst=10）は保守的に設定し、Phase 5 shadow compare で調整する。
- [ ] [重要度:中] blocking signal（403/429）を無視すると WAF に検知され target への全アクセスが遮断される - signal 検出・記録を必須にし、Phase 7 protective degrade 実装までに signal 履歴を蓄積する。

### 5.5 CTO観点
- [ ] [重要度:高] 本 Phase が admission/budget を導入しても `parallelism.enabled=false` のままでは実効性の検証ができない - 親計画 4.4 Go 条件に「scope unknown で active/mutating/aggressive が admission reject される」を追記し、shadow 観測で admission 判定の正しさを検証する。
- [ ] [重要度:高] admission policy の判定ロジックが lane の定義に依存するが、lane 分類は Phase 4 まで確定しない - Phase 2 では lane を `read_only` / `stateful_read` / `mutating` / `aggressive_exclusive` の4分類と仮置きし、Phase 4 で再調整することを明記する。
- [ ] [重要度:中] `config/shigoku.yaml` が各 Phase で追記されると設定正本としての一貫性が失われる - `parallelism` セクションを集約点とし、Phase 2-9 を通じてこのセクションに追記する方針を親計画へ提案する（PCR）

### 5.6 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0311-D01
    title: "継続監視: admission / budget policy のfail-closed維持"
    reason: "後続フェーズでlaneが増えるとpolicy抜けが起きやすい"
    impact: medium
    tracking_task_id: SGK-2026-0311
    recommended_next_action: "新lane追加時にscope unknown / origin_key欠落の拒否テストを追加する"
```

---

## 6. 実装前レビュー結果（2026-06-27）

### 6.1 Phase要約
- **目的:** Phase 1 で追加された Task 識別子（`origin_key`、`target_key` 等）を活用し、scope / admission / per-origin budget を共通 policy として導入する。scope unknown / out-of-scope / origin_key 欠落の active・mutating・aggressive 実行を fail-closed にし、`ParallelOrchestrator` の rate limiter を正規化 origin で制御可能にする。
- **Non-Goals:** 並列度変更、protective degrade mode 回路遮断実装（Phase 7）、lane scheduler 実装（Phase 4）、dispatch context isolation（Phase 3）、SwarmDispatcher/SwarmManager 並列化（Phase 8）。
- **前提条件:** Phase 0（並列/直列正本化）と Phase 1（Task.metadata 追加）が完了済み。Phase 1 で `origin_key` / `target_key` / `canonical_endpoint_key` / `schema_version` が Task.metadata map に保存され、欠落時 default が固定済みであること。
- **完了条件:** scope 不明・out-of-scope・origin_key 欠落の active/mutating/aggressive task が admission gate で実行前に拒否される。`parallelism.enabled=false` で serial mode が従来互換。`config/shigoku.yaml` の `parallelism` セクション不在時は safe default で起動。不正な config 値で起動時 validation error。

### 6.2 Ready / Not Ready
- **判定（2026-06-27 更新）: Conditional Ready — 最小影響アプローチ（Section 4.0）を採用する条件付きで実装開始可。**
- 変更理由: 当初 Not Ready とした 7 Blocker は全て「既存コード・呼び出し元・後続フェーズを変えない additive + 新規層分離」で解消できることが判明した。核心は **category → lane 自動推論** を導入し、既存の `create_parallel_task(task_id, func, ..., category="intel_passive")` 呼び出しを一行も変えずに admission を走らせる点（Section 4.0）。
- 最小影響の検証根拠（explorer 実コード確認ベース）:
  - `ethics_guard.py` / `enhanced_ethics_guard.py` は触らない → 既存 fail-open 挙動と既存テスト（`tests/unit/security/test_ethics_guard.py` 88行）は保持される。
  - `create_parallel_task()` の既存呼び出し元（MasterConductor 等）は default 付き kwargs 追加で後方互換 → 呼び出し元修正ゼロ。
  - `parallelism` セクション不在でも `ParallelismSettings` の Pydantic default で起動 → 既存 config / `src/config.py` は変更不要。
  - admission は `create_parallel_task()` 本体内で呼び、fail-fast かつ queue slot 消費前に reject → 呼び出し元を変えずに fail-fast を両立。
  - `mutating` に倒れる category（`attack_auth`/`attack_inject`）は Phase 2 default（`mutating.enabled=false`）で自動 reject され、fail-closed が効く。
- **実装開始の条件（いずれも Section 4.0 / 6.3 / 6.4 に組み込み済み）:**
  1. TDDを厳守し、T-0.1 characterization test を最初に固定して baseline を確保する。
  2. EthicsGuard は一切変更せず、`ActionAdmissionPolicy` / `ExecutionBudgetPolicy` / `normalize_origin_key()` を新規ファイルへ分離する。
  3. `create_parallel_task()` への追加は全て default 付き kwargs とし、既存呼び出し元を変更しない。
  4. 各ステップが独立してテスト可能で、途中で止めても serial 実行が壊れないことを T-6.1/T-6.2 で確認する。
- **残リスク（実装中に No-Go に戻す条件）:** characterization test で既存挙動との差分が発覚した場合、または category→lane マッピングが既存 serial 実行をブロックすることが判明した場合は実装を止めて再評価する。

### 6.3 Local Blocker（実装時最初に解決・最小影響解消法併記）
- [x] **LB-1: `Task` → `ParallelTask` の origin_key 橋渡しが未定義。** Phase 1 は `Task.metadata["origin_key"]` を追加したが、`ParallelOrchestrator` が使う `ParallelTask` には `origin_key` も `metadata` もない別構造体である（explorer 1章）。**最小影響解消:** `ParallelTask` に `origin_key: str | None = None` 等 additive 追加、`create_parallel_task()` に default 付き kwargs 追加。既存呼び出し元（MasterConductor 等）は修正ゼロで後方互換。category → lane 自動推論で admission が機能する（Step 1）。
- [x] **LB-2: EthicsGuard が scope unknown で fail-open する構造が admission の fail-closed と矛盾する。** `check_action()`（L118）: `_enabled=False` → ALLOWED。`_check_rate_limit()`（L161）: `not self.scope` → ALLOWED。`_check_http_request()`（L185）: 同様。**最小影響解消:** `ethics_guard.py` / `enhanced_ethics_guard.py` は一切触らない。`ActionAdmissionPolicy` を新規独立クラス（新規ファイル）へ。既存 fail-open 挙動と既存テスト（`tests/unit/security/test_ethics_guard.py`）は保持される（Step 0/Step 2）。
- [x] **LB-3: origin_key 正規化の責務と導出ロジックが未定義。** Phase 1 deferred にも「origin 正規化が曖昧だと rate limit/mutex が効かない - Phase 2 開始前に正規化責務を固定する」とある。**最小影響解消:** `normalize_origin_key()` を新規モジュール（`src/core/engine/origin_normalizer.py`）へ。origin_key 渡し時のみ適用、既存 `str(target)` パスは compat fallback で残す。既存 rate limiter ロジックは変更なし（Step 1）。
- [x] **LB-4: admission policy の実行タイミングが未確定。** `EntryGateFacade` は環境 readiness 確認で task-level admission とは別責務。**最小影響解消:** `create_parallel_task()` 本体内で admission check を呼ぶ。fail-fast（queue slot 消費前に reject）かつ呼び出し元を変えない。`_wait_for_slot()` 方式より fail-fast 性が高い（Step 2）。
- [x] **LB-5: `parallel_orchestrator` に既存テストがゼロのまま admission+budget を導入する baseline がない。** テストファイルが存在しない（explorer 5章）。**最小影響解消:** characterization test（T-0.1）を最初に1つ追加。既存挙動固定のみで実装コードへの影響ゼロ（Step 0）。
- [x] **LB-6: protective degrade signal の Phase 2 実装範囲が不明確。** **最小影響解消:** Phase 2 では `limiter.on_response()`（既存メソッド）に `BlockingSignalEvent` 記録フック1本追加。回路遮断ロジックは作らない（Phase 7 deferred）。既存 on_response 挙動は保持（Step 5）。
- [x] **LB-7: `parallelism` セクション不在時の default 挙動が未定義。** `extra="ignore"` で unknown key が無視される。**最小影響解消:** `ParallelismSettings` Pydantic モデルを全 field safe default 付きで `settings.py` に追加。セクション不在でも default 起動。既存 config / `src/config.py` は変更不要（Step 3）。

### 6.4 TDDチェックリスト
- [ ] **T-0.1: `test_existing_parallel_orchestrator_baseline`** — 現行 category-based rate limit + semaphore 挙動を固定する characterization test。`ParallelOrchestrator._get_semaphore("default")` が正しい worker 数の Semaphore を返すこと、`_get_rate_limiter("intel_passive")` が正しいカテゴリの limiter を返すこと。
- [ ] **T-1.1: `test_parallel_task_origin_key_bridge`** — `Task(metadata={"origin_key":"https://example.com"})` から `create_parallel_task()` 経由で `ParallelTask.origin_key` に値が伝播すること。
- [ ] **T-1.2: `test_origin_key_normalization`** — `"HTTPS://Example.COM:443/path"` → `"https://example.com"` に正規化。`"http://sub.example.com:8080/x"` → `"http://sub.example.com:8080"`。scheme なし → ValueError。
- [ ] **T-2.1: `test_scope_unknown_fail_closed_active`** — lane=mutating, scope=unknown → `AdmissionDecision(allowed=False, reason_code="scope_unknown")`
- [ ] **T-2.2: `test_scope_unknown_fail_closed_aggressive`** — lane=aggressive_exclusive, scope=unknown → rejected
- [ ] **T-2.3: `test_scope_unknown_allowed_read_only`** — lane=read_only, scope=unknown → `AdmissionDecision(allowed=True)`
- [ ] **T-2.4: `test_origin_key_missing_fail_closed`** — origin_key=None, lane=active → rejected, reason_code="origin_key_missing"
- [ ] **T-2.5: `test_origin_key_missing_safe_fallback_read_only`** — origin_key=None, lane=read_only → allowed with default bucket
- [ ] **T-2.6: `test_mutating_without_allowlist_rejected`** — lane=mutating, allowlist に origin なし → rejected
- [ ] **T-2.7: `test_mutating_with_allowlist_allowed`** — lane=mutating, allowlist に origin あり, scope=in_scope → allowed
- [ ] **T-2.8: `test_out_of_scope_rejection`** — target=out-of-scope URL, lane=active → rejected, reason_code="out_of_scope"
- [ ] **T-3.1: `test_parallelism_config_default_safe`** — `parallelism` セクション不在の YAML → `ParallelismSettings(enabled=False, shadow_mode=True)` で parse される
- [ ] **T-3.2: `test_parallelism_config_invalid_fail_closed`** — workers=0 や rpm=-1 等の不正値 → Pydantic ValidationError
- [ ] **T-3.3: `test_parallelism_config_yaml_roundtrip`** — YAML に全 field 定義 → `ParallelismSettings` parse → 全値が正しい
- [ ] **T-4.1: `test_per_origin_budget_enforcement`** — 同一 origin の task を budget 超過で投入 → 超過分が reject される
- [ ] **T-4.2: `test_per_origin_budget_different_origins_independent`** — 異なる origin は別予算で管理される
- [ ] **T-4.3: `test_budget_reset_cooldown`** — cooldown 経過後に予算がリセットされる
- [ ] **T-5.1: `test_blocking_signal_detection_403`** — 403 response → `BlockingSignalEvent(status_code=403)` が structured に記録される
- [ ] **T-5.2: `test_blocking_signal_detection_429`** — 429 response → blocking signal 記録
- [ ] **T-6.1: `test_phase1_regression_metadata_unchanged`** — Phase 1 の Task.metadata serialization、session reader、report reader が Phase 2 変更後も動作
- [ ] **T-6.2: `test_phase1_regression_serial_mode`** — `parallelism.enabled=false` → 既存 serial 実行テストが全 PASS

### 6.5 Go/No-Go Gate
- [ ] **Go:** scope unknown で active/mutating/aggressive lane の task が `ActionAdmissionPolicy` に reject される（T-2.1, T-2.2）。
- [ ] **Go:** origin_key 欠落で active/mutating/aggressive lane の task が reject される（T-2.4）。read_only は safe fallback（T-2.5）。
- [ ] **Go:** `mutating` / `aggressive_exclusive` は allowlist + explicit flag が揃わないと reject される（T-2.6）。allowlist あり + scope in_scope で allow（T-2.7）。
- [ ] **Go:** out-of-scope target の active/mutating/aggressive lane task が reject される（T-2.8）。
- [ ] **Go:** per-origin budget 超過時に reject され、structured reason code が記録される（T-4.1, T-5.1, T-5.2）。
- [ ] **Go:** `parallelism.enabled=false` で serial mode が従来通り動作する（T-6.2）。
- [ ] **Go:** `config/shigoku.yaml` の `parallelism` セクション不在時に safe default（enabled=false, shadow_mode=true, mutating.enabled=false, aggressive_exclusive.enabled=false）で起動する（T-3.1）。
- [ ] **Go:** 不正な config 値で起動時 Pydantic ValidationError になる（T-3.2）。
- [ ] **Go:** T-0.1 から T-6.2 の全テストが PASS。
- [ ] **Go:** Phase 1 回帰テスト全 PASS（T-6.1, T-6.2）。
- [ ] **Go:** `python3 scripts/sync_shigoku_updated_at.py` 後に `python3 scripts/validate_shigoku_docs.py` が 0 エラー。
- [ ] **No-Go (未該当確認):** scope unknown で active/mutating/aggressive が admission を通過する（fail-open 回帰）。
- [ ] **No-Go (未該当確認):** origin budget bypass が可能（admission gate 前の execution）。
- [ ] **No-Go (未該当確認):** 既存 serial 実行が壊れる（`parallelism.enabled=false` で task 実行不可）。
- [ ] **No-Go (未該当確認):** admission reject 時に reason_code が空または ambiguous。
- [ ] **No-Go (未該当確認):** Phase 1 metadata 互換性破壊（既存 artifact reader が落ちる）。

### 6.6 Shadow / Differential Testing
- [ ] **S-1: admission decision shadow** — 実 admission 判定を記録しつつ、`parallelism.enabled=false` 状態で全 task を実行し、admission が reject した task が本当に scope unknown / out-of-scope / origin_key 欠落かを事後検証する。
- [ ] **S-2: budget counter shadow** — 実予算消費なしで per-origin リクエスト数をカウントし、budget 超過仮説を検証する（実 enforcement は Phase 2 で行うが、shadow で budget design の妥当性を確認）。
- [ ] **S-3: config differential** — 旧 config（parallelism セクションなし）と新 config（あり）で起動し、default 値適用時の起動結果が同一であることを確認する。
- [ ] **S-4: rate limiter bridge differential** — 旧 `str(target)` 渡しと新正規化 origin 渡しで同一の rate limit 制御結果になることを確認する（target が hostname のみで port や fragment を含まないケース）。

### 6.7 Local Deferred（後続Phaseへ送る）
| # | 項目 | Deferred先 | 安全な理由 | 検出方法 |
|---|---|---|---|---|
| D-1 | Protective degrade mode 回路遮断実装 | Phase 7 (SGK-2026-0316) | Phase 2 は信号検出と記録のみ。serial mode 前提なので回路遮断せずとも危険はない | Phase 7 で reauth 競合、state mutation assertion、protective degrade test を追加 |
| D-2 | Per-origin `max_inflight` の runtime enforcement | Phase 5 (SGK-2026-0314) | Phase 2 は serial mode 前提なので inflight=1 が保証される。config schema 定義のみ Phase 2 で行う | Phase 5 で origin budget violation test を追加 |
| D-3 | Connection pool / socket budget | Phase 5 (SGK-2026-0314) | Phase 2 は task レベル admission+budget のみ。connection 枯渇は実並列化開始時に顕在化 | Phase 5 で connection budget assertion test を追加 |
| D-4 | `AdaptiveRateLimiter` の `time.sleep()` → async 化 | Phase 5 (SGK-2026-0314) | Phase 2 では既存 blocking limiter のまま正規化 origin 渡しで動作可能 | Phase 5 で async rate limit 回帰テストを追加 |
| D-5 | Lane scheduler との接続（lane 別 worker 割当） | Phase 4 (SGK-2026-0313) | Phase 2 は admission gate と budget のみ。lane 判定は Phase 4 | Phase 4 で lane classification unit test を追加 |
| D-6 | `ExecutionBudgetPolicy` の thread-safe 化 | Phase 5 (SGK-2026-0314) | Phase 2 は serial mode 前提で、per-origin counter への同時アクセスは発生しない | Phase 5 で concurrent budget enforcement test を追加 |

### 6.8 Parent Change Request（親計画へ反映提案）
- [x] **PCR-1（親計画へ昇格済み: 2026-06-27）:** 親計画 4.1 に `ParallelTask` と `Task` の橋渡し契約を追加する。`Task.metadata` → `ParallelTask` への origin_key/target_key/lane/scope 伝播は全 Phase の共通責務であり、`create_parallel_task()` 経由の伝播ルールを親計画に明記すべき。→ 親計画 4.1 Target identity 節へ統合済み。
- [x] **PCR-2（親計画へ昇格済み: 2026-06-27）:** 親計画 4.1 に `normalize_origin_key()` の仕様（scheme + host lowercase + port、default port 省略、path 含まない）を定義する。origin 正規化は Phase 2-7 全般で共有される。→ 親計画 4.1 Target identity 節へ統合済み。
- [ ] **PCR-3（不採用: 重複）:** 親計画 4.4 の Go/No-Go gate に「scope unknown で active/mutating/aggressive が admission reject される」を Go 条件として追加する。→ 不採用。親計画 4.4 No-Go条件「scope unknown で active/mutating/aggressive が実行される」（行178相当）と同一内容であり、Phase固有の完了条件ではなく全体No-Goとして既存のため。

### 6.9 Out of Scope（本Phaseでは実装しない）
- [ ] Protective degrade mode 回路遮断（signal 記録は Phase 2、action は Phase 7）
- [ ] Lane scheduler（lane 判定・mutex は Phase 4、lane 別 worker 割当は Phase 5）
- [ ] Per-origin `max_inflight` runtime enforcement（Phase 5）
- [ ] Connection pool / socket budget（Phase 5）
- [ ] `AdaptiveRateLimiter` の非同期化（Phase 5）
- [ ] SwarmDispatcher / SwarmManager の並列度変更（Phase 8）
- [ ] dispatch context isolation（Phase 3 — 別モジュール、独立実装可能）
- [ ] `TaskState` enum への `admitted` / `invalidated` 等の追加（Phase 1 で deferred 済み）

### 6.10 Phase順序再レビュー
- **Phase 0 → Phase 1:** ✅ done。Phase 0 の並列/直列正本化完了、Phase 1 の metadata 基盤追加済み。
- **Phase 1 → Phase 2:** ⚠️ 順序は妥当だが、Phase 1 の output（`Task.metadata`）→ Phase 2 の input（`ParallelTask`）への橋渡し契約が両 Phase の計画書で明示されていない。Phase 1 deferred にも「origin 正規化が曖昧」と記録あり。→ PCR-1 / PCR-2 で親計画へ反映提案済み。Phase 2 内で `create_parallel_task()` 経由の橋渡しを実装する（Step 1）。
- **Phase 2 → Phase 3:** ✅ 異なるファイル群を対象とするため独立実装可能。ただし Phase 3 の context isolation は Phase 2 の admission gate とは責務境界が明確に分かれているため、Phase 順序を入れ替えても支障なし。
- **Phase 2 → Phase 4:** ✅ Phase 4 の shadow scheduling は Phase 2 の `origin_key`、`AdmissionDecision`、`BudgetDecision` に依存する。Phase 2 完了は Phase 4 の前提として正しい。
- **Phase 2 → Phase 5-9:** ✅ 実並列化（Phase 5）は admission/budget 完了後でなければ危険。Phase 順序は全体として正当。
- **結論:** Phase 順序は壊れていない。実際の依存関係にも適合している。
