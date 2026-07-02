---
task_id: SGK-2026-0335
doc_type: manual
status: active
parent_task_id: SGK-2026-0282
related_docs:
  - docs/shigoku/specs/2026-07-01_sgk-2026-0335_bug-bounty-program-bundle-guard-policy-contract.md
  - docs/shigoku/specs/2026-07-02_sgk-2026-0335_enforcement-points-and-killswitch.md
  - docs/shigoku/subtasks/done/2026-07-01_bug-bounty-scope-bundle-guard-policy-compile_subtask_plan.md
created_at: '2026-07-02'
updated_at: '2026-07-02'
---

# Bug Bounty Bundle Operator Runbook

## 1. Bundle Import to Run: Standard Flow

### 1.1 Step-by-Step

1. **Collect raw program data**: ブラウザから HackerOne / Bugcrowd の program page を開き、
   policy text と scope 情報を保存する。
   - HackerOne: policy.md + scope_assets.csv
   - Bugcrowd: policy.md + scope_assets.txt

2. **Create `source_manifest.yaml`**:
   ```yaml
   schema_version: 1
   provider: hackerone  # or bugcrowd
   program_name: TikTok
   captured_at_utc: "2026-07-02T10:00:00Z"
   default_timezone: "UTC"
   bundle_id: "h1-tiktok-2026-07-02T10:00:00Z"
   policy_path: "policy.md"
   scope_sources:
     - kind: hackerone_csv
       path: "scope_assets.csv"
   ```

3. **Place files in a bundle directory**:
   ```
   program_bundle/
     source_manifest.yaml
     policy.md
     scope_assets.csv
     review_findings.yaml   # can be empty: review_findings: []
     overrides.yaml          # can be empty: overrides: {}
   ```

4. **Validate**
   ```bash
   python -m src.main --mode bugbounty --bundle-dir /path/to/bundle --target example.com --dry-run
   ```
   Dry-run は compile まで実行し、compile status を報告する。status が `ready` でなければ
   run は開始されない。

5. **Resolve manual review findings**
   - `review_findings.yaml` に `blocking=true` の pending finding がある場合、
     compile status は `manual_review_required` になる。
   - 各 finding の `status` を `accepted` / `dismissed` / `overridden` に変更し、
     必要なら `overrides.yaml` に補正を記述する。
   - 再 compile で status が `ready` になれば run 可能。

6. **Run**
   ```bash
   python -m src.main --mode bugbounty --program tiktok --target https://www.tiktok.com
   ```

### 1.2 Quick Start (Ad Hoc)

```bash
python -m src.main --mode bugbounty \
  --bundle-dir /path/to/program_bundle \
  --target https://www.tiktok.com \
  --enforcement-stage shadow_read_only
```

`--bundle-dir` は transport shortcut であり、内部的に import + compile を行い、
`compile_status=ready` の場合のみ run を開始する。runtime bypass ではない。

`--enforcement-stage` で rollout stage を指定できる（default: `mc_only`）。

## 2. Manual Review Runbook

### 2.1 When Manual Review is Required

以下のいずれかに該当する場合、compile status は `manual_review_required` になる：

- `blocking=true` の review finding が `pending`
- 同一 specificity の allow/deny conflict が override なしで残る
- temporal rule の日時解釈が不能

### 2.2 Resolution Flow

1. **View pending findings**
   ```bash
   python -m src.main --mode bugbounty --bundle-dir /path --show-findings
   ```
   出力には以下が含まれる：
   - `finding_id`: 安定 ID（e.g. `H1-AMB-001`）
   - `subject`: 該当 asset / rule の識別子
   - `source_refs`: 元の policy text / CSV 行
   - `machine_guess`: 機械抽出の推測結果
   - `recommended_override_path`: 推奨 override skeleton

2. **Review each finding**
   - Finding が正しい → `status: accepted` に変更
   - Finding が誤検出 → `status: dismissed` に変更
   - Finding に手動補正が必要 → `status: overridden` に変更し、対応する override を `overrides.yaml` に記述

3. **Update `review_findings.yaml`**:
   ```yaml
   review_findings:
     - finding_id: H1-AMB-001
       category: temporal_scope
       subject: "https://developers.tiktok.com/minis/"
       risk_level: high
       source_refs:
         - "policy.md#temporary-exclusion"
       machine_guess:
         effect: deny
       status: accepted
       blocking: false
   ```

4. **Apply overrides** (if needed):
   ```yaml
   overrides:
     scope:
       deny_url_prefixes:
         - "https://developers.tiktok.com/minis/"
   ```

5. **Recompile and verify**
   ```bash
   python -m src.main --mode bugbounty --bundle-dir /path --compile-only
   ```
   compile status が `ready` になるまで繰り返す。

### 2.3 Suggested Override Skeleton

Operator 向けの override skeleton 例：
```yaml
overrides:
  scope:
    allow_hosts: []
    deny_hosts: []
    allow_url_prefixes: []
    deny_url_prefixes: []
  attack_classes:
    social_engineering: {mode: deny}
    dos: {mode: deny}
    post_exploit: {mode: deny}
    ssrf: {mode: allow_with_constraints, allowed_destinations: []}
  auth: {allowed_email_domains: []}
  budgets: {requests_per_minute: 60}
```

## 3. Orphan Bundle and Prune Operations

### 3.1 Bundle Lifecycle

| State | Description |
|-------|------------|
| Imported | Bundle exists on disk, not yet compiled |
| Compiled | `compiled_guard_policy.yaml` generated |
| Active | `active_bundle.json` points to this bundle as runtime policy |
| Superseded | Newer bundle activated; old bundle kept for audit/rollback |
| Orphan | Bundle directory exists but not referenced by any active mapping or registry |

### 3.2 Retention Policy (V1)

- **Named bundle**: 自動削除しない。rollback / audit 用に保持。
- **Superseded named bundle**: 同上。
- **Ephemeral bundle** (`--bundle-dir` ad-hoc 使用): TTL 7 日。
- **Compiled artifact**: 常に bundle directory と同一のライフサイクル。

### 3.3 Prune Procedure

```bash
# Dry-run: show what would be removed
python -m src.main --mode bugbounty --prune --dry-run

# Prune expired ephemeral bundles
python -m src.main --mode bugbounty --prune
```

Prune の対象:
- 期限切れ ephemeral bundle（TTL 7 日超過）
- Orphan compiled artifact（参照切れの compiled_guard_policy.yaml）

Prune の除外対象:
- Active bundle とその upstream（rollback 用に保持）
- Named bundle（V1 では永続保持）

### 3.4 Orphan Detection

```bash
python -m src.main --mode bugbounty --list-orphans
```

以下を検出する:
- `active_bundle.json` が指す bundle directory が存在しない
- `compiled_guard_policy.yaml` が破損・欠落
- Registry に登録されているが disk 上に存在しない bundle

## 4. Shadow to Enforcement Transition

### 4.1 Rollout Stages

| Stage | MC blocks? | Worker blocks? | Network blocks? | External blocks? | Metrics |
|-------|-----------|----------------|-----------------|------------------|---------|
| `shadow_read_only` | ❌ | ❌ | ❌ | ❌ | `guard_decision_total{reason_code=shadow_*}` が全層で増加 |
| `mc_only` (default) | ✅ | ❌ | ❌ | ❌ | MC 層の block が実際に発生 |
| `worker_external_hard` | ✅ | ✅ | ✅ | ✅ | 全層 hard block |

### 4.2 Transition Procedure

**Phase 1: Shadow (read-only)**
```bash
SHIGOKU_GUARD_ENFORCEMENT_STAGE=shadow_read_only \
  python -m src.main --mode bugbounty --program tiktok --target https://www.tiktok.com
```
- 全 enforcement point が evaluator を呼び出す（metrics が記録される）
- 判定結果はすべて `allow` に変換される（実際の実行は妨げない）
- `guard_decision_total{reason_code=shadow_*}` の増加を観測する

**Phase 2: MC Only**
```bash
# default: mc_only — 環境変数設定不要
python -m src.main --mode bugbounty --program tiktok --target https://www.tiktok.com
```
- MC 層での block が有効化される
- 他層は shadow 継続
- `guard_decision_total{layer=mc,decision=block}` の発生を観測する

**Phase 3: Full Enforcement (Hard)**
```bash
SHIGOKU_GUARD_ENFORCEMENT_STAGE=worker_external_hard \
  python -m src.main --mode bugbounty --program tiktok --target https://www.tiktok.com
```
- 全層で hard block が有効化
- 全 enforcement point で block 判定が実際の実行を停止する

### 4.3 Transition Readiness Criteria

Stage を進める前に以下を確認する：

| Metric | Threshold | Stage Gate |
|--------|-----------|------------|
| `active_bundle_read_failure_total` | 0 | shadow → mc_only |
| `compile_failed_total` (直近 24h) | 0 | mc_only → hard |
| `guard_decision_total{layer=mc,decision=block}` の reason_code 分布 | 想定外の reason_code なし | mc_only → hard |
| `guard_decision_total{reason_code=shadow_*}`（他層） | 期待する block 判定と一致 | 全段階 |

### 4.4 Emergency Rollback (Kill Switch)

```bash
# Stage を即時 downgrade
SHIGOKU_GUARD_ENFORCEMENT_STAGE=shadow_read_only \
  python -m src.main --mode bugbounty --program tiktok ...

# または前バージョンの bundle に rollback
python -m src.main --mode bugbounty --bundle-id <previous-bundle-id> --target ...
```

Kill switch と bundle rollback は独立に操作可能。

### 4.5 Resume / Retry Compatibility

- デフォルト: 前回 run と同じ `bundle_id` / `policy_id` を引き継ぐ
- 明示 rebind: `--bundle-id <new-id>` で新しい policy を使用
- Snapshot 不一致が safety に影響する場合は fail-closed
