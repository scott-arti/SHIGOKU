---
task_id: SGK-2026-0335
doc_type: spec
status: active
parent_task_id: SGK-2026-0282
related_docs:
  - docs/shigoku/subtasks/done/2026-07-01_bug-bounty-scope-bundle-guard-policy-compile_subtask_plan.md
  - docs/shigoku/subtasks/2026-06-21_sgk-2026-0282_bug-bounty-scope-control_subtask_plan.md
  - docs/shigoku/specs/bug_bounty_enhancements.md
  - docs/shigoku/specs/modules/ETHICS_GUARD.md
created_at: '2026-07-01'
updated_at: '2026-07-02'
---

# Specification: Bug Bounty Program Bundle and Guard Policy Contract

## 1. Purpose

Bug bounty program の自然文ポリシー、構造化 scope、手動補正を SHIGOKU が V1 で安定して受け取り、
`compiled_guard_policy.yaml` という単一の実行正本に compile するための契約を定義する。

この spec の目的は、次の 3 点を固定することにある。

1. どの形式でプログラム情報を渡すか
2. 曖昧点をどう人手補正するか
3. 実行時にどの層がどの compiled policy を必ず参照するか

## 2. Scope and Non-Goals

### In Scope

- `program_bundle/` のディレクトリ契約
- `source_manifest.yaml` の必須項目
- HackerOne / Bugcrowd 入力の adapter 境界
- `review_findings.yaml` と `overrides.yaml` の schema
- `compiled_guard_policy.yaml` の最小 schema
- precedence, fail-closed, temporal rule の扱い
- runtime consumer に渡す guard decision contract

### Out of Scope for V1

- HackerOne / Bugcrowd API からの自動同期
- 報酬額や過去 bounty を用いた ROI ランキング
- runtime 中に自然文を再解釈する専用 AI judge
- full automatic な曖昧性解消

## 3. Lifecycle and Roles

### 3.1 Lifecycle

1. Operator が bug bounty program の snapshot を `program_bundle/` として保存する
2. Provider adapter が bundle を読み、normalized facts を生成する
3. Reviewer が `review_findings.yaml` を確認し、必要なら `overrides.yaml` を更新する
4. Compiler が `compiled_guard_policy.yaml` を生成する
5. MC、manager、worker、外部アクセスモジュールは raw source を読まず compiled policy だけを使う

### 3.2 Roles

- Operator: raw input の収集と bundle 化
- Adapter: provider 固有形式を normalized facts に変換
- Reviewer: 曖昧点の承認、却下、override 指定
- Compiler: precedence を適用して runtime 正本を生成
- Runtime consumer: compiled policy を参照して allow / block / requires_hitl / degrade を返す

### 3.3 Responsibility Separation Matrix

| Concern | Single writer / owner | Downstream consumers | Forbidden shortcut |
| --- | --- | --- | --- |
| raw source snapshot | Operator | Adapter | runtime が raw source を直接読む |
| provider normalization | Adapter | Reviewer, Compiler | adapter が final runtime verdict を確定する |
| precedence and policy compile | Compiler | Evaluator, activation preflight | MC / worker が独自 precedence を持つ |
| runtime guard evaluation | Shared evaluator | MC, manager, worker, external access modules | layer ごとに別々の rule engine を持つ |
| orchestration and phase control | MC / manager / worker | runtime execution | orchestration 層が compiled policy を改変する |
| transport execution | external access modules | target systems | evaluator を通さずに外部アクセスする |

- `review_findings.yaml` と raw provider text は compile-time artifact であり、runtime 参照を禁止する
- runtime layer は context を補うことはできるが、判定自体は単一の shared evaluator を通す
- shared evaluator は同一 `policy_id` + 同一 `guard_input` に対して deterministic な `guard_decision` を返さなければならない

## 4. Program Bundle Directory Contract

### 4.1 Canonical Form

V1 では bug bounty input の正本を chat text ではなく `program_bundle/` ディレクトリとして受け渡す。

```text
program_bundle/
  source_manifest.yaml
  policy.md
  scope_assets.csv        # HackerOne系の構造化scopeがある場合
  scope_assets.txt        # Bugcrowd系のTargets抽出テキスト、またはinline scope切り出し
  review_findings.yaml
  overrides.yaml
```

### 4.2 Required Files

- `source_manifest.yaml`: required
- `policy.md`: required
- `review_findings.yaml`: required
- `overrides.yaml`: required
- `scope_assets.csv` or `scope_assets.txt`: at least one required

`review_findings.yaml` と `overrides.yaml` は空でもよいが、ファイル自体は必ず存在させる。
空の場合の最小形は次とする。

```yaml
review_findings: []
```

```yaml
overrides: {}
```

### 4.3 Invariants

- 1 bundle は 1 program の 1 snapshot を表す
- bundle 内の時刻は source 上の表現を保持してよいが、compile 時に UTC へ正規化する
- runtime は bundle 内 raw source を直接読んではならない
- raw source, review, override のいずれかが変わったら compile をやり直す

## 5. `source_manifest.yaml` Contract

### 5.1 Required Fields

```yaml
schema_version: 1
provider: hackerone
program_name: TikTok
captured_at_utc: "2026-07-01T07:38:38Z"
default_timezone: "UTC"
bundle_id: "h1-tiktok-2026-07-01T07:38:38Z"
policy_path: "policy.md"
scope_sources:
  - kind: hackerone_csv
    path: "scope_assets.csv"
raw_source_urls:
  - "https://hackerone.com/tiktok"
```

### 5.2 Semantics

- `provider`: `hackerone` or `bugcrowd`
- `captured_at_utc`: bundle 収集日時。RFC3339 UTC
- `default_timezone`: source text に timezone が明記されない場合の解釈基準
- `bundle_id`: 同一 bundle を追跡する安定 ID
- `scope_sources`: compile 入力として読む scope source 一覧
- `raw_source_urls`: provenance 用。runtime では使わない

### 5.3 Validation Rules

- `provider` と `scope_sources.kind` の組み合わせが不正なら compile failed
- `policy_path` が存在しなければ compile failed
- `scope_sources` が 0 件なら compile failed

## 6. Provider Adapter Contract

### 6.1 Shared Adapter Responsibilities

provider adapter の責務は次の 4 つに限定する。

1. provider 固有入力の妥当性確認
2. raw facts の抽出
3. provider 非依存の normalized facts への変換
4. manual review が必要な曖昧点の列挙

adapter は final allow / block verdict を確定しない。
precedence の適用と `compiled_guard_policy.yaml` 生成は compiler の責務である。

また adapter は `EthicsGuard` や `MasterConductor` へ直接設定を流し込んではならない。
adapter の出力は必ず compiler を経由する。

### 6.1.1 Deterministic Processing Order

すべての provider adapter は以下の順序で処理する。

1. bundle shape validation
2. source load
3. provider-local fact extraction
4. asset normalization
5. rule candidate normalization
6. review candidate generation
7. extraction audit emission

この順序を守ることで、同じ bundle からは常に同じ normalized facts が得られることを期待する。

### 6.1.2 Shared Adapter Output

すべての provider adapter は次の normalized facts を返す。

```yaml
adapter:
  name: hackerone_program_adapter
  version: 1
program:
  provider: hackerone
  program_name: TikTok
source_inventory: []
assets: []
rule_candidates: []
review_candidates: []
extraction_audit: []
```

#### `source_inventory[]`

- `kind`: `policy_text | structured_scope | extracted_scope_block`
- `path`
- `source_ref_root`
- `loaded`: bool
- `parse_status`: `ok | warning | failed`

`source_inventory` は「何を読んだか」の一次記録であり、runtime には流さない。

#### `assets[]`

- `asset_id`: 安定 ID
- `raw_identifier`: 元の識別子
- `canonical_key`: compiler が比較に使う正規化キー
- `asset_kind`: `host_exact | host_wildcard | url_prefix | mobile_app | other`
- `runtime_surface`: `http | mobile | non_runtime`
- `submission_allowed`: bool
- `bounty_allowed`: bool
- `max_severity`: `none | low | medium | high | critical`
- `temporal_window`: optional
- `provider_metadata`: optional dict
- `source_ref`: `scope_assets.csv#row=12` のような参照

#### `rule_candidates[]`

- `rule_id`
- `category`: `attack_class | phase | budget | path | destination | auth | temporal_scope`
- `decision`: `allow | deny | requires_hitl`
- `subject`
- `constraints`
- `origin_type`: `policy_text | structured_scope | derived`
- `specificity`: `broad | medium | exact`
- `source_ref`

#### `review_candidates[]`

- `finding_id`
- `category`
- `subject`
- `machine_guess`
- `risk_level`
- `blocking`
- `recommended_override_path`
- `source_refs`

#### `extraction_audit[]`

- `step`
- `status`
- `summary`
- `source_refs`

### 6.1.3 Shared Normalization Rules

- host comparison は lowercase canonical host で行う
- wildcard は `*.example.com` 形式へ正規化する
- URL prefix は scheme を保持した canonical URL で保存する
- 時刻は parse 成功時に UTC へ正規化し、失敗時は review candidate を生成する
- `Focus Areas` や `Asset Priorities` のような優先度情報は runtime allow rule とみなさない
- `Safe Harbor` や disclosure policy は原則として runtime guard rule に変換しない
- provider text から security testing の禁止・制限が抽出できる場合のみ runtime rule candidate を生成する

### 6.2 HackerOne Adapter Rules

HackerOne adapter は `policy.md` と `scope_assets.csv` を読む。

### 6.2.1 Authoritative Sources

- asset 境界の正本: `scope_assets.csv`
- behavioral rule の正本: `policy.md`
- 両者の conflict 解消: compiler + review/override

`instruction` 列や program highlights の記述は補助情報として扱うが、
明示的な submission eligibility や explicit temporary exclusion を上書きする allow source にはしない。

### 6.2.2 Required CSV Columns

- `identifier`
- `asset_type`
- `instruction`
- `eligible_for_bounty`
- `eligible_for_submission`
- `availability_requirement`
- `confidentiality_requirement`
- `integrity_requirement`
- `max_severity`

required column が欠落している場合は compile failed とする。

### 6.2.3 Mapping Rules

- `asset_type=URL` かつ `identifier` が `https://` / `http://` で始まる場合:
  `asset_kind=url_prefix`
- `asset_type=URL` かつ host 形式の場合:
  `asset_kind=host_exact`
- `asset_type=WILDCARD` または `identifier` が `*.` を含む場合:
  `asset_kind=host_wildcard`
- `GOOGLE_PLAY_APP_ID`, `APPLE_STORE_APP_ID`:
  `asset_kind=mobile_app`

- `eligible_for_submission=true` なら scope allow candidate を生成する
- `eligible_for_submission=false` なら deny candidate を生成する
- mobile app asset は inventory へ残すが、HTTP runtime guard の allow list には直接入れない

### 6.2.4 H1 Policy Text Extraction Rules

HackerOne policy text から最低限次を抽出する。

- temporary exclusion / exclusion date
- social engineering prohibition
- DoS / privacy violation / service disruption prohibition
- test account requirement
- internal resource access prohibition
- SSRF 特例ルール
- known issue cutoff date

抽出結果は次のように変換する。

- `social engineering` -> `attack_class:social_engineering=deny`
- `DoS` / `service disruption` -> `attack_class:dos=deny`
- `privacy violations` -> `attack_class:privacy_harm=deny`
- `stop there and report immediately` -> `phase:post_exploit=deny`
- SSRF sheriff only -> `destination:ssrf_allowlist=allow`, `destination:ssrf_other=deny`

### 6.2.5 H1 Review Candidate Triggers

- `eligible_for_submission=false` は hard deny 候補として扱う
- `eligible_for_bounty=false` かつ `eligible_for_submission=true` は `submission only / no bounty` として記録する
- policy text 中の temporary exclusion は structured scope をさらに狭める deny rule として扱う

次の場合は review candidate を必ず生成する。

- wildcard allow と explicit deny row が同じ family に混在する
- text 上の temporary exclusion と CSV deny row の対象表記がずれる
- timezone つき日時の parse が不能
- `impact required` のような runtime guard に直接落ちない曖昧文

### 6.2.6 TikTok-Class Example Expectations

TikTok 系 sample では少なくとも次が出力されること。

- `*.tiktok.com` -> allow asset
- `https://developers.tiktok.com/minis/` -> deny asset or temporal deny candidate
- `*tiktokv.us` / `*us.tiktokv.com` -> deny asset
- `ssrf-bait.byted.org` sheriff 系のみ SSRF destination allow candidate
- `social_engineering`, `dos`, `post_exploit` deny candidates

### 6.3 Bugcrowd Adapter Rules

Bugcrowd adapter は `policy.md` を必須で読み、必要に応じて `scope_assets.txt` を補助入力に使う。

### 6.3.1 Authoritative Sources

- in-scope target 境界の正本: `Targets` セクション
- behavioral rule の正本: `Out of Scope`, `Excluded Submission Types`, `Credentials`, `N-day Policy`
- `Focus Areas` は優先度ヒントであり、runtime allow rule ではない
- `Safe Harbor` は法務・運用文脈であり、runtime allow rule ではない

### 6.3.2 Extraction Targets

- `Targets` セクションの exact host / URL
- `Focus Areas`
- `Excluded Submission Types`
- `Out of Scope`
- `Credentials`
- `Safe Harbor`
- `N-day/Third party 0-day Policy`

### 6.3.3 Target Normalization Rules

- listed host / URL だけを in-scope asset として生成する
- wildcard が書かれていない限り、unlisted subdomain は allow しない
- `sb-console-api.fireblocks.io` のような exact host は `asset_kind=host_exact`
- `https://...` の fully qualified target は `asset_kind=url_prefix`

### 6.3.4 Bugcrowd Text Mapping Rules

- `Targets` に列挙されていない subdomain は暗黙 allow しない
- `Third party providers and services` は deny rule を生成する
- `Potential post-exploitation scenarios ... stop testing and submit` は `post_exploit=deny` を生成する
- credential 条件は `auth` category rule として出力する

次も変換対象とする。

- `DoS/DDoS/Network DoS` -> `attack_class:dos=deny`
- `Rate limiting bypass attempts` -> `attack_class:rate_limit_bypass=deny`
- `P5 vulnerabilities` -> reward exclusion metadata として保持し、runtime deny rule にはしない
- `N-day after 14 days` -> `attack_class:third_party_n_day` の conditional candidate として生成

### 6.3.5 Bugcrowd Review Candidate Triggers

次の場合は review candidate を必ず生成する。

- `Targets` から host と path を一意に切り分けられない
- `N-day` 判定に必要な公開日が bundle 内 source だけでは確定できない
- focus area が allow なのか merely preferred area なのか text から断定できない
- credential requirement が email domain 制約なのか invite-only 制約なのか不明確

### 6.3.6 Fireblocks-Class Example Expectations

Fireblocks 系 sample では少なくとも次が出力されること。

- `sb-console-api.fireblocks.io`, `sb-mobile-api.fireblocks.io`, `sandbox-api.fireblocks.io` の exact allow asset
- unlisted Fireblocks subdomain の implicit deny posture
- `post_exploit=deny`
- `dos=deny`, `rate_limit_bypass=deny`
- `allowed_email_domains=bugcrowdninja.com`

### 6.4 Adapter Failure and Escalation Rules

次の場合は adapter 自身が `failed` を返してよい。

- required source file 欠落
- provider-specific required section / required column 欠落
- source encoding 破損で読取不能

次の場合は adapter 成功 + review candidate 生成とする。

- 一部の rule 文が曖昧
- temporal rule の一部だけ人手確認が必要
- priority / reward 文が guard rule へ写像不能

### 6.5 Step 2 Acceptance Criteria

Step 2 完了時点では少なくとも次を満たす。

- HackerOne sample から structured assets と policy-derived deny candidates が同時に出る
- Bugcrowd sample から `Targets` based asset list と text-derived deny/auth candidates が同時に出る
- adapter 出力だけで manual review 箇所が列挙される
- adapter 自身は final runtime policy を確定しない

## 7. Human Review Files

### 7.1 `review_findings.yaml`

`review_findings.yaml` は機械抽出が迷った点を保持する。runtime は直接参照しない。

```yaml
review_findings:
  - finding_id: H1-AMB-001
    category: temporal_scope
    subject: "https://developers.tiktok.com/minis/"
    risk_level: high
    source_refs:
      - "policy.md#temporary-exclusion"
      - "scope_assets.csv#row=32"
    machine_guess:
      effect: deny
      effective_from_utc: "2026-02-22T22:49:06Z"
    status: pending
    blocking: true
    note: "text and csv are consistent, but temporal handling must be reviewed"
```

#### Required Fields

- `finding_id`
- `category`
- `subject`
- `risk_level`
- `source_refs`
- `machine_guess`
- `status`
- `blocking`

#### Allowed `status`

- `pending`
- `accepted`
- `dismissed`
- `overridden`

### 7.2 Compile Gate on Review Findings

- `blocking=true` かつ `status=pending` の finding が 1 件でもあれば compile status は `manual_review_required`
- `blocking=false` の pending finding は compile を止めないが audit に残す

### 7.3 `overrides.yaml`

`overrides.yaml` は reviewer の最終判断を明示する。runtime へ届くのは override 適用後の compiled policy だけである。

```yaml
overrides:
  scope:
    allow_hosts:
      - "api.example.com"
    deny_hosts:
      - "internal.example.com"
    allow_url_prefixes: []
    deny_url_prefixes:
      - "https://developers.tiktok.com/minis/"
  attack_classes:
    social_engineering:
      mode: deny
    dos:
      mode: deny
    post_exploit:
      mode: deny
    ssrf:
      mode: allow_with_constraints
      allowed_destinations:
        - "https://ssrf-bait.byted.org/full-read-ssrf"
        - "https://ssrf-bait.byted.org/blind-ssrf/*"
  auth:
    allowed_email_domains:
      - "bugcrowdninja.com"
  budgets:
    requests_per_minute: 60
```

## 8. Compiler Precedence and Fail-Closed Rules

### 8.1 Precedence

rule の優先順位は次のとおり。

1. Human override
2. Explicit deny
3. More specific match
4. Structured asset allow
5. Policy-derived broad allow
6. Default deny

### 8.2 Specificity Rules

- `url_prefix deny` は同じ host wildcard allow より優先
- `host_exact deny` は同じ wildcard allow より優先
- temporal deny が有効期間内なら同じ asset の static allow より優先

### 8.3 Fail-Closed Conditions

次のいずれかに該当した場合、compile status は `manual_review_required` または `compile_failed` となり、
Bug Bounty runtime を開始してはならない。

- required file 欠落
- provider / source kind 不整合
- in-scope asset が 0 件
- blocking review finding が pending
- 同一 specificity の allow/deny conflict が override なしで残る
- temporal rule の日時解釈が不能

## 9. `compiled_guard_policy.yaml` Contract

### 9.1 Top-Level Schema

```yaml
schema_version: 1
compile_status: ready
bundle_id: "bbp-hackerone-tiktok-2026-07-01T07:38:38Z-ab12cd34"
policy_id: "bbp:hackerone:tiktok:2026-07-01T07:38:38Z"
provider: hackerone
program_name: TikTok
program_alias: "tiktok"
compiled_at_utc: "2026-07-01T08:10:00Z"
normalized_facts_hash: "sha256:..."
compiled_policy_hash: "sha256:..."
default_decision: deny
compatibility:
  min_reader_schema_version: 1
  backward_compatible_with:
    - 1
scope:
  allow_hosts: []
  deny_hosts: []
  allow_url_prefixes: []
  deny_url_prefixes: []
  non_http_assets: []
rules:
  phases: {}
  attack_classes: {}
  auth: {}
  budgets: {}
review_gate:
  manual_review_required: false
  blocking_findings: []
audit:
  source_hashes: {}
  compile_inputs: {}
  rule_origins: []
```

### 9.2 Required Semantics

- `default_decision` は V1 では常に `deny`
- `compile_status != ready` の policy は runtime へ渡してはならない
- `non_http_assets` は mobile app など runtime HTTP guard が直接評価しない asset を保持する
- `audit.rule_origins` は、どの source からどの runtime rule が作られたかを説明できなければならない
- `bundle_id` は immutable snapshot identity として扱い、同一 run 中に差し替えてはならない
- `program_alias` は mutable な運用名であり、active mapping の解決にのみ使う

### 9.3 Deterministic Identity and Compatibility

- 同一 `program_bundle/`、同一 `review_findings.yaml` 解決状態、同一 `overrides.yaml`、同一 compiler version からは、同一 `normalized_facts_hash` と同一 `compiled_policy_hash` が得られなければならない
- `normalized_facts_hash` は source manifest、policy text、scope source、override 適用前に compile 結果へ影響する review state を入力に含める
- `compiled_policy_hash` は compiled policy payload 全体と `schema_version` を入力に含める
- V1 の schema 変更方針は additive change 優先とし、field rename / removal のような breaking change は migration helper と reader audit なしでは許可しない
- runtime reader は `schema_version` と `compatibility.min_reader_schema_version` を確認し、未対応 version なら fail-closed しなければならない

### 9.4 Rule Origin and Audit Trace

`audit.compile_inputs` は少なくとも次を保持する。

- `manifest_hash`
- `policy_hash`
- `scope_hashes`
- `review_findings_hash`
- `overrides_hash`

`audit.rule_origins[]` は少なくとも次を保持する。

- `rule_origin_id`
- `runtime_rule_id`
- `origin_type`
- `source_ref`
- `subject`
- `decision`
- `review_finding_ids`
- `override_paths`
- `normalization_notes`

`rule_origin_id` は runtime decision から raw source まで逆引きできる安定 ID とする。

### 9.5 Temporal Rules

compiled policy は `effective_from_utc` / `effective_to_utc` を rule 単位で保持してよい。
日時解釈は必ず UTC へ正規化する。

## 10. Runtime Guard Decision Contract

runtime consumer は compiled policy を読み、少なくとも次の入力を guard evaluator に渡す。

```yaml
guard_input:
  bundle_id: "bbp-bugcrowd-fireblocks-2026-02-12T13:49:31Z-ef56aa01"
  policy_id: "bbp:bugcrowd:fireblocks:2026-02-12T13:49:31Z"
  target: "https://sb-console-api.fireblocks.io/api/v1/..."
  host: "sb-console-api.fireblocks.io"
  target_kind: "url"
  phase: "recon"
  attack_class: "sqli"
  method: "GET"
  requested_action: "http_probe"
  proposed_tool: "browser"
  auth_context: {}
  budget_snapshot: {}
  enforcement_layer: "worker"
```

返却値は次の形とする。

```yaml
guard_decision:
  decision: allow
  reason_code: in_scope_exact_host
  matched_rule_ids:
    - "scope.host.allow.1"
  matched_rule_origin_ids:
    - "origin.scope_assets.row12"
  source_refs:
    - "scope_assets.txt#line=18"
  policy_id: "bbp:bugcrowd:fireblocks:2026-02-12T13:49:31Z"
  bundle_id: "bbp-bugcrowd-fireblocks-2026-02-12T13:49:31Z-ef56aa01"
  decision_trace_id: "gd-20260701-000001"
  enforcement_layer: "worker"
  fail_closed: false
```

### Allowed `decision`

- `allow`
- `block`
- `requires_hitl`
- `degrade_to_report`

### Mandatory Enforcement Layers

- MC: task 作成前
- manager: 派生 task 発行前
- worker: 実行直前
- external access module: HTTP / browser / subprocess / external tool 実行直前

### Required `guard_input` Fields

- `bundle_id`
- `policy_id`
- `target`
- `host`
- `phase`
- `attack_class`
- `requested_action`
- `proposed_tool`
- `budget_snapshot`
- `enforcement_layer`

### Required `guard_decision` Fields

- `decision`
- `reason_code`
- `matched_rule_ids`
- `matched_rule_origin_ids`
- `policy_id`
- `bundle_id`
- `decision_trace_id`
- `enforcement_layer`
- `fail_closed`

### Runtime Fail-Closed Semantics

- compiled policy が unreadable、hash mismatch、schema unsupported、または evaluator internal error の場合は `block` を返す
- layer wrapper は evaluator error を local allow へ変換してはならない
- `fail_closed=true` の decision では `reason_code` に `policy_unavailable`, `policy_integrity_error`, `policy_schema_unsupported` などの machine-readable code を使う

## 11. CLI Delivery Timing and Entry Contract

### 11.1 Primary Design

V1 の推奨設計は、raw source を直接 runtime 引数で大量に渡すのではなく、
bundle 管理系コマンドで事前に保存・compile し、runtime 実行では `program` または `bundle_id`
だけを渡す 2 段階方式とする。

- management plane:
  - `bundle import`
  - `bundle compile`
  - `bundle activate`
  - `bundle update`
  - `bundle list`
  - `bundle show`
- runtime plane:
  - bug bounty 実行 CLI は `--program <alias>` または `--bundle-id <id>` を受ける

この spec ではコマンドファミリ名を規定するが、最終的な実装が
`shigoku bugbounty bundle ...`、`python -m src.main ...`、または同等の専用 CLI であることは許容する。
ただし、runtime 実行と bundle 管理の責務は分離しなければならない。

### 11.2 CLI Routing Constraint

既存ルール上、`shigoku-ops` は report / session / validate / gate などの ops 補助導線を優先する。
そのため、bug bounty bundle の import / update / activate は `shigoku-ops report` 系へ混在させず、
primary runtime CLI か専用の bug bounty management CLI に載せること。

### 11.3 Runtime Arguments

runtime bug bounty CLI は最低限次を受けること。

- `--program <alias>`: active bundle を解決する通常起動
- `--bundle-id <id>`: active alias を使わず明示的に bundle を pin する起動

優先順位は次のとおり。

1. `--bundle-id`
2. `--program`
3. default active program mapping

`--bundle-id` と `--program` が両方渡された場合、両者が一致しなければ preflight error とする。

### 11.4 Delivery Timing

compiled policy は MC が task を作る前に解決・注入しなければならない。

1. CLI が `program` または `bundle_id` を受理する
2. preflight で active mapping と compiled policy を解決する
3. `compile_status=ready` を確認する
4. 初期 `--target` や seed host が compiled policy 上で明らかに out of scope でないことを確認する
5. run context に `policy_id`, `bundle_id`, `compiled_guard_policy` を固定する
6. その後に MC を起動する

MC 起動後に raw source を読み始める設計は禁止する。

### 11.5 Convenience Path for Ad Hoc Input

V1 では利便性のため `--bundle-dir <path>` のような shortcut を許容してよい。
ただし、その意味は「bundle を直接 runtime に食わせる」ではなく、次の短縮形でなければならない。

1. 指定 bundle を validate する
2. 内部的に import / compile を行う
3. 必要なら ephemeral または named bundle として registry に保存する
4. `compile_status=ready` のときだけ run を開始する

つまり、`--bundle-dir` は transport shortcut であり、runtime bypass ではない。

### 11.6 Non-Normative Example

```bash
shigoku bugbounty bundle import \
  --provider hackerone \
  --program tiktok \
  --policy /path/policy.md \
  --scope-csv /path/scopes.csv

shigoku bugbounty bundle compile --bundle-id h1-tiktok-2026-07-01T07:38:38Z

shigoku bugbounty bundle activate --program tiktok --bundle-id h1-tiktok-2026-07-01T07:38:38Z

python -m src.main --mode bugbounty --program tiktok --target https://www.tiktok.com
```

## 12. Update, Versioning, and Activation Semantics

### 12.1 Immutable Bundle Versioning

`bundle update` は既存 bundle の破壊的上書きではなく、新しい version を作ること。

- old bundle: 保持
- new bundle: 生成
- compiled policy: 新 version に対して再生成
- active mapping: 必要なら切り替え

### 12.2 Activation Rule

- `bundle activate` は `compile_status=ready` の bundle に対してのみ成功する
- activation 切り替えは atomic であること
- activation 前に target program / provider mismatch を検出すること

### 12.3 Run Snapshot Freeze

run 開始時に選ばれた `bundle_id` / `policy_id` はその run の間固定する。

- 実行中に新しい active bundle が作られても、既存 run の policy は変えない
- 次回 run から新 bundle を使う

### 12.4 Rollback

rollback は old bundle を再 activate する操作で実現する。
runtime 中の hot reload は V1 では禁止する。

### 12.5 Update with Preview

V1 では最低限、update 前後で次を diff 表示できることが望ましい。

- added / removed assets
- allow -> deny の変更
- temporal exclusion の追加
- attack class policy の変更
- review finding の増減

## 13. Additional Operational Considerations

### 13.1 Legacy `--scope` Migration

V1 の決定事項:

- `--mode bugbounty` では legacy `--scope` を受け付けない
- preflight で明示エラーにし、bundle 導線へ誘導する
- help / example / operator doc から bug bounty 用の `--scope` 例を外す

内部実装の完全撤去は別フェーズで行う。
ただし V1 では runtime 導線から bug bounty 用 `--scope` を切り離すことを優先する。

### 13.2 Staleness and Drift Detection

初期リリース時点では historical bundle が存在しない前提のため、
V1 では stale bundle による block / warning 実装を完了条件に含めない。

ただし、将来の update に備えて次のメタデータは保存する。

- raw source hash
- `compiled_at_utc`
- `captured_at_utc`

V1 では「保存だけ行い、age-based 判定は deferred」でよい。

### 13.3 Concurrency and Locking

V1 は単独運用前提とし、同時更新制御は完了条件に含めない。

ただし将来の複数 operator / 自動ジョブ化に備えて、設計メモとして
`import / compile / activate` に file lock を差し込める構造を維持することが望ましい。

### 13.4 Secret and Credential Boundaries

bundle に test credential 実値を直接保存しないことを決定事項とする。

- allowed email domain
- auth requirement
- account creation rule

のような policy 情報は保存してよいが、秘密値が必要な場合は次のいずれかで参照する。

- `credential_profile_ref`
- `username_env`
- `password_env`
- `token_env`

例:

```yaml
auth:
  requires_test_account: true
  allowed_email_domains:
    - bugcrowdninja.com
  credential_profile_ref: fireblocks_sandbox_primary
  username_env: FIREBLOCKS_TEST_EMAIL
  password_env: FIREBLOCKS_TEST_PASSWORD
```

また、bundle import / override save / compiled policy write の保存経路では、
secret-like value が入力に紛れ込んだ場合に persistence 前に検査すること。

- default: write を拒否する
- logs / error payload には赤字化済み値のみ残す

V1 の基本方針は「動的利用時に隠す」ではなく「保存前に入れない」である。

### 13.5 Auditability

少なくとも次を run artifact と decision log に残すこと。

- `bundle_id`
- `policy_id`
- activation source
- compile status
- reason code
- enforcement layer

### 13.6 Multi-Program and Alias Safety

- `program alias` は provider をまたいで衝突しない設計にする
- same alias の accidental overwrite を避ける
- alias と canonical program name の対応を registry で説明できるようにする

V1 の決定事項:

- `bundle_id` は immutable
- `program alias` は mutable
- Docker tag に近い運用とし、active alias は常に 1 つの `bundle_id` を指す
- `bundle_id` 形式は `bbp-<provider>-<program>-<timestamp>-<short_hash>` を推奨する

### 13.7 Review Workflow UX

manual review が必要な bundle に対して、operator が次に何を直せばよいか分かる導線が必要である。

- pending finding 一覧
- source refs
- suggested override skeleton
- recompile command

### 13.8 Bundle Persistence and Retention

V1 の保存先は次のとおりとする。

- named bundle:
  - `workspace/bugbounty/programs/<provider>/<program_alias>/bundles/<bundle_id>/`
- active mapping:
  - `workspace/bugbounty/programs/<provider>/<program_alias>/active_bundle.json`
- ephemeral bundle:
  - `workspace/bugbounty/_ephemeral/<bundle_id>/`

保持方針は次のとおり。

- named bundle: V1 では自動削除しない
- superseded named bundle: rollback / audit 用に保持する
- ephemeral bundle: TTL 7日
- cleanup: import 時または明示 `prune` コマンド時に期限切れ ephemeral を掃除する

理由:

- bundle は program 単位の正本であり、`workspace/projects/<target>/...` よりも
  target 非依存の `workspace/bugbounty/...` 配下に置く方が意味的に自然
- named bundle はサイズが小さく audit 価値が高いため、V1 では keep が最適
- ephemeral だけ TTL 管理すれば利便性と掃除のバランスがよい

artifact path と registry の参照切れ検知は維持する。

#### Active Mapping Integrity Checks

`active_bundle.json` は少なくとも次を保持する。

- `provider`
- `program_alias`
- `bundle_id`
- `policy_id`
- `compiled_policy_path`
- `compiled_policy_hash`
- `activated_at_utc`

runtime preflight は `active_bundle.json` 解決後に次を検証する。

- referenced bundle directory が存在する
- `compiled_guard_policy.yaml` が存在する
- active mapping 上の `compiled_policy_hash` と実ファイル hash が一致する
- policy の `compile_status=ready`、`bundle_id`、`policy_id` が active mapping と一致する

いずれかが不一致なら fail-closed とし、`re-activate` または rollback を案内する。

### 13.9 Resume / Retry / Replay Compatibility

resume, retry, replay, import-recon などの再実行系フローは、元 run の `bundle_id` / `policy_id`
を引き継ぐか、明示的に rebind を要求する必要がある。

V1 の決定事項:

- default: same bundle snapshot を引き継ぐ
- explicit rebind: 新しい active bundle を使う
- snapshot 不一致で safety に影響が出る場合は fail-closed にする

つまり、resume / retry は「前回と同じ rule book で続ける」を正とし、
新しい bundle を使いたい場合だけ明示操作にする。

### 13.10 Rollout Strategy and Kill Switch

V1 の rollout は次の順で段階導入する。

1. `shadow read-only`: evaluator は判定するが block せず、decision diff と reason code だけを記録する
2. `MC only enforcement`: task 生成前 block を有効化する
3. `worker/external hard enforcement`: 実行直前と外部アクセス直前の block を有効化する

各段階は downgrade 可能でなければならない。

- enforcement stage の設定を下げる kill switch を用意する
- 旧 active bundle への rollback と rollout stage の切り戻しは独立に実行できるようにする

### 13.11 Observability and Safety Metrics

少なくとも次の metrics / counters を定義する。

- `bundle_import_to_ready_seconds`
- `compile_failed_total`
- `manual_review_required_total`
- `guard_decision_total{layer,decision,reason_code}`
- `active_bundle_read_failure_total`
- `policy_fail_closed_total`

V1 の acceptance review では少なくとも次を観測できること。

- compile failure の発生頻度
- manual review 比率
- layer 別 block reason の偏り
- active mapping / compiled artifact 読み出し失敗
- false block 調査に必要な `decision_trace_id` と `rule_origin_id` の追跡性

## 14. Acceptance Examples

### 14.1 TikTok HackerOne Example

2026-07-01 に取得した sample では、HackerOne CSV に以下が含まれる。

- `*.tiktok.com` の wildcard allow
- `https://developers.tiktok.com/minis/` の `eligible_for_submission=false`
- `*tiktokv.us`, `*us.tiktokv.com`, `p16-bg.tiktokcdn-us.com` などの `eligible_for_submission=false`

同じ sample の policy text には次が含まれる。

- `developers.tiktok.com/minis/` は 2026-02-23 から temporary exclusion
- TikTok FBT platform は 2026-05-13 23:59 GMT+8 以降 temporary exclusion
- `social engineering` は禁止
- `DoS` と privacy violation は禁止
- SSRF は `https://ssrf-bait.byted.org/...` 系に限定

この bundle を compile した結果、少なくとも次が成立しなければならない。

- `https://developers.tiktok.com/minis/` は deny
- TikTok の internal resource へ進む post-exploit action は deny
- SSRF destination は sheriff 指定先以外 deny
- `compile_status=ready` でなければ bug bounty run を開始しない

### 14.2 Fireblocks Bugcrowd Example

2026-02-12 13:49:31 GMT+0 時点の sample では、Targets として次の exact host が列挙される。

- `sb-console-api.fireblocks.io`
- `sb-mobile-api.fireblocks.io`
- `sandbox-api.fireblocks.io`

同じ policy text には次が含まれる。

- listed target 以外の Fireblocks domain/property は out of scope
- `Third party providers and services` は out of scope
- `Potential post-exploitation scenarios` は stop testing and submit
- `DoS/DDoS/Network DoS` と `Rate limiting bypass attempts` は excluded
- account registration は `@bugcrowdninja.com` email を要求

この bundle を compile した結果、少なくとも次が成立しなければならない。

- listed host 以外は exact deny 相当
- post-exploit action は deny
- DoS / rate-limit bypass 系 attack class は deny
- auth requirement として `bugcrowdninja.com` が記録される

## 15. Definition of Done for Step 1

- `program_bundle/` の canonical contract が固定されている
- shared evaluator を唯一の runtime decision contract とする責務分離が固定されている
- HackerOne / Bugcrowd の sample をこの contract へ落とせる
- `review_findings.yaml` と `overrides.yaml` の最小 schema が固定されている
- `compiled_guard_policy.yaml` の最小 runtime schema が固定されている
- deterministic hash / schema compatibility / rule origin trace が固定されている
- active mapping integrity と rollout/observability の最小要件が固定されている
- precedence と fail-closed 条件が実装前に曖昧でない
