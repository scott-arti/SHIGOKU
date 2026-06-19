---
task_id: SGK-2026-0307
doc_type: plan
doc_usage: implementation_plan
status: done
parent_task_id: SGK-2026-0303
related_docs:
- docs/shigoku/plans/2026-06-17_masterconductor-seed-target-service-followup_plan.md
- docs/shigoku/reports/2026-06-17_SGK-2026-0303_work_report.md
- docs/shigoku/reports/2026-06-17_SGK-2026-0307_work_report.md
- docs/shigoku/worklogs/2026-06-17_SGK-2026-0307_work_log.md
created_at: '2026-06-17'
updated_at: '2026-06-18'
title: 'MasterConductor seed collectors 二段分割計画'
---

# 実装計画書：SGK-2026-0307 MasterConductor seed collectors 二段分割

## 1. 背景

SGK-2026-0303 で `_SeedCollectors` を `master_conductor_recon_seed_collectors.py` へ一括抽出したが、
827 行に達し、目標上限 500 行を +327 行超過。SGK-2026-0303-D01 として deferred されていた。

## 2. 達成したいゴール

- [x] `master_conductor_recon_seed_collectors.py` (827行) を `_SeedCollectors` の公開 import を維持したまま、path/collector cluster と history-replay/scenario-probe cluster に二段分割する。
- [x] 全ファイルが 250-500 行に収まること。
- [x] `ReconSeedTargetService` (`master_conductor_recon_seed_target_service.py`) の consumer 互換性と全テスト維持。

## 3. 分割境界

### 分割前（現在）
```
master_conductor_recon_seed_collectors.py (827行)
├── _SeedCollectors (class)
│   ├── get_context_auth_headers (31行)
│   ├── get_context_cookie_string (2行)
│   ├── resolve_recon_file_path (38行)
│   ├── resolve_project_tagged_dir (29行)
│   ├── resolve_in_scope_hosts (23行)
│   ├── collect_csrf_seed_targets (109行)
│   ├── collect_xss_seed_targets (105行)
│   ├── collect_history_replay_targets (169行)
│   ├── refine_backfill_seed_targets (109行)
│   ├── collect_scenario_probe_seed_targets (78行)
│   └── select_targets_for_scenario_probe (74行)
```

### 分割後

#### `master_conductor_recon_seed_collectors.py` (~475行)
`_SeedCollectors` に path 解決 / auth ヘルパー / CSRF / XSS / backfill refine を残す。

```
├── class _SeedCollectors
│   ├── get_context_auth_headers
│   ├── get_context_cookie_string
│   ├── resolve_recon_file_path
│   ├── resolve_project_tagged_dir
│   ├── resolve_in_scope_hosts
│   ├── collect_csrf_seed_targets
│   ├── collect_xss_seed_targets
│   └── refine_backfill_seed_targets
```

#### `master_conductor_recon_seed_replay_probe.py` (~420行) — 新規
history replay / scenario probe / scenario target selection を独立 helper に。

```
├── class _SeedReplayProbe
│   ├── collect_history_replay_targets
│   ├── collect_scenario_probe_seed_targets
│   └── select_targets_for_scenario_probe
```

`_SeedReplayProbe.__init__` は `context / workspace / project_manager / target / settings_ / scope / seed / collectors` を注入受け取り。
`collectors` 参照は `collect_csrf_seed_targets` / `refine_backfill_seed_targets` 呼び出し用。

### データフロー
```
ReconSeedTargetService (coordinator)
├── scope:  _UrlScopeResolver
├── seed:   _SeedTargetSelector
├── _collectors:  _SeedCollectors   ← path / auth / CSRF / XSS / refine
└── _replay_probe: _SeedReplayProbe ← history replay / scenario probe
    ↑ _collectors を注入 (collect_csrf / refine_backfill に使用)
```

## 4. 具体的な仕様と制約条件

- `_SeedCollectors` の class 名 / import path は変更しない（consumer からの import を維持）。
- `_SeedReplayProbe` は `_SeedCollectors` への参照を持つが、`MasterConductor` instance や task queue への逆参照は禁止。
- service の `_collectors` property を `_SeedCollectors` インスタンス解決のまま維持し、`_replay_probe` を別プロパティとして追加。
- 全 68 targeted tests の selected targets / scope / malformed input tolerance の挙動を変えない。

### 目安サイズ
| ファイル | 目標 | 見積 |
|---|---|---|
| `master_conductor_recon_seed_collectors.py` | 300-500 | ~475 |
| `master_conductor_recon_seed_replay_probe.py` | 300-500 | ~420 |

## 5. 実装ステップ

- [x] ステップ1: `master_conductor_recon_seed_replay_probe.py` を作成し、`_SeedReplayProbe` に history replay / scenario probe / scenario target selection を抽出。
- [x] ステップ2: `_SeedCollectors` から上記3メソッドを削除。
- [x] ステップ3: `ReconSeedTargetService` の constructor で `_SeedReplayProbe` を初期化し、委譲メソッドを追加。
- [x] ステップ4: targeted tests 68件全pass を確認。consumer 側 import の不変を確認。

### 推奨検証コマンド
```bash
.venv/bin/pytest tests/core/engine/test_master_conductor_api_candidate_routing.py tests/core/engine/test_master_conductor_scenario_probes.py tests/core/intelligence/test_phase0_risk_clearance_checklist.py -q
.venv/bin/python -m compileall src/core/engine/master_conductor_recon_seed_collectors.py src/core/engine/master_conductor_recon_seed_replay_probe.py src/core/engine/master_conductor_recon_seed_target_service.py
```

### 完了条件
- `_SeedCollectors` の class 名 / import path 不変。
- `master_conductor_recon_seed_collectors.py` が ~475 行（300-500 範囲内）。
- `master_conductor_recon_seed_replay_probe.py` が ~420 行（300-500 範囲内）。
- targeted tests 68件全pass。
- consumer 側（`master_conductor.py` / `master_conductor_facade.py`）の import 変更不要。

## 6. 既知のリスク

- [ ] [重要度:中] `_SeedReplayProbe` が `_SeedCollectors` 参照を持つ循環的依存（service 側で injection により解決済み。conductor 本体への逆参照は禁止）。
- [ ] [重要度:低] auth ヘルパーは replay/probe 側では現状未使用。必要時は service 経由で injection 可能。
