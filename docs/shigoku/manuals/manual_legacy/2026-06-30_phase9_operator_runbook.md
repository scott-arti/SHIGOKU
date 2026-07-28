---
task_id: SGK-2026-0318
doc_type: manual
status: active
parent_task_id: null
related_docs:
  - docs/shigoku/subtasks/done/2026-06-26_swarm-phase-9-release-gate-rollout-policy-promotion_subtask_plan.md
  - docs/shigoku/subtasks/done/2026-06-23_sgk-2026-0291_swarm-parallelism-review_subtask_plan.md
title: 'Phase 9 Operator Runbook: Release Gate Rollout 運用マニュアル'
created_at: '2026-06-30'
updated_at: '2026-07-02'
tags:
  - shigoku
  - phase9
  - runbook
  - operations
---

# Phase 9 Operator Runbook

## 1. 概要

この runbook は SHIGOKU Phase 9 の release gate / rollout / rollback / policy promotion を
オペレータが実行するための手順書です。

## 2. 前提条件

- `config/shigoku.yaml` の `parallelism` セクションが存在すること
- `shigoku-ops runtime-control gate` が利用可能であること
- Phase 5-8 の実装が完了していること
- 作業者は `operator` 承認ロールを持つこと

## 3. Rollout 手順

### 3.1 Shadow Mode (初期状態)

```bash
# 確認: parallelism が shadow_mode=true で enabled=false であること
grep -A5 'parallelism:' config/shigoku.yaml
# 期待出力:
#   parallelism:
#     enabled: false
#     shadow_mode: true
```

シャドウモードでは実実行は serial のままで、shadow decision と gate evidence のみ生成されます。

### 3.2 Canary 展開

```bash
# Step 1: Gate evidence を評価（shadow_mode=true のまま）
.venv/bin/shigoku-ops runtime-control gate \
    --evidence-file workspace/projects/<target>/reports/phase9_evidence.json \
    --phase phase9

# Step 2: Gate 評価結果を確認
# 期待: status=pass, decision=proceed

# Step 3: Canary target のみ enabled=true に設定
# config/shigoku.yaml に追記:
#   canary_targets:
#     - <target_name>
```

### 3.3 Limited Default 展開

```bash
# Step 1: 全 canary target の gate pass を確認
.venv/bin/shigoku-ops runtime-control gate \
    --evidence-file workspace/projects/<target>/reports/phase9_evidence.json \
    --phase phase9

# Step 2: Finding parity 100% を確認
# gate evidence の finding_parity.high_critical_parity == 100.0

# Step 3: scope/origin/request budget violation 0 を確認
# gate evidence の scope_violation_count, origin_budget_violation_count, request_budget_violation_count == 0

# Step 4: critical event drop 0 を確認
# gate evidence の critical_event_drop_count == 0

# Step 5: reader compatibility pass を確認
# gate evidence の reader_compatibility_status == "pass"

# Step 6: promotion matrix で候補 flag を確認後、limited default を有効化
# config/shigoku.yaml に追記:
#   parallelism:
#     enabled: true  # limited — only for ga/public/read_only lanes
```

## 4. Rollback 手順

### 4.1 Kill Switch 発動

```bash
# Step 1: kill_switch を有効化（即時 serial 強制）
# config/shigoku.yaml を直接編集:
#   parallelism:
#     kill_switch: true

# Step 2: 設定変更を反映（アプリケーション再起動）
# アプリケーションを再起動すると、新しい kill_switch 状態が読み込まれます。

# Step 3: 次の batch が serial path で実行されることを確認
# SwarmDispatcher は _is_inner_parallelism_enabled() で kill_switch をチェックします。
# kill_switch=true の場合、_dispatch_serial() が使用され、全並列化が無効化されます。
```

### 4.2 Parallelism 完全無効化

```bash
# 全並列化を無効化
# config/shigoku.yaml を直接編集:
#   parallelism:
#     enabled: false
#     kill_switch: true

# 確認（python3 で settings を読み取り）
python3 -c "
from src.core.config.settings import get_settings
p = get_settings().parallelism
print(f'enabled={p.enabled} kill_switch={p.kill_switch} executor={p.default_executor}')
"
```

### 4.3 Rollback 検証

```bash
# rollback drill evidence を生成
python3 -c "
from src.reporting.rollback_drill import generate_rollback_evidence
evidence = generate_rollback_evidence(
    kill_switch_before=False,
    kill_switch_after=True,
    config_diff={'parallelism.kill_switch': 'false -> true'},
    verification_result={
        'serial_path_confirmed': True,
        'finding_parity_maintained': True,
        'reader_compatible': True,
    },
)
print('rollback_drill_status:', evidence['rollback_drill_status'])
print('reason_code:', evidence['reason_code'])
"
# 期待: rollback_drill_status=pass, reason_code=ROLLBACK_DRILL_PASSED
```

### 4.4 Post-Rollback Reader 互換性確認

```bash
# 既存 session/report reader が serial path の artifact を読めることを確認
python3 -c "
from src.reporting.reader_compatibility import check_reader_compatibility
result = check_reader_compatibility([])
assert result['reader_compatibility_status'] == 'pass'
"
```

## 5. Canary 運用

### 5.1 Canary Target 追加

```bash
# 1. canary target を config/shigoku.yaml に追加

# 2. Gate evidence を評価
.venv/bin/shigoku-ops runtime-control gate \
    --evidence-file workspace/projects/<target>/reports/phase9_evidence.json \
    --phase phase9

# 3. High/Critical finding parity が 100% であることを確認
# gate evidence の finding_parity.high_critical_parity == 100.0
```

### 5.2 Canary 結果のモニタリング

```bash
# gate evidence の内容を python3 で確認
python3 -c "
import json
with open('workspace/projects/<target>/reports/phase9_evidence.json') as f:
    evidence = json.load(f)
for rec in evidence:
    name = rec.get('gate_name')
    status = rec.get('status')
    print(f'{name}: {status}')
    # 確認項目:
    # - high_critical_parity == 100.0
    # - scope_violation_count == 0
    # - request_budget_violation_count == 0
    # - critical_event_drop_count == 0
"
```

## 6. Audit 確認

### 6.1 Gate Evidence Audit

```bash
# 全 gate evidence の整合性確認
.venv/bin/shigoku-ops runtime-control gate \
    --evidence-file workspace/projects/<target>/reports/phase9_evidence.json \
    --integrity-manifest workspace/projects/<target>/reports/phase9_integrity.json \
    --phase phase9

# 期待: status=pass, 全 critical gate が pass
```

### 6.2 Promotion/Demotion Audit

```bash
# promotion matrix の現在状態を確認
python3 -c "
from src.reporting.promotion_matrix import PromotionMatrix
m = PromotionMatrix()
for d in m.generate_matrix_table():
    print(f'{d[\"target_risk_tier\"]}/{d[\"specialist_maturity\"]}/{d[\"lane_policy\"]}: {d[\"action\"]} ({d[\"reason\"]})')
"
```

### 6.3 Rollback Drill Audit

```bash
# rollback drill の実施証跡を確認
python3 -c "
from src.reporting.rollback_drill import generate_rollback_evidence
e = generate_rollback_evidence(
    kill_switch_before=False,
    kill_switch_after=True,
    config_diff={'parallelism.kill_switch': 'false -> true'},
    verification_result={'serial_path_confirmed': True, 'finding_parity_maintained': True, 'reader_compatible': True},
)
print('rollback_drill_status:', e['rollback_drill_status'])
print('reason_code:', e['reason_code'])
"

# 期待: rollback_drill_status=pass, reason_code=ROLLBACK_DRILL_PASSED
```

## 7. 失敗時の分岐

### 7.1 Gate Fail → No-Go

- finding_parity が 100% 未満 → 昇格不可。serial 強制に戻し原因調査。
- scope_violation > 0 → 昇格不可。allowlist / scope 設定を確認。
- budget violation > 0 → 昇格不可。budget policy を調整。
- critical event drop > 0 → 昇格不可。EventBus reliability を確認。
- reader compatibility fail → 昇格不可。reader 互換性を修正。

### 7.2 Kill Switch 即時復旧

```bash
# 即時 serial 復帰
# config/shigoku.yaml を直接編集:
#   parallelism:
#     kill_switch: true
# アプリケーション再起動で kill_switch が反映されます。
```

## 8. 証跡保存先

| 証跡種別 | 保存先 |
|---------|--------|
| Gate evidence JSON | `workspace/projects/<target>/reports/phase9_evidence.json` |
| Gate 評価結果 | `workspace/projects/<target>/reports/phase9_gate_result.json` |
| Operator summary | `workspace/projects/<target>/reports/operator_summary_<date>.json` |
| Shadow compare report | `workspace/projects/<target>/reports/shadow_compare_<date>.json` |
| Rollback drill evidence | `workspace/projects/<target>/reports/rollback_drill_<date>.json` |
| Reader compatibility result | `workspace/projects/<target>/reports/reader_compat_<date>.json` |
| Promotion matrix | `workspace/projects/<target>/reports/promotion_matrix_<date>.json` |

## 9. 承認者

| 操作 | 最低承認レベル |
|------|---------------|
| Shadow mode 運用 | operator |
| Canary 展開 | operator + reviewer |
| Limited default 展開 | operator + reviewer + CTO approval |
| Broader default 展開 | CTO approval required |
| Kill switch 発動 | operator (即時) |
| Promotion (ga lane) | operator + reviewer |
| Demotion | operator |
