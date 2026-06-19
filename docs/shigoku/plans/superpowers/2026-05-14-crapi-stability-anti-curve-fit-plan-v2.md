---
task_id: SGK-2026-0055
doc_type: plan
doc_usage: implementation_plan
status: backlog
parent_task_id: null
related_docs: []
created_at: '2026-05-14'
updated_at: '2026-05-19'
---

# CRAPI Stability Plan v2 (Anti-Curve-Fit Revision)

## 1. 目的
- CRAPI での攻撃成功率と `confirmed` 再現率を上げる。
- 同時に、CRAPI 固有条件へのカーブフィッティングを防ぐ。
- 判定は「単発の良い run」ではなく「複数 run の再現率」で行う。

## 2. 非交渉ガードレール
- `src/` にターゲット固有文字列を追加しない。
- 重み付けロジックの採用判定は CRAPI 単独で行わない。
- 採用には CRAPI と非 CRAPI の両方で gate と再現率を満たすことを必須にする。

## 3. 変更対象
- `src/main.py` の `_build_heuristic_findings_from_execution_notes` と execution notes 取り込み部。
- `src/core/agents/swarm/injection/manager.py` が出している生シグナルのうち、report 側へ落としている項目。
- `scripts/bench/run_scn01_07_p0_5runs.sh` と `scripts/bench/summarize_scn_benchmark.py` の評価補助。

## 4. 実装方針
### Phase A: 観測データ欠落の解消
- `execution_notes` に次を追加する。
- `comparison_checks`
- `auth_context_matrix`
- `object_ab_comparison`
- `schema_candidate_params`
- `single_request_validation`
- `detection_mode`
- `task_id`
- 目的は「候補重み付け前の情報欠落」をなくすこと。

### Phase B: 重み付けを 2 段構成へ変更
- 1 段目は Evidence Gate とする。
- 2 段目は Gate 通過候補のみをランキングする。
- Evidence Gate で `timeout/error` 単独候補を落とす。
- Ranking は加点と減点の両方を使う。
- `single_request_validation=True` は減点する。
- `probe_skipped_reason` は減点する。

### Phase C: 昇格条件の一般化
- `heuristic_promoted` 条件を privilege probe 偏重から外す。
- `access_control`, `idor_bola`, `mass_assignment`, `endpoint_bfla` ごとに昇格条件を持つ。
- 昇格には「複数回成功」だけでなく「異なる有効プローブで再現」を含める。

### Phase D: 反カーブフィット評価
- 評価は 3 バケットで行う。
- バケット1: CRAPI
- バケット2: API 系シャドーターゲット
- バケット3: Web フォーム系シャドーターゲット
- 採用判定は 3 バケット同時判定にする。

## 5. 採用基準 (Go / No-Go)
- Go 条件:
- consistency が全 run で `consistent`
- CRAPI で `confirmed>=3` を 5 run 中 4 run 以上
- required classes (`access_control, idor_bola, mass_assignment, endpoint_bfla`) が CRAPI で各 5 run 中 4 run 以上
- 非 CRAPI 2 バケットで gate pass rate が現行比 -5% 以内
- 非 CRAPI で required class 欠落が増えない
- No-Go 条件:
- CRAPI が改善しても非 CRAPI で gate pass rate が 5% 超悪化
- `src/` にターゲット固有文字列が混入
- reason code 欠損または PoC 欠損が増加

## 6. 実行順序
1. Baseline 固定: 現行ロジックで 3 バケットを各 5 run 実行。
2. Phase A だけ適用して再計測。
3. Phase B だけ適用して再計測。
4. Phase C を適用して再計測。
5. P0/P1/P2 を比較し、再現率最優先で採用プロファイルを決定。

## 7. 検証コマンド
```bash
cd /home/bbb/Documents/App/Shigoku

# 1) ターゲット固有文字列混入チェック（srcのみ）
rg -n "127\\.0\\.0\\.1:8888|crapi|/identity/api|/workshop/api|/community/api" src || true

# 2) 1レポートごとの consistency
.venv/bin/shigoku-ops --json report consistency --report <absolute-haddix-report-path>

# 3) 1レポートごとの gate
.venv/bin/shigoku-ops --json report gate \
  --report <absolute-haddix-report-path> \
  --allowed-missing scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology \
  --required-confirmed-classes access_control,idor_bola,mass_assignment,endpoint_bfla \
  --required-class-confirmed-min 1 \
  --confirmed-min 3 \
  --candidate-max 2 \
  --confirmed-poc-missing-max 0 \
  --reason-code-missing-max 0
```

## 8. ロールバック条件
- 非 CRAPI バケットで 2 連続悪化した段階で、直前 Phase を即ロールバックする。
- ロールバック後は単一ノブのみ変更して再試行する。

## 9. 期待成果
- CRAPI で `confirmed` 再現率の下限が上がる。
- required classes の欠落が減る。
- 非 CRAPI を同時評価するため、CRAPI 特化の過学習を抑制できる。

