---
task_id: SGK-2026-0089
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-11'
updated_at: '2026-07-02'
---

# 高速ベンチ運用 + P0採用決定 + Confirmed増加プラン（1ページ）

## 1. 結論（先に要点）
- 境界条件（confirmed/candidate）の採用は **P0維持**。
- `P1/P2` tightening は、現状データで `fail=5/5` かつ `confirmed_below_minimum` を改善できなかった。
- 実行時間短縮は達成（5runが約50分→約3分半）。
- ただし `BENCH_ULTRA=1` は品質評価には強く効きすぎ、Confirmedが0件化しうるため、**速度評価専用モード**として扱う。

## 2. 直近の事実（固定データ）
- 高速実行（Ultra）:
  - `P0_run01 started_at=2026-05-11T22:10:00+09:00`
  - `P0_run05 ended_at=2026-05-11T22:13:26+09:00`
  - 5run約3分半。
- replay gate matrix:
  - `replay_gate_matrix_summary.json` より `P1/P2` とも `pass=0, fail=5`。
  - reason codes（全run共通）:
    - `confirmed_below_minimum`
    - `family_gate_not_passed`
    - `required_detection_class_below_minimum`
    - `unexpected_missing_scenarios`
- Ultra時の品質サマリ:
  - `scn01_07_p0_summary_latest.json` より
  - `avg_confirmed_count=0.0`, `avg_candidate_count=0.0`
  - `scn_03`以外の検出率が低下。

## 3. 運用モード定義（短時間と品質を分離）
- Mode A: **Smoke/速度確認**（最短）
  - 目的: スクリプト健全性・時間監視
  - 設定: `BENCH_FAST=1 BENCH_ULTRA=1 BENCH_ULTRA_MAX_DERIVED=1 BENCH_ULTRA_MAX_SESSION_TASKS=8`
- Mode B: **Quality/KPI測定**（Confirmed評価）
  - 目的: Confirmed/Candidate、SCN01-07再現率評価
  - 設定: `BENCH_FAST=1 BENCH_ULTRA=0`
- ルール:
  - 境界採用判断は必ず **Mode B** で実施。
  - Mode Aの数値は採用判定に使わない（速度指標のみ）。

## 4. Confirmed増加プラン（最短で効く順）
### Step 1: クラス不足を埋める seed_set_v2 を投入
- 目的: `required_detection_class_below_minimum` の解消。
- 方針: `tagged_urls` に以下カテゴリseedを明示追加（同一ホスト限定）。
  - `admin` / `auth` / `id_param` / `api_data` / `feedback_review`
- 実装方針:
  - 当日ファイル名規則 `YYYYMMDD_*_tagged_<category>.jsonl` で投入。
  - 1カテゴリあたり2-3本、再現性のあるURLを固定。

### Step 2: Qualityモードで短いA/B実験（3run）
- A: `seed_set_v1`、B: `seed_set_v2` を比較。
- 判定指標:
  - `avg_confirmed_count`（最優先）
  - `required_detection_class_below_minimum` の発生回数
  - `SCN01-07 detection rate`

### Step 3: 効いたseedだけ残して5run本番
- v2で改善したカテゴリseedのみ残す。
- 5runで再計測し、`confirmed_min=3` 到達率を確認。

## 5. 実行コマンド（そのまま使う）
### 5.0 seed_set_v2 投入（最初に1回）
```bash
cd /home/bbb/Documents/App/Shigoku
./.venv/bin/python scripts/bench/apply_seed_set_v2.py \
  --project-dir /home/bbb/Documents/App/Shigoku/tmp/bench_runtime/workspace/projects/127.0.0.1:8888
```

### 5.1 速度確認（Smoke）
```bash
cd /home/bbb/Documents/App/Shigoku
PROFILE_ID=P0 BENCH_FAST=1 BENCH_ULTRA=1 \
BENCH_ULTRA_MAX_DERIVED=1 BENCH_ULTRA_MAX_SESSION_TASKS=8 \
RUN_COUNT=5 RUN_TIMEOUT_SEC=420 \
bash scripts/bench/run_scn01_07_p0_5runs.sh
```

### 5.2 境界再評価（再スキャンなし）
```bash
cd /home/bbb/Documents/App/Shigoku
ARTIFACT_DIR=/home/bbb/Documents/App/Shigoku/tmp/bench_runtime/workspace/projects/127.0.0.1:8888/reports/benchmark_scn01_07_P0 \
bash scripts/bench/replay_gate_matrix.sh
```

### 5.3 Confirmed評価（Quality）
```bash
cd /home/bbb/Documents/App/Shigoku
PROFILE_ID=P0 BENCH_FAST=1 BENCH_ULTRA=0 RUN_COUNT=3 RUN_TIMEOUT_SEC=900 \
SEED_SET_ID=scn01-07_seed_v2 \
bash scripts/bench/run_scn01_07_p0_5runs.sh
```

## 6. 完了条件
- seed_set_v2 適用後の Qualityモードで、
  - `avg_confirmed_count` が v1 比で改善、かつ
  - `required_detection_class_below_minimum` 発生回数が減少。
- この条件を満たしたら、P0運用を継続しつつseed_set_v2を標準化する。

## 7. 実測アップデート（2026-05-11 22:51-23:32 JST, seed_set_v2, Quality 3run）
- 実行条件:
  - `PROFILE_ID=P0 BENCH_FAST=1 BENCH_ULTRA=0 RUN_COUNT=3 RUN_TIMEOUT_SEC=900 SEED_SET_ID=scn01-07_seed_v2`
- スナップショット:
  - `/home/bbb/Documents/App/Shigoku/tmp/bench_runtime/workspace/projects/127.0.0.1:8888/reports/benchmark_scn01_07_P0/snapshot_seedv2_quality3run_20260511_233220`
- 集計結果:
  - `runs=3`, `all_consistent=true`
  - `avg_confirmed_count=1.67`, `avg_candidate_count=2.0`
  - `SCN01-07 detection rate=1.0`（全SCN01-07を再現）
  - gate: `pass=0, fail=3`
  - 主因: `confirmed_below_minimum`(3/3), `unexpected_missing_scenarios`(3/3), `candidate_above_maximum`(1/3)
- 解釈:
  - SCN01-07再現は安定しているため、問題は「検出できない」ではなく「confirmed密度不足」。
  - 直近ボトルネックは `confirmed_min=3` 未達（1-2件帯）。

## 8. Confirmed増加の次施策（最短ルート）
### 8.1 まずは density prewarm を入れて 1run 比較
- 目的:
  - gateの自動提案 `increase_confirmed_density` を先に実施し、confirmed密度を上げる。
- コマンド:
```bash
cd /home/bbb/Documents/App/Shigoku
./.venv/bin/python -m src.main --focus-tests --focus-group density

PROFILE_ID=P0 BENCH_FAST=1 BENCH_ULTRA=0 RUN_COUNT=1 RUN_TIMEOUT_SEC=900 \
SEED_SET_ID=scn01-07_seed_v2 \
bash scripts/bench/run_scn01_07_p0_5runs.sh
```

### 8.2 candidateノイズ抑制の最小A/B（各1run）
- 目的:
  - confirmedを落とさず `candidate_above_maximum` を抑える設定幅を確認。
- A（現状）:
```bash
cd /home/bbb/Documents/App/Shigoku
PROFILE_ID=P0 BENCH_FAST=1 BENCH_ULTRA=0 RUN_COUNT=1 RUN_TIMEOUT_SEC=900 \
SEED_SET_ID=scn01-07_seed_v2 \
bash scripts/bench/run_scn01_07_p0_5runs.sh
```
- B（candidate抑制）:
```bash
cd /home/bbb/Documents/App/Shigoku
SHIGOKU_REPORT_HEURISTIC_MAX_CANDIDATES=1 \
SHIGOKU_REPORT_HEURISTIC_APPEND_WHEN_CONFIRMED=1 \
PROFILE_ID=P0 BENCH_FAST=1 BENCH_ULTRA=0 RUN_COUNT=1 RUN_TIMEOUT_SEC=900 \
SEED_SET_ID=scn01-07_seed_v2 \
bash scripts/bench/run_scn01_07_p0_5runs.sh
```

### 8.3 良い設定だけで 5run 本番
- 採用基準:
  - `avg_confirmed_count` を優先（最低でも2.0超、目標3.0）
  - `candidate_above_maximum` 発生率低下
  - `all_consistent=true` 維持

## 9. A/B最小実験の実測判定（2026-05-11〜2026-05-12）
- A（density prewarm + P0既定）:
  - report: `haddix_report_20260511_235614.md`
  - consistency: `consistent`
  - gate reason: `confirmed_below_minimum`, `unexpected_missing_scenarios`
  - `confirmed=2`, `candidate=1`
  - scenario coverage: `8/12`（missing=`scn_08, scn_10, scn_11, scn_12`）
- B（`SHIGOKU_REPORT_HEURISTIC_MAX_CANDIDATES=1`）:
  - report: `haddix_report_20260512_000312.md`
  - consistency: `consistent`
  - gate reason: `confirmed_below_minimum`, `required_detection_class_below_minimum`, `unexpected_missing_scenarios`
  - `confirmed=1`, `candidate=1`
  - scenario coverage: `5/12`（`scn_04, scn_06, scn_09` も新規missing化）
- 判定:
  - **A採用 / B却下**（Bはcandidateは減らせてもconfirmedとSCN再現を悪化させる）。

## 10. 次の固定打ち手
- 5run本番は A構成で実施（`SHIGOKU_REPORT_HEURISTIC_MAX_CANDIDATES` は固定しない）。
- 実行後に `summarize_scn_benchmark.py` と `replay_gate_matrix.sh` で再スキャンなし評価を行う。
