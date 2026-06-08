---
task_id: SGK-2026-0213
doc_type: work_log
status: done
parent_task_id: null
related_docs: []
created_at: '2026-05-12'
updated_at: '2026-05-19'
---

# 2026-05-12 Codex Handover v2 (SCN01-07: 品質優先 + 速度/コスト最適化)

## 1. この引き継ぎ書の目的
この文書は、次のCodexチャットがこのセッションの続きから即時再開できるように、
- 実施したこと
- 悩んだこと
- 解決したこと
- 未解決/残課題
- 次の最短アクション
をまとめたもの。

対象リポジトリ: `/home/bbb/Documents/App/Shigoku`

## 2. セッションの大目標（再確認）
- 最優先: **SHIGOKUが脆弱性を見つける品質（検出品質・confirmed品質）**
- その次: 速度短縮とコスト低減
- 進め方: 影響小で効果高の順に改善
  - 元3: `phase2_on_empty_phase1` 抑制（空振りPhase2削減）
  - 元2: RiskPredictor delay 条件付き化（高リスクのみ）
  - 元5: timeout retry 条件付き化（同一原因の再試行抑制）
  - 元1: injection並列度 1→2（限定）
  - 元4: Phase1本格並列化（最後）

## 3. 今回実装した変更（コード）

### 3.1 timeout retry の同一原因ガード（元5）
- 変更ファイル:
  - `src/core/agents/swarm/injection/manager.py`
- 実装内容:
  - timeout原因キー生成を追加（URLの動的ID/hex正規化 + query key上位）
  - 同一原因timeoutが既に発生しており、かつ低優先度ターゲットの場合、retry回数を0に抑制
- 主な位置:
  - `_build_timeout_cause_key` 追加
  - `dispatch()` の Phase1ループ内で `timeout_cause_failures` を参照して `effective_timeout_retries` を抑制

### 3.2 RiskPredictor delay 条件の堅牢化（元2）
- 変更ファイル:
  - `src/core/engine/master_conductor.py`
- 実装内容:
  - `risk_predictor_delay_high_only=true` 時、
    - `risk_level in {high, critical}` または
    - `risk_score >= risk_predictor_delay_min_score`
    のときだけ delay を適用
  - ログも `risk_level/risk_score/min_score` を出すよう改善

### 3.3 BENCH_FASTの安全デフォルト（元3 + 元1の限定適用）
- 変更ファイル:
  - `scripts/bench/run_scn01_07_p0_5runs.sh`
- 実装内容（`BENCH_FAST=1` のとき）:
  - `SHIGOKU_PHASE2_ON_EMPTY_FORCE_DISABLE=1`
  - `SHIGOKU_RISK_PREDICTOR_DELAY_HIGH_ONLY=1`
  - `SHIGOKU_PHASE1_TIMEOUT_RETRY_SAME_CAUSE_GUARD=1`
  - `SHIGOKU_PHASE1_TIMEOUT_RETRY_GUARD_MIN_PRIORITY=70`
  - `SHIGOKU_INJECTION_BATCH_PARALLELISM=2`
  - いずれも明示envで上書き可能
- 補助:
  - 実効値を `[INFO]` で出力するようにし、再現性デバッグを容易化

### 3.4 テスト追加
- 変更ファイル:
  - `tests/core/agents/swarm/test_injection_manager.py`
- 追加内容:
  - 同一原因timeoutガードで「2件目以降のretry抑制」が効くことを検証

## 4. 今回の検証コマンドと結果（要点）

### 4.1 単体/統合テスト
- 実行:
  - `.venv/bin/pytest -q tests/core/agents/swarm/test_injection_manager.py`
  - `.venv/bin/pytest -q tests/core/engine/test_mc_intelligence_integration.py`
- 結果:
  - `18 passed, 1 skipped`
  - `8 passed`

### 4.2 実ベンチ（直近の重要比較）

| セット | summary.json | runs | avg_confirmed | avg_candidate | SCN07 rate | all_consistent |
|---|---|---:|---:|---:|---:|---|
| A/B baseline | `/tmp/bench_ab_baseline_20260512_114238/.../summary.json` | 3 | 1.6667 | 1.3333 | 1.0 | true |
| A/B tuned | `/tmp/bench_ab_tuned_20260512_114238/.../summary.json` | 3 | 2.0 | 0.6667 | 1.0 | true |
| postfix fast 3run | `/tmp/bench_postfix_fast_3run_20260512_162333/.../summary.json` | 3 | 1.3333 | 2.3333 | 1.0 | true |
| fast-fix 3run | `/tmp/bench_fast_fix_3run_20260512_191910/.../summary.json` | 3 | 2.6667 | 0.3333 | 1.0 | true |
| fast-fix gate5 (旧) | `/tmp/bench_fast_fix_gate5_20260512_215613/.../summary.json` | 5 | 2.2 | 1.4 | 1.0 | true |
| fast-fix gate5 (最新) | `/tmp/bench_fast_fix_gate5_20260512_231151/.../summary.json` | 5 | 2.2 | 0.8 | 1.0 | true |

### 4.3 最新5run（2026-05-12 23:11開始）の時間感
- 実行区間: `23:11:51 -> 23:31:18`（約19分27秒 / 5run）
- 平均: 約3分53秒 / run
- 以前の50分超より大幅短縮

## 5. report/session整合性ゲート（必須運用）
このセッションでも全レポートで実施済み。

- 直近5本:
  - `haddix_report_20260512_231623.md`
  - `haddix_report_20260512_231955.md`
  - `haddix_report_20260512_232341.md`
  - `haddix_report_20260512_232706.md`
  - `haddix_report_20260512_233117.md`
- 全て `status=consistent`

確認コマンド:
```bash
.venv/bin/python scripts/verify_report_session_consistency.py --report <absolute-report-path>
```

## 6. 悩んだこと / つまずき / 根本原因

### 6.1 速度は上がったのに品質が安定しない
- 症状:
  - 速いrunでも `confirmed_min=3` を毎回満たせない
  - 5runで `confirmed` のばらつき（1,3,2,3,2）
- 根本:
  - `phase2` を抑制した結果、Phase1の取り切り性能と再試行戦略の揺らぎがそのまま出る
  - 特に `mass_assignment` の取り切りが run により 1 or 2 で変動

### 6.2 「標準summaryゲート」と「運用ゲート」のズレ
- `summary.json` の `gate_status_counts` は標準ポリシー評価。
- 実運用では `--allowed-missing scn_08,10,12` を付けるため、別途 `shigoku-ops report gate` で再評価が必要。
- SCN11 は Ver.1 方針で deferred 例外には入れず、coverage 達成対象として扱う。
- この二重評価を混同すると判断を誤る。

### 6.3 軽量thinking有効化は逆効果
- `SHIGOKU_DEEPSEEK_THINKING_ENABLED_FOR_LIGHTWEIGHT=true` で実行したセットは、
  - `scan_exit=124`（timeout）
  - 時間増 + confirmed低下
- 結論:
  - BENCH_FASTでは lightweight thinkingは原則OFFが妥当。

### 6.4 実行運用のハマりどころ
- `sudo`実行でartifact権限問題（書き込み不可）
- `ARTIFACT_DIR` 変数の展開ミスで summarize失敗
- timeoutの `kill-after` なしだとゾンビ的に長引くケース

## 7. 解決したこと
- 速度問題（長時間化）:
  - `RUN_TIMEOUT_KILL_AFTER_SEC` を導入した hard-kill で改善
  - BENCH_FAST時の無駄待ちを設定で削減
- 空振りPhase2:
  - `phase2_on_empty_force_disable=1` 運用で抑制
- delay過多:
  - RiskPredictor delayを条件付き化して低リスク待機を削減
- timeout再試行過多:
  - 同一原因かつ低優先度の再試行を抑制

## 8. まだ未解決（本質課題）
- **confirmedの安定到達（毎runで3以上）**
  - 最新5runでも運用ゲートは `2 pass / 3 fail`
  - fail理由は全て `confirmed_below_minimum`

## 9. 直近の実運用ゲート結果（allowed-missing込み）

### 9.1 旧5run
- artifact: `/tmp/bench_fast_fix_gate5_20260512_215613/.../benchmark_scn01_07_P0`
- 結果: `gate_pass=1 gate_fail=4`

### 9.2 最新5run
- artifact: `/tmp/bench_fast_fix_gate5_20260512_231151/.../benchmark_scn01_07_P0`
- 結果: `gate_pass=2 gate_fail=3`
- 改善はあるが、まだ不十分

## 10. 現時点のベースライン（次チャット開始時の推奨）
- 速度と品質のバランスが最も良い現構成:
  - `BENCH_FAST=1`
  - `SHIGOKU_DEEPSEEK_THINKING_ENABLED_FOR_LIGHTWEIGHT=false`
  - `SHIGOKU_PHASE2_ON_EMPTY_FORCE_DISABLE=1`
  - `SHIGOKU_RISK_PREDICTOR_DELAY_HIGH_ONLY=1`
  - `SHIGOKU_PHASE1_TIMEOUT_RETRY_SAME_CAUSE_GUARD=1`
  - `SHIGOKU_INJECTION_BATCH_PARALLELISM=2`
  - `RUN_TIMEOUT_KILL_AFTER_SEC=30`

## 11. 次チャットで最短再開する手順

### 11.1 まずは再現3run（ガード閾値チューニング）
`confirmed`安定化のため、次はガードを少し緩めて試す。

```bash
cd /home/bbb/Documents/App/Shigoku
RUN_TAG=$(date +%Y%m%d_%H%M%S)
RT="/home/bbb/Documents/App/Shigoku/tmp/bench_fast_tune_guard_${RUN_TAG}"
ART="${RT}/workspace/projects/127.0.0.1:8888/reports/benchmark_scn01_07_P0"

SHIGOKU_MODEL=deepseek/deepseek-v4-flash \
SHIGOKU_MODEL_OUTPUT=deepseek/deepseek-v4-pro \
SHIGOKU_MODEL_LIGHTWEIGHT=deepseek/deepseek-v4-flash \
SHIGOKU_DEEPSEEK_THINKING_ENABLED_FOR_OUTPUT=true \
SHIGOKU_DEEPSEEK_THINKING_ENABLED_FOR_LIGHTWEIGHT=false \
SHIGOKU_RISK_PREDICTOR_DELAY_DISABLE=1 \
SHIGOKU_PHASE1_TIMEOUT_RETRY_SAME_CAUSE_GUARD=1 \
SHIGOKU_PHASE1_TIMEOUT_RETRY_GUARD_MIN_PRIORITY=55 \
SHIGOKU_MAX_DERIVED_TASKS_PER_SESSION=40 \
SHIGOKU_MAX_SESSION_TASKS=300 \
RUNTIME_CWD="${RT}" PROFILE_ID=P0 SEED_SET_ID=scn01-07_seed_v2 AUTO_APPLY_SEED=1 \
BENCH_FAST=1 BENCH_ULTRA=0 RUN_COUNT=3 RUN_TIMEOUT_SEC=900 RUN_TIMEOUT_KILL_AFTER_SEC=30 \
bash scripts/bench/run_scn01_07_p0_5runs.sh
```

### 11.2 集計
```bash
./.venv/bin/python scripts/bench/summarize_scn_benchmark.py \
  --artifact-dir "${ART}" \
  --output-csv "${ART}/summary_results.csv" \
  --output-summary "${ART}/summary.json"
cat "${ART}/summary.json"
```

### 11.3 必須: report/session整合性チェック
```bash
for m in "${ART}"/P0_run*_meta.env; do
  r=$(awk -F= '/^report_path=/{print $2}' "$m")
  .venv/bin/python scripts/verify_report_session_consistency.py --report "$r"
done
```

### 11.4 実運用ゲート（allowed-missing込み）
```bash
PASS=0; FAIL=0
for m in "${ART}"/P0_run*_meta.env; do
  r=$(awk -F= '/^report_path=/{print $2}' "$m")
  if ./.venv/bin/shigoku-ops --json report gate --report "$r" \
      --allowed-missing scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology \
      --confirmed-min 3 --candidate-max 2 --confirmed-poc-missing-max 0 --reason-code-missing-max 0 \
      | jq -e '.gate_passed == true' >/dev/null; then
    PASS=$((PASS+1))
  else
    FAIL=$((FAIL+1))
  fi
done

echo "gate_pass=${PASS} gate_fail=${FAIL}"
```

## 12. 判断ルール（次チャット用）
- `gate_pass >= 2/3` なら、その設定を5runで再検証
- `gate_pass < 2/3` なら、次の順で進める
  - `phase1_timeout_retry_guard_min_priority` をさらに緩める（55→45）
  - それでもダメなら元4（Phase1本格並列化）へ着手

## 13. 注意（作業環境）
- ワークツリーはかなり dirty。**無関係変更は触らない/戻さない**。
- `report`/`session`/`gate` は CLI-first で `shigoku-ops` を優先。
- Pythonは基本 `.venv/bin/python` を使用。
