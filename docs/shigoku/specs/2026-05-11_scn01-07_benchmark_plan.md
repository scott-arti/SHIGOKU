---
task_id: SGK-2026-0090
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-11'
updated_at: '2026-05-19'
---

# SCN01-07 測定用ベンチ計画（固定seed・固定session / 境界tightening）

## 1. 目的
- SCN01-07 の検出品質を、再現可能な条件で数値化する。
- `confirmed` / `candidate` の境界条件を段階的に tightening し、取りこぼし率（FN）と誤検知率（FP）を同時に追跡する。

## 2. スコープ
- 対象シナリオ:
  - `scn_01_idor_bola_object_access`
  - `scn_02_mass_assignment_object_update`
  - `scn_03_injection_input_tampering`
  - `scn_04_endpoint_enumeration_bfla`
  - `scn_05_rate_limit_resilience`
  - `scn_06_data_exposure_diff`
  - `scn_07_token_trust_boundary`
- 非対象: SCN08-12（本計画では評価軸から除外）

## 3. 前提固定（Primary Source of Truth）
- report: `/home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260510_142342.md`
- session: `/home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:8888/sessions/session_20260510_142337.json`
- consistency checker verdict:
  - `status=consistent`
  - `rerun_required=false`

## 4. ベンチ設計
### 4.1 再現テストセット（固定seed・固定session）
- 目的: 同一条件で検出率が再現するかを測る。
- 入力固定:
  - 同一 target（`127.0.0.1:8888`）
  - 同一 seed セット（7シナリオに必要な route/param 群を固定）
  - 同一 session ファイル（ベースラインをコピーして使用）
- 実行固定:
  - 1セット = 5 run（最小）
  - run ごとに report/session を保存し、後段で比較

### 4.2 境界tightening実験（confirmed/candidate）
- 目的: 判定を厳しくしたときの FN/FP 変化を把握する。
- 境界プロファイル（3段階）:
  - P0（現行）: 既定値
  - P1（中 tightening）: confirmed の成立要件を1段厳格化
  - P2（強 tightening）: confirmed 要件をさらに厳格化、candidate昇格を抑制
- 各プロファイルで 5 run 実行（合計 15 run）。

## 5. 測定指標
- シナリオ検出率（SCN別）
  - `DetectionRate(scn) = DetectedRuns(scn) / TotalRuns`
- 再現率（confirmed）
  - `ReproConfirmed = ConfirmedRuns / TotalRuns`
- 取りこぼし率（FN率）
  - `FNRate = 1 - Recall`
  - Recall は「期待される検出イベント」を分母に計算
- 誤検知率（FP率）
  - `FPRate = FalsePositives / (FalsePositives + TrueNegatives)`
  - 運用上はまず `FalsePositives / ReportedFindings` も併記
- 境界移動感度
  - `DeltaConfirmed(Px-P0)`
  - `DeltaCandidate(Px-P0)`
  - `DeltaFN(Px-P0)`
  - `DeltaFP(Px-P0)`

## 6. 実行手順
### Step A: 前提整合チェック
```bash
cd /home/bbb/Documents/App/Shigoku
python3 scripts/verify_report_session_consistency.py \
  --report /home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:8888/reports/haddix_report_20260510_142342.md
```

### Step B: 実行バッチ
- 各 run の report/session を `workspace/projects/127.0.0.1:8888/reports|sessions` に保存。
- run メタ情報として `profile_id`, `seed_set_id`, `session_id`, `started_at` を記録。

### Step C: findings 抽出
```bash
cd /home/bbb/Documents/App/Shigoku
python3 scripts/inspect_session_findings.py --session <session_path>
```

### Step D: gate 値観測（副次KPI）
```bash
cd /home/bbb/Documents/App/Shigoku
python3 scripts/check_initial_release_gate.py \
  --report <report_path> \
  --allowed-missing scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology \
  --confirmed-min 3 \
  --candidate-max 2 \
  --confirmed-poc-missing-max 0 \
  --reason-code-missing-max 0 \
  --required-confirmed-classes access_control,idor_bola,mass_assignment,endpoint_bfla \
  --required-class-confirmed-min 1
```

## 7. 収集テーブル（最小）
- `run_id`
- `profile_id`（P0/P1/P2）
- `seed_set_id`
- `session_path`
- `report_path`
- `scn_01..07_detected`（bool）
- `confirmed_count`
- `candidate_count`
- `fn_count`
- `fp_count`
- `gate_status`
- `reason_codes`

## 8. 判定基準（現実的な暫定）
- Go 条件（P1採用候補）:
  - SCN01-07 の平均 DetectionRate が P0 比で低下しない（許容低下 3%以内）
  - FP率が P0 比で改善
  - gate fail の増加が許容範囲内
- No-Go 条件:
  - いずれかの SCN が再現率 60% 未満
  - FN率が P0 比で有意に悪化

## 9. 実施順序（短期）
1. P0 で 5 run（現状ベースライン確定）
2. P1 で 5 run（第一 tightening）
3. P2 で 5 run（上限 tightening）
4. 3プロファイル比較表を作成し、採用境界を決定

## 10. リスクと緩和
- seed 偏りで SCN03/06/07 がぶれる
  - 緩和: seed セットを固定ID化し、run間で完全再利用
- 単一 session 依存で過学習的な最適化が起きる
  - 緩和: 第2フェーズで session を 2本目追加して外部妥当性確認
- confirmed 厳格化で見かけ上の検出数が減る
  - 緩和: confirmed/candidate 合算推移と FN/FP を同時評価

## 11. 完了条件
- SCN01-07 について、P0/P1/P2 比較の定量表が埋まっている。
- 境界採用案（P0維持 / P1採用 / P2採用）が数値根拠付きで決定できる。
- 再現コマンド、利用 report/session、reason code を第三者が追試可能。
