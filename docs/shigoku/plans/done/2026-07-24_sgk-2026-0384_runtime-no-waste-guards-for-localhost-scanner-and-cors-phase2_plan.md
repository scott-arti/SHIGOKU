---
task_id: SGK-2026-0384
doc_type: plan
status: done
parent_task_id: SGK-2026-0383
related_docs:
- docs/shigoku/plans/done/2026-07-24_sgk-2026-0383_smartcmdssrf-finish-safe-verdict-false-positive-fix_plan.md
- docs/shigoku/reports/2026-07-24_sgk-2026-0384_runtime-no-waste-guards-for-localhost-scanner-and-cors-phase2_work_report.md
- docs/shigoku/worklogs/2026-07-24_sgk-2026-0384_runtime-no-waste-guards-for-localhost-scanner-and-cors-phase2_work_log.md
title: Runtime no-waste guards for localhost scanner and CORS Phase2
created_at: '2026-07-24'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/core/engine/master_conductor.py, src/core/agents/swarm/injection/manager.py
---

# 実装計画書：Runtime no-waste guards for localhost scanner and CORS Phase2

## 1. 達成したいゴール（ユーザー視点）

- [x] DVWA low のように対象が `http://localhost:4280/` で確定している場合、asset `localhost` から `https://localhost` の無応答スキャンを生成しない。
- [x] CORS専用チェックで finding なし・弱い兆候なし・エラーなしの場合、APIパスであってもPhase2の長時間待ちに進ませない。
- [x] XSSは今回実装対象外とし、時間ではなく「入力/反射/DOM到達経路の有無」で判断する方針だけを申し送りに残す。

## 2. 全体像とアーキテクチャ

- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: asset再スキャンURLの生成時に、現在の対象URLと同じホストならscheme/portを引き継ぐ。
  - `src/core/agents/swarm/injection/manager.py`: CORSのみのPhase1結果が無信号なら、high-risk API扱いによるPhase2強制を解除する。
  - `tests/core/engine/test_master_conductor_api_candidate_routing.py`: localhost assetのURL生成回帰テストを追加する。
  - `tests/core/agents/swarm/test_injection_manager.py`: quiet CORS/API endpointのPhase2スキップ回帰テストを追加する。
- **データの流れ / 依存関係:**
  - `context.target_info["target"]` / `context.target_info["scheme"]` / `context.target_info["host"]` -> `_resolve_asset_scan_url()` -> `web_scanner.params["url"]`
  - CORS Phase1 result -> `phase1_vuln_types` / `phase1_signals` -> `cors_no_signal_safe_skip` -> `phase1_safe_skip_no_signal`

## 3. 具体的な仕様と制約条件

- **入力情報 (Input):**
  - asset名: `str`
  - target情報: `context.target_info`
  - CORS Phase1結果: `phase1_url_results`
- **出力/結果 (Output):**
  - assetが現在のtargetと同じホストなら、targetのscheme/portを使ったscan URLを生成する。
  - CORS Phase1が無信号なら、Phase2ブロック理由に `cors_no_signal` を残して早期終了する。
- **制約・ルール:**
  - 並列化はしない。
  - XSSの早期打ち切りは今回は実装しない。
  - 時間の長さだけでは打ち切らず、証拠がないことを条件にする。

## 4. 実装ステップ（AIに指示する手順）

- [x] ステップ1: `https://localhost` 誤生成の赤テストを追加する。
- [x] ステップ2: CORS/API無信号Phase2の赤テストを追加する。
- [x] ステップ3: `master_conductor.py` に `_resolve_asset_scan_url()` を追加し、同一ホストではtargetのscheme/portを引き継ぐ。
- [x] ステップ4: `manager.py` に `cors_no_signal_safe_skip` を追加し、CORSのみの無信号結果ではPhase2強制を解除する。
- [x] ステップ5: 対象テスト、周辺テスト、構文チェック、最新レポート/セッション整合性を確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）

- [x] [重要度:中] XSS短縮は未実装。時間ではなく「入力経路・反射・DOM到達経路が存在しない」ことを機械判定できる場合のみ、別タスクで検討する。
- [x] [重要度:低] graphify update は既存グラフの比較/クラスタ処理で長時間停止したため、今回は未完了として記録する。

### 5.1 deferred_tasks

deferred_tasks: []
