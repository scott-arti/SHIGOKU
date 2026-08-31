---
task_id: SGK-2026-0462
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/2026-08-22_sgk-2026-0459_active-save-sink-discovery.md
- docs/shigoku/plans/2026-08-28_sgk-2026-0460_cross-target-state-isolation.md
- docs/shigoku/plans/2026-08-29_sgk-2026-0461_browser-evidence-confirm-enforce.md
- docs/shigoku/reports/2026-08-30_sgk-2026-0462_canonical-save-endpoints-wiring_work_report.md
- docs/shigoku/worklogs/2026-08-30_sgk-2026-0462_canonical-save-endpoints-wiring_work_log.md
- docs/shigoku/plans/2026-08-30_sgk-2026-0463_stored-stage2-redirect-marker-fix.md
created_at: '2026-08-30'
updated_at: '2026-09-01'
tags:
- shigoku
- vdp
- detection
- xss
- stored
- orchestration
---

# SGK-2026-0462 計画書 — canonical VDP 経路で save_endpoints を injection タスクへ配線（保存型XSSの第2段階＝ブラウザ発火を到達させる）

## 目的（Objective）

canonical VDP のフル走行で、保存型XSS（POST保存sink）に対する **ブラウザ発火検証（第2段階 `_attempt_stored_revisit_validation`）** が起動し、実ブラウザ dialog 証拠（browser_evidence）が生成されるようにする。これにより SGK-2026-0461 の browser_evidence 自動確認フローが受理対象を得て、**formal confirmed=1（variant=stored・dialog_observed=True）** に到達する。

## 背景・真因（2026-08-30 実走行＋コード引用で Claude が確定）

実走行 session_20260830_002046（練習台 127.0.0.1:5008・Caido 8081・Juice Shop 起動下）:
- 結果 **Confirmed 0 / Candidate 13**（全件 xss on 'comment'・evidence_type=`real_http`・reason_code=`browser_execution_missing`）。
- 練習台アクセスログで第2段階固有の良性マーカー POST（`sgk<hex>`）= **0件** → ブラウザ発火検証は一度も起動していない。

真因チェーン（引用）:
1. 第2段階ゲート `smart_xss.py:1248-1252`: `method in (POST,PUT,PATCH) and params["revisit_candidates"] and not params["reflection_url"]`。
2. `method=POST` は manager が save_ep を一致させたとき成立（`manager.py:3106` `resolved_method=save_ep_method` → base_params["method"] `:3124`）。save_ep 一致は `_match_save_endpoint`（`:354`・scheme+netloc+path 照合／query無視）で `current_context["save_endpoints"]`（`:2984` が `_context` から読む）が前提。
3. `save_endpoints` は **build 時 `master_conductor.py:14758-14760`（recon-category タスク builder）でのみ** `task_params["_context"]["save_endpoints"]` に注入される。
4. canonical VDP の injection ディスパッチはこの builder を通らないため、`_context` に save_endpoints が載らない。dispatch 時の `_merge_accumulated_context`（`:8172`・呼び出し `:7718`）は **既存キーの保持のみ**で、元が無ければ足せない。さらに `:7716 if not accumulated_context.is_empty()` によりマージ自体がスキップされ得る。
5. 結果 save_ep 不一致 → resolved_method=GET（実測 poc に `method=GET` メタ）→ ゲート不成立 → 第2段階スキップ → HTTP反射のみ検出（real_http）→ browser_evidence 不在 → SGK-2026-0461 の確認フロー不起動 → Confirmed 0（fail-closed として正しい）。

位置づけ: これは **検出/オーケストレーション側（save_endpoints→_context 配線）** の課題であり、確定バー5ファイルにも SGK-2026-0461 の確認フローにも属さない。SGK-2026-0461 の B 実装自体は健全（ユニット/回帰/token0/バー無改変で検証済み）。

## 完了契約（Fixed completion criteria）

- CB-A: 全 injection タスク（category / canonical VDP 両方）の dispatch 時に `_context["save_endpoints"]`（および forms_by_url / url_evidence_by_url）が確実に載る。sidecar 不在時は no-op（既存挙動 byte-identical）。
- CB-B: 練習台5008 フル走行で保存型XSSが method=POST 解決 → `_attempt_stored_revisit_validation` 起動（マーカーPOST発生）→ ブラウザ dialog 観測（browser_evidence）→ SGK-2026-0461 確認フロー起動 → **formal confirmed=1（variant=stored・dialog_observed=True）**、consistency=consistent、混入0。
- CB-C: DVWA 既知安全保留 不変（5候補・reason code）。確定バー5ファイル無改変。製品非依存 token0。新規/変更ユニット緑。

## 実装方針（推奨・最小・加算）

1. `_merge_accumulated_context`（`master_conductor.py:8172`）または dispatch RUNNING 遷移（`:7714-7719`）に、**injection タスク限定で** `_context` に save_endpoints が無い/空なら `_load_run_save_endpoints()` で補填する防御ロジックを追加。forms_by_url / url_evidence_by_url も同様（既存尊重）。
2. `:7716 accumulated_context.is_empty()` によるスキップ経路でも injection タスクには補填が効くようにする。
3. 既存 `14758-14760` は温存（idempotent）。canonical/非canonical で分岐せず injection タスクなら一律保証する形が望ましい。

## NOT in scope

- 確定バー5ファイルの変更。SGK-2026-0461 の確認フロー（B）の変更。検出の発火判定・確定基準の緩和。
- browser_evidence 以外の evidence type の昇格。save-endpoint 発見ロジック自体の変更（サイドカーは既に正しく生成されている）。

## ガードレール

- カーブフィッティング禁止・確定基準を下げない・製品非依存 token0 維持（テストにも DVWA/juice 等パス片 NG・汎用 `/app/...`）。
- 追加のみ・sidecar 不在時 byte-identical。DVWA 既知安全保留と既存ゲートテストで回帰確認必須。
- 破壊的操作前に対象確認。commit は検証後・push はユーザー。Caido=127.0.0.1:8081。
- コーディングは DeepSeek、Claude が独立検証（DVWA baseline + gate scripts + 実走行 confirmed=1 + バー無改変 + token0）。
