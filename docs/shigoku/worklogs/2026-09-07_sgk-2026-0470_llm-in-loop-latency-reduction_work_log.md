---
task_id: SGK-2026-0470
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-03_sgk-2026-0470_llm-in-loop-latency-reduction.md
- docs/shigoku/reports/2026-09-07_sgk-2026-0470_llm-in-loop-latency-reduction_work_report.md
created_at: '2026-09-07'
updated_at: '2026-09-07'
tags:
- shigoku
- performance
- llm
- robustness
---

# SGK-2026-0470 作業ログ

## 1. 測定（事実確定）
- 既存 RunLedger spool（`workspace/projects/localhost:3000/sessions/run_ledger/`）の `event_type==llm_called` を
  `actor_name` で集計。run 04f64975=398/poc_judge269(68%)、run 36f88cad=272/poc_judge217(80%) を再現。
- 候補台帳 190件: cors 150(79%)/sqli 30/xss 8/bac 2、状態 confirmed 28/needs_more 139/refuted 8/parked 15。

## 2. 実装（DeepSeek 指示 → Claude 独立検証）
- settings.py に 2 フラグ追加（`t3_prejudge_dedup_enabled` / `t3_skip_unchanged_rejudge_enabled`・既定 False）。
- Lever 2: `_judge_evidence_fingerprint`（PoCJudge._build_user_payload と同一射影）+ `_t3_apply_hybrid_verdict` で
  needs_more 記録の指紋一致時スキップ、判定実施時に `evidence_summary["judge_fingerprint"]` を刻印。
  sha256 hex は台帳の PII マスカで PHONE_JP 誤マスク→base-26 英字55字に是正（save/load 往復テスト緑）。

## 3. 制御 A/B（方式A・実データ固定入力）
- 実走行 04f64975 の session task_execution_records から本物 findings 110件を復元、台帳の実判定を finding_id で join。
- 素朴版 Lever 1（代表のみ判定）: 246→81(67.1%) だが **confirmed 1件消失**（SQLi `data` 署名で needs_more を代表に選び confirmed 破棄）。
- 原因: 強さ(severity/has_poc/confidence)が実確定を捉えない＋レポート時 0464 と違い判定前なので確定前候補を捨てうる非対称。

## 4. confirm-gated 是正（opencode 経由・本家 DeepSeek）
- `_prejudge_dedupe`（破棄版）を `_prejudge_order_rep_first`（並べ替えのみ・破棄なし）に置換。
  `_t3_record_confirmed` 追加。判定ループを「代表先行→確定した署名のみ残りスキップ／未確定は全件判定」に。
- opencode は `setsid` で harness から切り離して起動（harness バックグラウンドはメモリ監視 kill 対象）。
  `-m deepseek/deepseek-v4-flash`＋preset personal-dev（全役割本家）。session ses_f87c9e4e7ffe3Y5645lt6cHNRE。
  export で providerID=deepseek/modelID=deepseek-v4-flash のみ（35/36）を確認。

## 5. 検証（Claude 独立）
- 変更: manager.py＋テストのみ。凍結5 `git diff --quiet HEAD` exit 0。AST OK。
- pytest（PYTHONPYCACHEPREFIX で root所有 __pycache__ 回避）: 対象58 / 注入スイート 646 passed・回帰0。
- 制御 A/B 再実行（confirm-gated 実コード）: **246→82(66.7%減)・confirmed 消失0・破棄0 → PASS**。
- 製品非依存 token 0（追加行 denylist grep）。

## 6. 環境メモ
- Caido 8081 稼働。opencode from Claude の運用知見をメモリ [[opencode-from-claude-detached]] に保存。
