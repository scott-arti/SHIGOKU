---
task_id: SGK-2026-0440
doc_type: work_log
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/done/2026-08-11_sgk-2026-0440_finding-pipeline-instrumentation.md
- docs/shigoku/reports/2026-08-11_sgk-2026-0440_finding-pipeline-instrumentation_work_report.md
created_at: '2026-08-11'
updated_at: '2026-08-11'
tags:
- shigoku
- vdp
- diagnostics
---

# 作業ログ: SGK-2026-0440（finding-pipeline 計装）

## 実施内容

1. **診断（exp-1/exp-3・読取のみ）**: swarm 攻撃経路の診断イベント 0 件を確認。
   F0-F6 の計装地点を一次証拠で特定（Phase1/Phase2・early-return・suppression・
   FindingValidator・URL レベル skip）。`Finding.id`（md5）を安定キーに採用。
   default-off は既存 `diagnostics.enabled` を再利用（0425 契約）。
   `DiagnosticEventV1.from_dict` が strict のため vdp_contract 新キー
   `finding_funnel_v1` を additive 経路に選択。
2. **F0-F6 マッピング設計提示 → ユーザー承認**。
3. **実装（fix-5: レコーダ+swarm フック / fix-6: session/report 統合・並列）**:
   - `finding_funnel_trace.py`: FindingFunnelRecorder（strict vocab・first-failure
     規約・決定性 section・config-guarded singleton）
   - F0（MC タスク生成・ownership suppression の記録化）/ F1（specialist dispatch・
     URL skip 6 種）/ F2（manual_verify finding 生成 6 箇所）/ F3（Phase2 開始・
     skip・budget・timeout）/ F4（FindingValidator gate・auto_reverification）
   - session: `inject_vdp_section_to_session_payload` に additive 運搬
   - report: `embed_finding_funnel_index`（None → markdown 不変）・
     `HaddixFinding.additional_info` に first_failure 付与・extractor additive
4. **統合検証**: 主要 105 passed・swarm/engine 広域 1386 passed・38 failed は
   **HEAD worktree と IDENTICAL**（独立 worktree 比較で 0440 起因なしを確定）。
   stash を絡めた比較は不安定状態で無効と判明（0439 はコミット済みで
   stash は 0440 のみ退避・diff 0 確認後に drop）。
5. **封印 run（session_20260811_091439）**: finding_funnel_v1 に **entries 8 =
   ユニーク候補 8 全てをカバー**（raw NOT in funnel: []）。
   **first-failure: F3 phase2_skipped_early_return ×5 / F0 task_suppressed_ownership ×3**。
   レポートに機械可読ブロック埋め込み。GET-only・安全0・secret 0・consistent・
   preflight exit 0・byte-identical・実行1回・所有権 bbb。

## 観測メモ

- レポート表示 Candidate:16 は finding dict 行数（同一 finding_id の重複行を含む）。
  ユニーク候補は 8 で funnel は全てに付与。重複記録は既存挙動（D01 として追跡）。
- F2 が by_stage で 5 なのは、一部 finding が F2 記録前に F3 イベントで
  entry 化された経路の反映（計測順序・計測の欠落ではない）。
- 既存 LSP 警告（pii_masker:371 / network_client:141,452 / realpath:350,425,444 /
  reauth:39）は全て HEAD 由来・タッチせず。

## 成果物

- 変更: src/core/engine/finding_funnel_trace.py（新規）/ master_conductor.py /
  master_conductor_session_service.py / main.py / src/reporting/finding_extractor.py /
  haddix_formatter.py / haddix_submission_internal_formatter.py /
  vdp_report_projection.py / injection/manager.py + テスト4ファイル
- session: workspace/projects/localhost:3000/sessions/session_20260811_091439.json
- report: workspace/projects/localhost:3000/reports/haddix_report_20260811_091439.md
