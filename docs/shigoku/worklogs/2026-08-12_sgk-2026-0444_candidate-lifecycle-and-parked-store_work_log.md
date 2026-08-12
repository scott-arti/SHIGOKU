---
task_id: SGK-2026-0444
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0444_candidate-lifecycle-and-parked-store.md
- docs/shigoku/reports/2026-08-12_sgk-2026-0444_candidate-lifecycle-and-parked-store_work_report.md
created_at: '2026-08-12'
updated_at: '2026-08-12'
tags:
- shigoku
- security-sensitive
---

# 作業ログ: SGK-2026-0444（T2 候補ライフサイクル＋棚上げ保管＋復活）

## 変更要約

| 日付 | 内容 | 参照 |
|---|---|---|
| 2026-08-12 | 設計承認関門: ①状態機械（遷移表 T1〜T9）②ledger スキーマ/マスク方針（D5=マスク済サマリ投影）③復活条件（型付きトークン・消費記録で盲目再試行防止）④予算/ランキング（max_visits=3・max_age_days=30・threshold=0.67・run_budget=10）を提示 → ユーザー承認。計画書 §設計付録 A〜F に固定 | 計画書 §設計付録 |
| 2026-08-12 | 実装: candidate_lifecycle.py（LifecycleState/CandidateRecord/CandidateLifecycleManager・遷移表・D1/D3・no-op invariant・derive_triggers/revisit/allocate）・candidate_ledger.py（原子的書込・quarantine fail-safe・最低層 write API マスキング・冪等・token_map 非永続）・__init__.py additive export | 計画書 §E |
| 2026-08-12 | テスト 48 件（遷移表全行・round-trip+secret-scan・破損 fail-safe・復活合致/非合致/再トリガー不可・ランキング・run 跨ぎ統合）＋ T1 回帰 39 件 → 全 PASS。T1 判定/Evidence Validator/PCR-P1 diff 0・preflight exit 0・docs validator 0 | 作業報告書 §1 |
| 2026-08-12 | 計画書を done/ へ移動・作業報告書/作業ログ作成・台帳（registry yaml / ledger md,csv）更新・タスク done 化 | 台帳 |

## 次アクション

- T3（SGK-2026-0445・ロードマップ定義済み）: swarm 経路への配線（新情報供給・revisit 呼び出し・active 列接続）＋
  予算パラメータの YAML 配線。親タスクは done、配線は T3 で分離追跡。
- T4（SGK-2026-0446・ロードマップ定義済み）: needs_human の人間解決パス＋Haddix レポート明記。
