---
task_id: SGK-2026-0445
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0445_wire-hybrid-judge-into-swarm-live.md
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/reports/2026-08-12_sgk-2026-0445_wire-hybrid-judge-into-swarm-live_work_report.md
created_at: '2026-08-12'
updated_at: '2026-08-12'
tags:
- shigoku
- vdp
- security-sensitive
---

# 作業ログ: SGK-2026-0445（T3 ハイブリッド判定＋ライフサイクルの swarm 配線）

## 変更要約

| 日付 | 内容 | 参照 |
|---|---|---|
| 2026-08-12 | 設計承認関門: ①配線点（manager.py Phase-2 merge ゲート）②再現 sender 封印接続（SealedReproductionChecker・ガード列再利用）③poc_judge 予算（10 回/600s・fail-closed）④funnel emit 設計（REASON_CODES additive・OUTCOMES 不変）⑤confirmed 成果物（ledger マスク保存）を提示 → ユーザー承認。計画書 §設計付録 A〜F に固定 | 計画書 §設計付録 |
| 2026-08-12 | Lane A: sealed_reproduction_checker.py（SealedReproductionChecker / PoCJudgeBudget / BudgetedPoCJudge / JudgeBudgetExhausted）＋ __init__.py export（24 passed・回帰 0） | 計画書 §B/C |
| 2026-08-12 | Lane B（本ログ）: ①funnel REASON_CODES に hybrid_confirmed / hybrid_refuted / hybrid_parked / hybrid_needs_human / reproduction_transport_error を additive 追加 ②manager.py Phase-2 merge ゲートに T3 配線（有効化フラグ既定 off・ledger パスは ProjectManager の projects-base-dir 解決を再利用・予算付き judge・例外写像→ai_judge=None 再試行・lifecycle apply_verdict→ledger put→run 終了時 save・F5 verdict 系 emit）③settings に t3_hybrid_enabled（additive・既定 off）④テスト 13 件（OFF byte-identical / CONFIRMED / INCONCLUSIVE / NEEDS_HUMAN / 予算超過・ValueError 写像 / 終端・parked スキップ / 語彙 strict / フラグ・パス解決） | 計画書 §A/D/E/F |
| 2026-08-12 | 検証: funnel trace + swarm hooks + T3 wiring 42 passed・validation 138 passed（test_phase_b_readiness 2 件は既存環境要因・baseline でも同一失敗）・injection 全体 611 passed（test_cmd_ssrf_timeout_fix 3 件は既存環境要因・baseline でも同一失敗） | 本ログ検証 |
| 2026-08-12 | 循環 import 修正: manager.py の module-level validation import（Lane B で追加）が validation→candidate_lifecycle→injection→manager→candidate_ledger→candidate_lifecycle(partial) のループを閉じていたため、全 validation import を関数内 lazy import へ移動（+ from __future__ import annotations・TYPE_CHECKING 型ヒント・ValidationResult は docstring 参照のみのため削除）。OFF テストは定義元モジュール patch 方式に更新。検証: test_sealed_reproduction_checker.py 単体 24 passed（当初失敗→解消）・T3 wiring 13 passed・funnel 29 passed・validation 138 passed / 2 既存環境要因・injection 611 passed / 3 既存環境要因・import 単体 OK | 本ログ検証 |
| 2026-08-12 | 配線点の移動（計画書 §設計付録 A 修正・ユーザー承認）: 封印 run 2 回の実測で early-return 経路（fast-types）が merge ゲートをバイパスすることが確定したため、T3 判定を Phase-1 finding 確定直後（early-return 分岐の直前）にも配線。実装は `_t3_run_hybrid_pass(task, findings)` ヘルパーに抽出（ledger open→budgeted judge→checker→lifecycle→per-finding apply→pass 終了時 save を一元化）し、phase1 地点・merge ゲート双方から呼び出し。merge 側は ledger 状態チェックで重複 judge なし（終端/parked スキップ・needs_more は T2 T5 で再判定）。テスト 4 件追加（early-return ON で CONFIRMED 到達＋F5 hybrid_confirmed＋ledger save／early-return OFF byte-identical／phase1 確定 finding の merge スキップ（judge 1 回）／needs_more 再判定 budget_used=2）。検証: T3 wiring 17 passed・funnel 29 passed・validation 138 passed / 2 既存環境要因・injection 615 passed / 3 既存環境要因・import 単体 OK | 本ログ検証 |
| 2026-08-12 | 再現 sender へのスコープ供給（計画書 §設計付録 B 追記・ユーザー承認）: 封印 run 4 回の実測で SealedReproductionChecker が scope_definition=None のまま（fail-closed → reproduction 常に not_run → needs_more 止まり・F5 未達）であることが確定したため、`_build_sealed_reproduction_scope(target_url)` を追加（ターゲット自身の host[:port] のみ・strict_mode=True・不正入力は None→fail-closed。EthicsGuard の hostname/netloc 両候補マッチにより host:port 完全一致のみ許可）。`_t3_run_hybrid_pass` の checker 構築に scope_definition を供給（コンストラクタ注入 checker は従来どおり優先）。テスト 5 件追加（host:port 構築・plain host・不正入力 fail-closed・同一 host:port のみ許可の精度検証・real checker 統合＝スコープ供給で再送が実際に試行され CONFIRMED 到達）。検証: T3 wiring + sealed checker 46 passed・funnel 29 passed・validation 138 passed / 2 既存環境要因・injection 620 passed / 3 既存環境要因・import 単体 OK | 本ログ検証 |
| 2026-08-12 | F5 emit 修正＋ledger 分散原因修正（run5 実測・ユーザー承認）: ①F5 emit を verdict.state ベースから apply_verdict 後の record.state（LifecycleState）ベースへ変更 — T6 予算切れ棚上げ（verdict=NEEDS_MORE・budget_used が max_visits 到達 → inconclusive_parked。run5 の b7aa7f57bce4 が budget_used=3・reason=budget_exhausted で棚上げされたのに F5 未 emit だった）も hybrid_parked を emit するように。hybrid_final_state は LifecycleState.value（"inconclusive_parked" 等）。②ledger 1 件のみの原因: `_resolve_candidate_ledger_path` が task.target（パス・クエリ付きフル URL）をプロジェクト名に使ったため、finding の URL パスごとに ledger が分散生成されていた（run5 実物: 11 レコードが 9 ファイルに分散・`workspace/projects/localhost:3000/rest/products/search?q=/candidate_ledger.json` 等。プロジェクトディレクトリの実体は host:port 単位）。`_extract_target_host_port` 共通ヘルパーを追加し host[:port] 抽出に修正（スコープ構築と共用・全 finding が同一 ledger に集約）。テスト 3 件追加（T6 予算切れ棚上げ emit・needs_more 無 emit 維持・パス/クエリ正規化）。検証: T3 wiring + sealed checker 49 passed・funnel 29 passed・validation 138 passed / 2 既存環境要因・injection 623 passed / 3 既存環境要因・import 単体 OK | 本ログ検証 |
| 2026-08-12 | **封印 run 最終（run6 = session_20260812_175220・完了条件実測）**: funnel **F5 by_stage 0→5**（438f9bac437c / 67001d154ed0 / b7aa7f57bce4 / eac69dd7387e / f4a0c33cba59 が F5 reached）・ledger 11 候補を単一ファイルに保存（**inconclusive_parked ×4**（budget_exhausted・T6 棚上げ）・**refuted ×1**（b7aa7f57bce4・ai_counter_evidence = 証拠内矛盾の実測反証・D3 契約どおり）・needs_more ×6・**confirmed 0 = 誤確定ゼロ実証**）・poc_judge 22 calls 実起動・GET-only 20/20・state_change 0・ledger マスク `[PII:` 18 箇所・生秘密 0・consistency consistent。前 run の修正（配線点移動・スコープ供給・F5 emit・ledger 集約・chown）の効果を実測で確定 | 本ログ検証・報告書 §1 |
| 2026-08-12 | ドキュメント閉鎖: 完了報告書作成（work_report・§19 完了条件判定 all PASS・in_scope_blocker 0 件）・work_log done 化・task_registry を done に更新・plan を done/ へ移動 | 報告書 |

## 次アクション

- 封印 run 最終（run6）で完了条件 1〜4 を実測（F5 0→5・ledger 11 候補・誤確定ゼロ・GET-only・consistency consistent）→ 本タスク done。
- run 内調査キャップ配線（T2 allocate_investigation_budget・run_budget=10）と judge token 数記録（run_ledger_llm_usage）・YAML 予算配線は未配線（SGK-2026-0445-D01・親ロードマップ SGK-2026-0442 で追跡）。
- confirmed の実戦実測はターゲット状態依存（run6 では 3条件AND 未達 = 誤確定ゼロ実証）（SGK-2026-0445-D02・SGK-2026-0442 で追跡）。
- T4（SGK-2026-0446・ロードマップ定義済み）: Haddix レポートへの 確定/保留/人間送り 明記。
