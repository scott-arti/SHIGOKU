---
task_id: SGK-2026-0448
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-13_sgk-2026-0448_confirm-real-bug-three-levers.md
- docs/shigoku/reports/2026-08-13_sgk-2026-0448_confirm-real-bug-three-levers_work_report.md
created_at: '2026-08-13'
updated_at: '2026-08-13'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
---

# 作業ログ: SGK-2026-0448 — 本物の対象で「確定1件」を実際に出すための3レバー

| 日付 | 内容 | 参照 |
|---|---|---|
| 2026-08-13 | フェーズ0（STEP 1・コード変更なし）: 本物 Caido 起動（`caido-cli --listen 127.0.0.1:8081`）+ Juice Shop コンテナ起動・転送ガード事前確認（75002B 同一 200 >512B → PASS+WARNING・0447 と同一）・封印 run `session_20260813_223445`（preflight PASS・consistent） | 計画書「フェーズ0結果」 |
| 2026-08-13 | フェーズ0 トレース表（5 候補）: **レバー1 confirmed**（`Early return (phase1_early_return)` ×3・legacy 経路が payout_grade_hold を迂回）・**レバー2 confirmed**（authz 2 件が signals 充足・marker authz_diff 一致でも missing_impact）・**レバー3 否定**（配線済み・機械フロアで未到達・authz_diff 再現不能は設計） | 計画書「フェーズ0結果」 |
| 2026-08-13 | 設計提示 → **ユーザー承認**（question ツール）→ STEP 2 へ | 計画書「修正設計」 |
| 2026-08-13 | STEP 2 実装（fix-1）: レバー1 `should_early_return_phase2`（オプトイン既定 OFF）+ レバー2 `authz_fields.py`（機械的 impact/repro）+ manager.py 4 箇所・idor.py 3 箇所配線。555 passed・payout_grade.py diff 0 | 本報告書 §1 |
| 2026-08-13 | オーケストレータレビュー: **object_ab_idor_probe の誤発火リスク発見**（`build_authz_differential` の `unauth_success` トークンが認証済み test でも付与 → 偽の「未認証許可」impact 捏造）。fix-1 へ訂正指示 → helper を役割明示 2 分岐化・manager site2 / idor cross_session / id_manipulation の配線を除外・site4 の status 役割修正。555 passed 維持 | 本報告書 §1 |
| 2026-08-13 | STEP 3 確定 run: `master_conductor.py` 2 箇所へ一時オプトイン追加 → 封印 run `session_20260813_232923` → **byte-exact 復元**（sha256 `f923709f…` 一致）。funnel: early_return 3→1・authz 2 件 payout_grade PASS・Phase-2 で新規 sqli 候補 `b41d9c6e47cd`（impact 空 → deferred D01） | 計画書「STEP 3」 |
| 2026-08-13 | 検証: 対象テスト 64 passed / スライス 555 passed・`check_vdp_product_independence.py` exit 0・payout_grade.py diff 0・PCR-P1 無変更・GET-only（OPTIONS 17 ブロック）・consistency consistent・commit なし | 本報告書 §2 |
| 2026-08-13 | 完了判定: (a) 確定 0 → **(b) 候補単位 fail-closed 説明で完了条件 3 満たす**。§19 分類: in_scope_blocker 0 / deferred D01-D03 / observation O1-O4 | 本報告書 §5 |
| 2026-08-13 | ドキュメント閉鎖: 計画書にフェーズ0/STEP2/STEP3 追記 → `done/` へ移動・作業報告書/作業ログ作成・registry/ledger を done 更新・sync → validate 0 エラー | 本報告書 |

## 次アクション
- D01: Phase-2/LLM 生成 finding の impact 機械埋め拡張（追跡: SGK-2026-0442 系）
- D02: authz_diff の GET-only 内再現設計見直し（追跡: SGK-2026-0442 系）
- D03: 0447 D-B4-1 継続追跡
- ユーザーによる commit（オーケストレータ検証済み）
