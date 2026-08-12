---
task_id: SGK-2026-0447
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0447_real-caido-rerun-and-fake-proxy-guard.md
- docs/shigoku/reports/2026-08-13_sgk-2026-0447_real-caido-rerun-and-fake-proxy-guard_work_report.md
created_at: '2026-08-13'
updated_at: '2026-08-13'
tags:
- shigoku
- vdp
- security-sensitive
- preflight
- sealed-run
---

# 作業ログ: SGK-2026-0447 — 本物 Caido 経由の正しい再実行 ＋ 偽プロキシ検知ガード

## 変更要約

| 日付 | 内容 | 参照 |
|---|---|---|
| 2026-08-12 | 設計提示（(a) ガード検証ロジック (b) 配置 (c) fail 挙動 (d) 再実行手順）→ ユーザー承認。指示書 `scratchpad/deepseek_0447_go.md` は存在せず → 計画書を正として進める旨をユーザー確認 | 計画書 §1・§8 |
| 2026-08-12 | Part A 実装（fix-1）: `check_forwarding()` additive（GET 3 本・同一 canned ≤512B → FAIL closed）+ entry_gate 配線 + snapshot フィールド + 実 fixture テスト（proxy_fakes.py・stdlib のみ・製品非依存）。検証 83 passed | 計画書 §2 Part A |
| 2026-08-12 | ora-1 レビュー → REQUEST_CHANGES（B1: 既定構成で guard fail-closed によりプローブ到達不能・テスト patch が本番挙動を隠蔽 / B2: 302・404 同一応答で誤検知）。修正方針をユーザー承認（B1: skip_guard additive・B2: status==200 限定判定） | 計画書 §2 判定追記 |
| 2026-08-12 | B1/B2 修正（fix-1）: `skip_guard=True`（preflight プローブ 1 か所のみ・ユーザー grep 検証条件）+ status==200 限定判定（>512B は PASS+WARNING）。183 passed。ora-1 再レビュー → APPROVE | 計画書 §2・§5-1 |
| 2026-08-12 | Part B run1（session_20260812_234723）: ゲート PASS（8081・forwarding PASS）・本物応答確認（75002B・canned 署名ゼロ）・**PATCH 13 件を検出**（mass_assignment recheck・GET-only 契約違反）・funnel 未記録（diagnostics off）を検出 | 本ログ検証 |
| 2026-08-12 | B3（funnel 記録のための diagnostics 有効化）・B4（GET-only ネットワーク境界ガード＋needs_human 写像）をユーザー承認（§19 スコープ追加）→ 計画書追記 | 計画書 §2・§5 |
| 2026-08-13 | B4 実装（fix-1）: `ReadonlyEnforcedError` + `sealed_run_get_only` + InjectionManager needs_human 写像（judge 非依存 ledger put）。ora-1 レビュー → APPROVE（D-B4-1: discovery 経路のサイレントスキップは deferred） | 計画書 §2 B4 |
| 2026-08-13 | run2（B4 有効）: **preflight abort** — ガードが Caido コントロールプレーン（POST /graphql・use_proxy=False）までブロック。修正方針（use_proxy=True 限定）を ora-1 確認 → APPROVE → fix-1 修正 → 再検証（SealedRun 7 passed・183 維持） | 本ログ検証 |
| 2026-08-13 | **クリーン run3（session_20260813_011154・封印 1 回）**: ゲート PASS（TCP/GraphQL/Forwarding）・funnel 記録（F5:1・B3 解決）・**GET-only 達成（evidence PATCH 0・OPTIONS 17 ブロック・B4 解決）**・confirmed 0（誤確定ゼロ）・ledger 16 候補・consistency consistent・config byte-exact 復元 | 本ログ検証・報告書 §2 |
| 2026-08-13 | ドキュメント閉鎖: 完了報告書作成（§19 分類: in_scope_blocker 0）・work_log done 化・task_registry/task_ledger を done に更新・plan を done/ へ移動 | 報告書 |

## 次アクション
- D-B4-1（discovery 経路の ReadonlyEnforcedError サイレントスキップ・検知欠落）: 親ロードマップ SGK-2026-0442 の追跡タスクで discovery 経路のブロック検知・needs_human 写像の設計判断（送信はゼロで安全・実害なし）。
- T4（SGK-2026-0446）: Haddix レポートへの 確定/保留/人間送り 明記（ロードマップ定義済み）。
- confirmed の実戦実測はターゲット状態依存（run3 でも confirmed 0 = 誤確定ゼロ実証。3条件AND 敷居は不変）。
