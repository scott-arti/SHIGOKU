---
task_id: SGK-2026-0433
doc_type: plan
status: done
parent_task_id: SGK-2026-0432
related_docs:
- docs/shigoku/subtasks/done/2026-08-08_sgk-2026-0432_gap-closure-causal-diagnosis_subtask_plan.md
- docs/shigoku/reports/2026-08-08_sgk-2026-0432_gap-closure-causal-diagnosis_work_report.md
title: m3a gap-closure 能力拡張（第2アカウント authz 比較・タイミング基盤）
created_at: '2026-08-08'
updated_at: '2026-08-08'
tags:
- shigoku
target: src/core/engine
---

# 実装計画: m3a gap-closure 能力拡張（SGK-2026-0433・active）

SGK-2026-0432 の診断で分類された (H) `authz_impact_not_proven`（第2アカウント比較の欠如）と
(C) `insufficient_timing_validation`（タイミング基盤の欠如）を、gap-closure できる能力として実装する。
**目的は confirmed 件数を増やすことではなく、owner-vs-non-owner の独立証拠を「集められる能力」を与えること。**
証拠条件・Evidence Validator の判定基準は緩めない。

## 認可エンベロープ（ユーザー承認済み・2026-08-08）

- **対象は封印使い捨てローカル Juice Shop コンテナのみ**（loopback / sealed net / 既存 `run_m5_audit.sh` harness）。**実VDP（外部）は対象外**。
- **auth-setup の POST を限定許可**: テスト用アカウント **A / B の register・login のみ** POST を許可する
  （＝認証基盤構築であり攻撃ではない）。**これ以外の POST/PUT/PATCH/DELETE・状態変更は fail-closed で禁止**。
- **攻撃 follow-up は m3a read-only（GET のみ）を維持**: 認証後の authz 比較は、B のセッションで A のリソースを
  **GET** で取得して比較する。注入・状態変更は行わない。
- アカウント資格情報は **生成 or env 参照**とし、ハードコード・コミット・log/session/report への平文出力を禁止（redaction 必須）。

## スコープ

- 第2アカウント基盤: アカウント A/B の provisioning（register/login POST）と、認証済みセッションの注入。
  `VDP_ACCOUNT_A/B_ID`（または生成値）で駆動し、**製品固有のURL/アカウントをハードコードしない**（一般則で発見/設定）。
- authz 比較 follow-up: owner(A) が作った resource を non-owner(B) の認証 GET で取得し、応答差分を
  **独立クラス固有証拠（S10 independent evidence）**として Evidence Validator に渡す。
- タイミング基盤 (C): repeat/timing control による timing 差 marker の取得（`insufficient_timing_validation` の gap-closure）。

## 必須テスト / 完了条件

1. auth-setup が **A/B の register/login POST のみ**に限定され、それ以外の状態変更は fail-closed で拒否される（self-checking テスト）。
2. B の認証 GET で A の resource を比較する follow-up が実行され、**owner-vs-non-owner 差分**が独立証拠として記録される。
3. authz_impact_not_proven だった candidate が gap-closure 後に **(a) 真の境界越えがあれば confirmed（Evidence Validator 経由・閾値緩和なし）／(b) 無ければ正しく hold/refuted**（＝比較が実際に実行されたこと自体が成功。confirmed 件数は指標にしない）。
4. timing 差 marker が取得でき、(C) candidate の gap が閉じる（または能力不足を明示）。
5. 安全0件（許可外の状態変更・secret漏洩・scope逸脱・予算超過・二重送信）／PCR-P1 無改変／product-independence preflight exit 0（docs も手動 redaction。恒久対策は SGK-2026-0435）。
6. 封印 harness での実測（sealed opaque case）と、テストの両方でカバー。

## NOT in scope

- 実VDP（外部）への通信・auth-setup 以外の POST・m3b/m3c/m4・全面 enforce。
- Evidence Validator / 証拠条件 / 閾値の緩和。confirmed 件数の指標化。
- 製品固有の既知脆弱性・固有URL・固有アカウント・payload・challenge の実装分岐/評価正解利用。
- 新規外部スキャナ/依存の追加。

## 参照

- SGK-2026-0432 診断（(H) authz / (C) timing の gap 根拠）。
- SGK-2026-0421（scope 再検証・read-only guard）、0422（Evidence Validator）、0419（capability matrix / budget）。
