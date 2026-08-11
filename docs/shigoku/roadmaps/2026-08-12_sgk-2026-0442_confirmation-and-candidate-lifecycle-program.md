---
task_id: SGK-2026-0442
doc_type: roadmap
status: active
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/done/2026-08-11_sgk-2026-0441_validation-loop-modernization-payout-grade.md
- docs/shigoku/plans/done/2026-08-11_sgk-2026-0440_finding-pipeline-instrumentation.md
created_at: '2026-08-12'
updated_at: '2026-08-12'
tags:
- shigoku
- vdp
- security-sensitive
target: src/core/validation,src/core/agents/swarm,src/reporting,workspace/projects
---

# ロードマップ: 確定（confirm）と候補ライフサイクルのプログラム

## 目的

0440 の計測で「候補は見つかるが確定に上がらない」が確定し、0441 で AI 検証ループを近代化した。
本プログラムは残る本丸——**見つけた候補を、賞金バウンティで賞金が出る粒度・根拠の PoC で"確定"させる。証明できない候補は
即捨てせず、予算内で掘り、決着が付かなければ"棚上げ保管"し、人間が結果を把握できるようにする**——を、
**どの swarm/サブエージェントからも呼べる共有の仕組み**として実装する。

## 確定した設計方針（ユーザー承認済み・2026-08-12）

### 1. ハイブリッド判定（共有モジュール）
- **機械フロア**（0441 `payout_grade` を土台）＝証拠が実在するか（再現 req/res＋発火印＋impact）。
- **AI 判断**（`poc_judge` role）＝本物か・実害があるか・賞金級か。**ただし機械フロアを満たさない限り確定させない（AI は証拠を捏造できない）**。
- **再現で裏取り**（可能なら PoC を再送して同じ発火を確認）。
- 置き場所は既存の共有モジュール `src/core/validation/finding_validator.py`（現状デッドコード）を復活・強化。**どの swarm からも `validate_finding(finding)` で呼べる**。共通 `Finding` モデル上で動く。

### 2. 候補ライフサイクル（即捨てしない・かつ溜めっぱなしにしない）
状態：`confirmed`（賞金級 PoC 済）/ `refuted`（**明確な反証がある時のみ**）/ `needs_more`（予算内で継続）/ `inconclusive_parked`（予算切れ・棚上げ）/ `needs_human`（見込み高いが自動で詰め切れず人間へ）。
- 1 候補ごとに**調査予算**（回数/時間）。予算内で決着 → 予算切れは棚上げ or 人間送り。
- **証明できないだけでは却下しない**（false negative 防止）。却下は明確な反証時のみ。
- 見込み順（実害×AI手応え）に予算配分。

### 3. 棚上げ保管（置き場所・取り出し方）
- **場所**: `workspace/projects/<target>/candidate_ledger.json`（**run 跨ぎで永続**。`scans/`/`tagged_urls/` と同列）。
- **鍵**: `Finding.id`（12桁 md5・既存）。
- **中身**: `{finding_id → {state, evidence(マスク済・0439方式), reason, first_seen, last_investigated, budget_used, promise_score, revisit_triggers}}`。**生の秘密は保存しない**。
- **API**: `get/put/list_by_state`（lifecycle と reporting が読む）。
- **復活**: 次 run で **新情報（新capability/新アカウント/新endpoint）が revisit_trigger に合致した候補のみ**再活性化（盲目的再試行はしない）。

### 4. Haddix レポート（人間が結果を把握）
run 終了時に、**確定（賞金級 PoC 付き）/ 棚上げ（inconclusive とその理由）/ 人間送り（needs_human）** を明記するセクションを追加。

## 不変条件（全タスク共通・絶対）

- **確定の敷居を下げない**（機械フロア必須・AI 主張のみでは確定しない・Evidence Validator/署名確定は無変更で共存）。confirmed 件数を成功指標にしない。
- **カーブフィッティング禁止**（製品固有の答えを実装分岐/正解にしない・製品 token 遮断・preflight exit 0・docs opaque）。AI には自由に推論させる。
- 秘密は 0439 のマスク＆復元を維持（ledger も**マスク保存**）。PCR-P1 無改変・schema additive・封印ローカル read-only GET・安全0。
- 各タスクは**診断先行＋設計承認関門**（確定パスに触るため）。

## タスク分割（最適な区切り・各々独立完了・検証可能）

- **T1 = SGK-2026-0443**: 共有ハイブリッド判定モジュール（FindingValidator 復活・機械フロア＋AI＋再現裏取り・rich verdict）。swarm 未配線。
- **T2 = SGK-2026-0444**: 候補ライフサイクル＋棚上げ保管（candidate_ledger）＋復活。T1 の verdict の上に構築。
- **T3 = SGK-2026-0445**: swarm 経路への配線（デッド呼び出し復活・0440 funnel に confirmed(F5)/parked を before/after 実測）。
- **T4 = SGK-2026-0446**: Haddix レポートに 確定/保留/人間送り を明記。

依存: T2←T1、T3←T1+T2、T4←T3。各 T は個別に計画書化（本ロードマップは全体設計と区切りを固定）。

## NOT in scope（本プログラム）

- VDP の署名付き確定（Evidence Validator）の再設計 → 当面共存。
- 状態変更を伴う攻撃・m3b 以上・実VDP外部。
- 証拠条件/閾値の緩和・LLM のみ確定。
