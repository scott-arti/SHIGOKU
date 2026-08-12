---
task_id: SGK-2026-0444
doc_type: plan
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0443_shared-hybrid-confirmation-judge.md
created_at: '2026-08-12'
updated_at: '2026-08-12'
tags:
- shigoku
- vdp
- security-sensitive
target: src/core/validation,workspace/projects
---

# 実装計画: T2 — 候補ライフサイクル ＋ 棚上げ保管（candidate_ledger）＋ 復活

（親ロードマップ: SGK-2026-0442。設計方針・不変条件・保管仕様はそちらが正本。）

## 背景

- T1（0443）で共有ハイブリッド判定 `validate_finding()` が rich verdict（`VerdictState` 5状態＋reason＋evidence_refs＋promise_score）を返すようになった。
- しかし「証明できない候補が永遠に活動列に残る／溜まる」問題への対処は未実装。棚上げ保管も無い。

## 目的

**候補の一生（ライフサイクル）を管理する仕組みと、棚上げ保管（run 跨ぎ）＋新情報での復活を実装する。**
本タスクは**サービス/ストア単体**（swarm 実行ループへの配線・実確定は T3、Haddix 明記は T4。ここではやらない）。

## スコープ（T2 のみ）

1. **ライフサイクル管理**（T1 verdict を消費）:
   - 状態遷移: `needs_more` は**調査予算**（回数/時間・設定値）内で継続。予算切れ→`inconclusive_parked`。`needs_human`→人間送り。`confirmed`/`refuted`は終端。
   - **証明できないだけでは refute しない**（T1 の契約踏襲）。予算切れは棚上げであって却下ではない。
   - 見込み順（`promise_score`）に予算配分するためのランキング関数。
2. **棚上げ保管ストア（candidate_ledger）**:
   - 場所: `workspace/projects/<target>/candidate_ledger.json`（**run 跨ぎで永続**・`scans/`等と同列）。
   - 鍵: `Finding.id`（12桁 md5・既存）。
   - レコード: `{finding_id → {state, evidence(**マスク済・0439方式**), reason, first_seen, last_investigated, budget_used, promise_score, revisit_triggers}}`。**生の秘密を保存しない。**
   - API: `get(finding_id)` / `put(record)` / `list_by_state(state)` / `all()`。原子的書き込み・破損耐性（不正 JSON はfail-safeで空扱い、既存 recon_state 等の作法に倣う）。
3. **復活（revisit）**:
   - 次 run で **新情報（新 capability / 新アカウント / 新 endpoint 等）が `revisit_triggers` に合致した parked 候補のみ**再活性化（活動列へ戻す）。**盲目的な再試行はしない。**
   - revisit_trigger の生成規則（何を「新情報」とみなすか）を製品非依存に定義。

## 診断先行 ＋ 設計承認関門
実装前に: (a) ライフサイクル状態機械（遷移・予算切れ→棚上げ/人間送りの条件）、(b) ledger スキーマとマスク方針、
(c) revisit_trigger の定義（新情報の判定・盲目再試行防止）、(d) 予算・ランキングのパラメータ — を提示し承認を得てから実装。

## 不変条件（ロードマップ §不変条件に従う）
- **確定の敷居を下げない**（T1 判定は無変更で利用・ここでは確定を生成しない。状態管理と保管のみ）。
- **証明不足だけで却下しない**（棚上げ＝消さない・取り出せる）。
- 秘密は**マスク保存**（生秘密を ledger に書かない）。カーブフィッティング禁止（preflight exit 0・docs opaque）。
- PCR-P1 無改変・schema additive・**サービス単体（swarm 未配線）で既存挙動 byte-identical**。

## 完了条件（設計承認後）
1. 製品非依存 fixture で self-checking: needs_more→予算内継続→予算切れで inconclusive_parked／needs_human→人間送り／confirmed・refuted は終端／**証明不足だけでは refute しない**／promise_score 順ランキング。
2. **棚上げ round-trip**: put→(別プロセス/再ロード)→get で復元・**マスク保存で生秘密ゼロ**（secret-scan）。破損 JSON でも fail-safe。
3. **revisit**: 新情報合致で parked→活動列復帰・非合致では復帰しない、を実証。
4. 既存挙動 byte-identical（未配線・回帰0）・PCR-P1 diff 0・preflight exit 0・docs opaque・validator 0。

## NOT in scope（T2）
- swarm 実行ループへの配線・実確定の発生（T3）。Haddix レポート明記（T4）。T1 判定ロジックの変更。実VDP外部・状態変更・m3b 以上。

## 参照
- `src/core/validation/finding_validator.py`（T1 verdict 契約）・`src/core/models/finding.py`（安定 id）・0439（マスク）・`recon_state.json` 保存作法（原子的・破損耐性）。
