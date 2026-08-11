---
task_id: SGK-2026-0443
doc_type: plan
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-11_sgk-2026-0441_validation-loop-modernization-payout-grade.md
created_at: '2026-08-12'
updated_at: '2026-08-12'
tags:
- shigoku
- vdp
- security-sensitive
target: src/core/validation/finding_validator.py,src/prompts/roles/poc_judge.md,config/shigoku.yaml
---

# 実装計画: T1 — 共有ハイブリッド確定判定モジュール

（親ロードマップ: SGK-2026-0442。設計方針・不変条件はそちらを正本とする。）

## 背景

- swarm 経路には確定機構が無い（`FindingValidator` はデッドコード・F5 エミッタゼロ）。VDP 側は署名付き Evidence Validator が権威。
- 0441 で機械フロア `payout_grade`（決定的・fail-closed・LLMなし）と AI 枠 `poc_judge` role（未接続）は用意済み。

## 目的

**どの swarm/サブエージェントからも呼べる、ハイブリッド確定判定モジュールを作る。** 本タスクは**モジュール単体**（swarm 配線・ledger・レポートは T2〜T4）。

## スコープ（T1 のみ）

1. `src/core/validation/finding_validator.py`（デッド）を**共有ハイブリッド判定**に作り直す:
   - **機械フロア**: 0441 `evaluate_payout_grade` を必須ゲートとして呼ぶ（再現 req/res＋発火印＋impact）。満たさなければ AI 判断でも confirmed にしない。
   - **AI 判断**: `poc_judge` role（reasoning/thinking）を接続。生証拠を読み「本物か・実害・賞金級か」を判断。**製品非依存プロンプト**（既知答えを与えない）。
   - **再現裏取り（任意・注入可能）**: PoC 再送フックのインターフェースを用意（実送信は T3 で封印環境に接続。T1 では stub/injectable）。
2. **rich verdict** を返す: `state ∈ {confirmed, refuted, needs_more, inconclusive, needs_human}` ＋ `reason` ＋ `evidence(マスク)` ＋ `promise_score`。
   - `confirmed`: 機械フロア pass ＋ AI 賞金級判断 ＋（再現裏取りが有効なら）再現一致。
   - `refuted`: 明確な反証（`_REFUTE_SIGNAL_KEYS`）がある時のみ。
   - それ以外は `needs_more`/`inconclusive`/`needs_human`（証明できないだけでは refute しない）。
3. **呼び出し口**: `validate_finding(finding)` を共通 `Finding` モデル上で。全 swarm から利用可能な契約として整備（署名/型を安定化）。
4. AI 呼び出しは role ベース（§18）。ledger/永続化・swarm 配線は**本タスクではしない**（T2/T3）。

## 診断先行 ＋ 設計承認関門
実装前に: (a) verdict スキーマ（状態・理由語彙）、(b) 機械フロアと AI 判断の合成規則（confirmed に必要な条件）、
(c) poc_judge プロンプト（製品非依存・幻覚防止＝証拠に無いことを confirmed にしない縛り）、(d) 再現裏取りインターフェース — を提示し承認を得てから実装。

## 不変条件（ロードマップ §不変条件に従う）
- 確定の敷居を下げない（機械フロア必須・AI 主張のみで確定しない）・Evidence Validator 無変更で共存。
- カーブフィッティング禁止（preflight exit 0・docs opaque）。秘密はマスク（evidence はマスク形で扱う）。PCR-P1 無改変・schema additive。

## 完了条件
1. `validate_finding()` が rich verdict を返し、**製品非依存 fixture** で: 機械フロア不足→confirmed にしない／AI が「confirmed」と言っても証拠不足なら confirmed にしない／明確反証のみ refuted／それ以外は needs_more/inconclusive/needs_human、を self-checking テストで実証。
2. 単体で完結（swarm/ledger/report 未配線）・既存挙動 byte-identical（誰も呼んでいないので回帰0）。
3. preflight exit 0・docs opaque・PCR-P1 diff 0・validator 0。

## NOT in scope（T1）
- swarm への配線・ledger 永続化・レポート出力（T2/T3/T4）。実送信での再現裏取り（T3）。VDP 署名確定の変更。

## 参照
- `src/core/validation/finding_validator.py`（復活対象）・`payout_grade.py`（機械フロア）・`poc_judge.md`（AI role）・`src/core/models/finding.py`（共通モデル・安定id）。
