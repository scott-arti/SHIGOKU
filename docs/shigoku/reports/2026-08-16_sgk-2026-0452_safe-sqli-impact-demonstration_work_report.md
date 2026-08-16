---
task_id: SGK-2026-0452
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-15_sgk-2026-0452_safe-sqli-impact-demonstration.md
- docs/shigoku/plans/done/2026-08-15_sgk-2026-0451_smart-sqli-firing-path-fix.md
- docs/shigoku/worklogs/2026-08-16_sgk-2026-0452_safe-sqli-impact-demonstration_work_log.md
created_at: '2026-08-16'
updated_at: '2026-08-16'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
- sealed-run
deferred_tasks:
- id: SGK-2026-0452-D01
  summary: poc_judge の LLM 非決定性。同一 finding でも run ごとに accept/reject にぶれる（B6/B7 accept・B8 は ai_no_prize_grade で正当却下・境界的 severity）。判定基準・プロンプトを緩めずに reliability/determinism を上げる方策を検討。temperature=0 等は一貫 accept を保証せず、境界ゆえ一貫 reject の可能性もあり、その場合は honor する（緩めない）。「3連続 judge-accept」は機構でなく judge の運を測る proxy のため採用しない。
  tracking_task_id: SGK-2026-0442
- id: SGK-2026-0452-D02
  summary: 実害実証の技法拡張（防御ありの相手への対応）。現状の実証プローブは1種類の固定ペイロード形式のみで、対象に入力フィルタ/防御（危険文字の除去・別応答等）が1つでもあると実証が成立しない。防御検知＋回避（文字の別表現・区切り変更・条件言い換え等の複数手を試す）が未実装で、一流の発見者と同等以上には明確な要改善点。オーケストレータ/ユーザー確認で明確化（能力を過大にも過小にも見せない）。
  tracking_task_id: SGK-2026-0442
---

# 作業完了報告: SGK-2026-0452 — SQLi 候補の「安全な実害実証」で live confirmed=1 を出す（縦=depth・バー無改変）

（親ロードマップ: SGK-2026-0442。0451 で発火を決定化し `sql_error` 候補は毎 run 安定生成できたが live confirmed は 0。本タスクは**確定バー（3条件AND: payout_grade＋poc_judge＋reproduction matched）を1バイトも触らず**、poc_judge が正当に納得する「実証された実害」を本当に観測して live confirmed=1 に到達した。トップハンター同等の"確証の深さ"を、現在の仕組みを維持したまま実装。）

## 1. 変更要約

- **フェーズ0（実装前調査・承認済み）**: 0451 の live 却下の実 refs を突合し、真因が「実害不足（ai_no_prize_grade）」ではなく**証拠チェーンの内部矛盾（ai_counter_evidence）**であることを candidate_ledger の実データで特定。judge に渡るのは6フィールドのみ（`finding_validator.py:424-448`）と確定。どのバーも構造的変更不要（0449 実証で marker `sql_error` により機械床/再現は通る）ことを確認。
- **実装（オプトイン `sqli_impact_probe_enabled`・既定 OFF バイト等価）**:
  - `smart_sqli.py`: 証拠チェーン整合の修正（evidence=raw エラー観測プローブに固定・LLM 主張文を入れない）＋安全実証プローブ `_fire_impact_demonstration_probe`（boolean 差分オラクル＋非機微1トークン `sqlite_version()` 抽出・`sql_error_observed` 時のみ・GET-only・`_send_request` 再利用）。
  - `injection_evidence_fields.py`（0449 所有）: impact 充填を観測事実ベースに加法拡張（fail-closed）。
  - `settings.py`: `sqli_impact_probe_enabled`。`manager.py`: 実証観測の記録配線。
- **承認された堅牢化（バー無改変・呼び出し側のみ）**:
  - judge 再試行（承認 C）: `manager.py` T3 配線・**パース不能 JSON のときのみ1回**・正当な却下は再試行しない・失敗は fail-closed。
  - reproduction の network_client 修正: MC dispatch で set_network_client が呼ばれず checker が `disabled_no_client` になっていた真因をコードで確定→`_resolve_request_client()`（既存フォールバック）に変更。
  - candidate_lifecycle T1 精緻化（承認）: 初回訪問でも `verdict.state==CONFIRMED`（3条件AND成立）のときのみ confirmed で作成。CONFIRMED 以外は従来どおり needs_more。
  - funnel F6 emit（計装）: `lstate==CONFIRMED` のときのみ emit。
  - report 集計反映（計装）: `_split_findings_by_confirmation` ほかで `hybrid_final_state=="confirmed"` のみ confirmed に数える（ledger が唯一の source of truth・needs_more/parked は必ず candidate・backfill/promotion 捏造なし）。

## 2. 検証（オーケストレータ独立検証・実 artifact）

### B9 end-to-end 実証（session_20260816_223550 / haddix_report_20260816_223552）

- **report Confirmed: 1 / Candidate: 5**（sqli が confirmed 表示）。**funnel F6=1**。ledger state=confirmed・hybrid_final_state=confirmed。
- finding: HIGH・error(500 SQLITE_ERROR)＋boolean 差分(OR 1=1→len200 / OR 1=2→rows0 len30)＋非機微抽出 sqlite_version()=3.44.2。**機微データ抽出 0**（finding 内 password/email/資格情報 0）。
- **バー無改変**: `payout_grade.py` / `sealed_reproduction_checker.py` / `poc_judge.md` / `finding_validator.py` / `task_queue.py`(PCR-P1) すべて `git diff --quiet HEAD` exit0。
- judge 受理は壊れた JSON 経由の再試行ではなく genuine accept。
- **GET-only**（全 28 件 GET・非 GET 0）・secret 生値 0。
- `verify_report_session_consistency.py` **status=consistent**・rerun_required=false。
- `check_vdp_product_independence.py` **verdict=pass・total_token_hits 0**（changed_files 7）。
- `validate_shigoku_docs.py` **0 エラー**。
- 単体テスト: 新規 `test_sqli_impact_probe.py` / `test_injection_evidence_fields_impact.py`・report 反映テスト（`test_vdp_formatter_projection.py` 22 passed）・reporting スライス 1093 passed。

### judge 非決定性の正直な記録

最終ビルドの複数 run で poc_judge の判定がぶれた（B6/B7 accept・B8 は同一 finding を `ai_no_prize_grade` で**正当却下**）。この finding は境界的 severity（sqlite_version 漏えいは実在だが低〜中）で、ぶれは純粋なノイズだけでなく境界性も反映。**再試行増・複数サンプリング多数決・streak 狙いの再実行はしていない**（gaming 禁止）。B9 は genuine accept の run を1本用いて report 反映まで end-to-end 実証した。

## 3. 完了判定（§19）

- 固定完了条件 1/3/4/5/6 は PASS。条件2（当初「連続3回」）は計画書「STEP 3 最終結果」の**ユーザー合意による再解釈**（genuine live confirmed の end-to-end 実証＋機構の決定性＋バー無改変。judge 非決定性は別 deferred）で PASS。
- **`in_scope_blocker` 0 件** → **done**。
- `deferred_followup`: D01（judge 非決定性・基準を緩めない）／D02（実害実証の技法拡張・防御回避の未実装）。いずれも SGK-2026-0442 配下。

## 4. 捏造なし自己確認

impact/evidence は実観測レスポンスのみから構成（error 実測・boolean 差分の実測・sqlite_version の応答出現）。report の confirmed 表示は ledger の hybrid_final_state=confirmed のみに従い、needs_more/candidate は confirmed に数えない。確定バーの判定基準・プロンプトは無改変。機微データは一切抽出していない。

## 5. リスク / 次

- 実装はオプトイン（既定 OFF＝バイト等価）で既定 run への回帰リスクは隔離。
- **D02（防御ありの相手での実害実証）は一流水準に向けた明確な宿題**。単一固定ペイロードのため入力フィルタ1つで実証不成立。防御検知＋回避技の実装を SGK-2026-0442 配下で追跡。
- **D01（judge 安定化）**は基準を緩めずに取り組む。一貫 reject になる場合は honor する。
