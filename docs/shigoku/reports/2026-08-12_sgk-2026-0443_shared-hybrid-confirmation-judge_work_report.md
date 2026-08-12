---
task_id: SGK-2026-0443
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0443_shared-hybrid-confirmation-judge.md
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/worklogs/2026-08-12_sgk-2026-0443_shared-hybrid-confirmation-judge_work_log.md
title: 共有ハイブリッド確定判定モジュール（T1）作業完了報告
created_at: '2026-08-12'
updated_at: '2026-08-12'
tags:
- shigoku
- security-sensitive
target: src/core/validation/finding_validator.py,src/core/validation/__init__.py,src/prompts/roles/poc_judge.md
deferred_tasks:
  - deferred_id: SGK-2026-0443-D01
    title: "candidate_ledger 棚上げ保管・復活（T2）"
    reason: "T1 はモジュール単体（配線・保管・レポートは NOT in scope）。HybridVerdict の保存・復活は T2"
    impact: low
    tracking_task_id: SGK-2026-0442
    recommended_next_action: "SGK-2026-0444（ロードマップ定義済み・未起票）で candidate_ledger を構築"
  - deferred_id: SGK-2026-0443-D02
    title: "swarm 経路への配線＋F5 エミッタ（T3）"
    reason: "T1 の validate_finding() は呼び出し元ゼロの共有契約（デッド呼び出しの復活配線は T3）。0440 funnel に confirmed(F5)/parked を接続"
    impact: low
    tracking_task_id: SGK-2026-0442
    recommended_next_action: "SGK-2026-0445（ロードマップ定義済み・未起票）で配線"
  - deferred_id: SGK-2026-0443-D03
    title: "実送信での再現裏取り（T3 内）"
    reason: "T1 は NoopReproductionChecker スタブ（差込口のみ）。実送信は T3 で assert_read_only_probe（GET-only 送信境界）を利用して接続"
    impact: low
    tracking_task_id: SGK-2026-0442
    recommended_next_action: "SGK-2026-0445 で ReproductionChecker 実装を差し込む"
  - deferred_id: SGK-2026-0443-D04
    title: "Haddix レポートに 確定/保留/人間送り を明記（T4）"
    reason: "レポート出力は NOT in scope"
    impact: low
    tracking_task_id: SGK-2026-0442
    recommended_next_action: "SGK-2026-0446（ロードマップ定義済み・未起票）"
---

# 作業完了報告: SGK-2026-0443（T1 共有ハイブリッド確定判定モジュール）

## 0. 成果物サマリ

- **設計承認関門を通過**: ①verdict スキーマ ②機械フロア×AI 合成規則 ③poc_judge プロンプト
  （幻覚防止）④再現裏取り差込口 ＋ 決定事項 D1〜D7 を提示しユーザー承認。
  計画書 §設計付録 A〜G として確定（実装契約として固定）。
- **モジュール作り直し**: `src/core/validation/finding_validator.py`（139 → 482 行）。
  `VerdictState`（confirmed/refuted/needs_more/inconclusive/needs_human）・`HybridVerdict`
  （reason/mechanical_floor/ai_judgement/reproduction/evidence_refs/promise_score）・
  `AiJudgement`・`ReproductionOutcome`・`ReproductionChecker`/`NoopReproductionChecker`・
  `PoCJudge`（LLMClient(role="poc_judge")・fail-closed JSON パース・構築時マスク）。
- **機械フロア必須ゲート**: `evaluate_payout_grade`（決定的・LLM なし・0441 無改変）を
  バイパス不可で呼ぶ。AI 発言はフロア不足を上書きできない。
- **合成規則**: 9 段の状態遷移表（優先順位順）。確定＝3条件AND
  （フロア pass ∧ AI 賞金級 ∧ 再現一致）。却下は3種の明確な反証のみ。
- **幻覚防止プロンプト**: `poc_judge.md`（31 → 47 行・additive）に証拠帰属ルール
  （証拠に無いことは confirmed にできない・evidence_refs 引用必須）・製品非依存・秘密禁止・
  出力 JSON 拡張。
- **レガシー互換**: インスタンス `validate()`/`validate_batch()`/`ValidationResult` は
  byte-identical 温存（manager.py:3987/4026 の配線と funnel ゲート reason_code
  `finding_validator_rejected` が依存。配線解除は T2 で実施）。
- **単体完結**: 生産呼び出しゼロのまま（配線・ledger・レポートは T2〜T4）。既存挙動ビット同一。

## 1. 検証（実装後・実測）

| 項目 | 結果 |
|---|---|
| 対象単体（tests/core/validation ＋ manager 配線3ファイル） | **73 passed / 2 failed**（2件は既存環境要因 §3） |
| fixture self-checking（f1〜f12 ＋ oracle 対応テスト） | 全 PASS（機械フロア不足→確定しない・AI 主張のみ→確定しない・証明不足のみ→却下しない・refute→却下・3条件AND→確定・T1 stub→確定到達不能・needs_human・マスク・例外境界・防御的パース） |
| フル回帰（CI 同条件 `pytest tests/ -m "not slow and not requires_api"` ＋ --continue-on-collection-errors） | **6783 passed / 383 failed / 8 skipped / 1 xfailed / 5 collection errors** — ベースライン（変更 stash 時）と失敗集合 IDENTICAL（ソート済み diff）＝**回帰ゼロ** |
| preflight | `check_vdp_product_independence.py` → **pass / exit 0**（6/6 checks・total_token_hits 0・4 files scanned） |
| PCR-P1 | task_queue.py **diff 0** |
| 禁則 | vdp_evidence_validator / vdp_admission / admission_policy / src/reporting/ **diff 0** |
| docs | validate_shigoku_docs.py 0 エラー（BROKEN_LINKS 0・REGISTRY_ISSUES 0・DEFERRED_LINK_ISSUES 0） |
| 変更ファイル | 対象6ファイルのみ（finding_validator.py / __init__.py / poc_judge.md / テスト3ファイル） |

## 2. oracle レビュー（approve-with-minor）→ 対応

| 指摘 | 対応 |
|---|---|
| [重要] evidence_refs / markers が verdict に未マスクで到達 | judge() で全要素を pii_masker に通す（秘密境界の再帰的 redact・テスト追加） |
| [minor] 空 choices で IndexError（契約は ValueError） | `(response.get("choices") or [{}])[0]` に修正・テスト追加 |
| [minor] AI/再現チェックが短絡規則より先に実行（LLM 例外が refuted 判定を覆い隠す） | 遅延評価化: rule 2 / rule 7 の直前で実行。refute シグナル時は AI を呼ばない（テスト追加） |
| [minor] テストギャップ12件 | フェンス JSON・空応答・非オブジェクト・型不正・空 choices・非文字列 content・予期しない status（fail-closed）・例外伝播2種・refs/markers マスク・バッチ契約（入力順）を追加 |
| [nit] 型注釈 | TYPE_CHECKING で PayoutGradeResult・tuple[str, ...] に精密化 |

## 3. 不変条件の実証（死守事項）

- **確定の敷居を下げない**: T1 デフォルト（NoopReproductionChecker）では confirmed 到達不能
  （f6 実証）。確定は3条件AND（f5）。AI は機械フロアを上書き不可（f1）。
- **AI 主張のみで確定しない**: AI 証拠不足→inconclusive（f2）・AI 未実行→needs_more（f11）。
- **証明不足だけでは却下しない**: f3。却下は refute シグナル / AI counter-evidence /
  再現不一致の3種のみ（f4/f7/f10）。
- **Evidence Validator 無変更で共存**: vdp_evidence_validator.py diff 0・本モジュールから
  import なし。docstring に「hybrid confirmed は助言的確定・canonical ではない」を明記。
- **カーブフィッティング禁止**: promise_score はゲート充足数/3 の参考値のみで確定を
  ゲートしない。fixture は製品非依存（target.example）。
- **秘密マスク**: verdict は証拠値を保持しない（evidence_refs はフィールド名のみ）。
  AI reason / evidence_refs / markers は pii_masker で構築時マスク（f9 ＋ 追加テスト）。
- **PCR-P1 無改変**: task_queue.py diff 0。

## 4. 完了条件判定（計画書対比・§19 スコープ固定）

| 完了条件 | 判定 | 根拠 |
|---|---|---|
| 1. validate_finding() が rich verdict を返し、製品非依存 fixture で self-checking 実証（機械フロア不足→確定しない／AI が「confirmed」と言っても証拠不足→確定しない／明確反証のみ refuted／それ以外は needs_more/inconclusive/needs_human） | PASS | HybridVerdict 返却・f1〜f12＋追加テスト全 PASS（73 passed） |
| 2. 単体で完結（swarm/ledger/report 未配線）・既存挙動 byte-identical（回帰0） | PASS | フル回帰ベースライン比較 IDENTICAL・レガシー API 検証済み |
| 3. preflight exit 0・docs opaque・PCR-P1 diff 0・validator 0 | PASS | §1 参照 |

**in_scope_blocker 0 件**。deferred_followup: D01〜D04（T2〜T4・親ロードマップ
SGK-2026-0442 で追跡）。non_blocking_observation: フルスイートの 383 件失敗＋
collection errors 5 件・test_phase_b_readiness の 2 件は本タスク以前からの
既存環境要因（欠落モジュール・workspace アーティファクト欠落。ベースライン比較で確定）。
本タスクを **done** とする。

## 5. 作業プロセス注記（教訓）

- 実装委譲中、fixer が「既存失敗の調査」に git stash を誤用して作業5ファイルを退避したまま
  無応答となった（作業は失われず stash@{0} に生存・回収・検証済み）。以後の委譲指示では
  「git stash 等の破壊的操作は使用禁止・ベースライン調査は read-only で」を明示すること
  （rules/lessons.md 追記候補・別タスクで検討）。
