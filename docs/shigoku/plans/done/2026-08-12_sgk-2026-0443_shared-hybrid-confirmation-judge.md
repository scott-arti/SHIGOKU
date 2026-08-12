---
task_id: SGK-2026-0443
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-11_sgk-2026-0441_validation-loop-modernization-payout-grade.md
- docs/shigoku/reports/2026-08-12_sgk-2026-0443_shared-hybrid-confirmation-judge_work_report.md
- docs/shigoku/worklogs/2026-08-12_sgk-2026-0443_shared-hybrid-confirmation-judge_work_log.md
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

## 設計付録（2026-08-12 ユーザー承認済み・実装契約）

### A. verdict スキーマ（確定版）
`finding_validator.py` に新設（既存レガシー API は E 参照）:

```python
class VerdictState(Enum):
    CONFIRMED = "confirmed"        # 確定
    REFUTED = "refuted"            # 却下
    NEEDS_MORE = "needs_more"      # 継続
    INCONCLUSIVE = "inconclusive"  # 棚上げ
    NEEDS_HUMAN = "needs_human"    # 人間送り

@dataclass(frozen=True)
class AiJudgement:            # poc_judge パース結果
    payout_grade: bool        # 賞金級
    is_real: bool
    has_actual_impact: bool
    counter_evidence: bool    # 明確な反証（証拠内の矛盾実測）のみ true
    needs_human: bool
    evidence_refs: tuple[str, ...]
    markers: tuple[str, ...]
    reason_masked: str        # 構築時に pii_masker でマスク（write 境界で redact）

@dataclass(frozen=True)
class ReproductionOutcome:
    status: Literal["not_run", "matched", "mismatched"]
    reason: str

@dataclass(frozen=True)
class HybridVerdict:
    state: VerdictState
    reason: str                        # 安定コード（語彙表）
    mechanical_floor: PayoutGradeResult  # 0441 無改変で保持
    ai_judgement: Optional[AiJudgement]
    reproduction: ReproductionOutcome
    evidence_refs: tuple[str, ...]     # フィールド名のみ・値を保持しない
    promise_score: float               # 満たしたゲート数/3・参考のみ・確定をゲートしない
```

reason 語彙: confirmed=`hybrid_confirmed`／refuted=`explicit_refute_signal`・`ai_counter_evidence`・`reproduction_mismatch`／needs_more=フロア reason コードパススルー（`missing_evidence` 等）・`ai_judgement_pending`・`reproduction_pending`／inconclusive=`ai_no_prize_grade`・`ai_indecisive`／needs_human=`ai_needs_human`。

### B. 合成規則（状態遷移表・優先順位順に評価）
| # | 条件 | state | reason |
|---|---|---|---|
| 1 | `has_explicit_refute_signal(finding)` 真（falsification/falsified/refuted/false_positive／payload_delivery.delivered=false） | refuted | explicit_refute_signal |
| 2 | AI `counter_evidence=true` | refuted | ai_counter_evidence |
| 3 | 機械フロア fail（AI 発言は上書き不可） | needs_more | フロア reason |
| 4 | AI 未実行（ai_judge=None） | needs_more | ai_judgement_pending |
| 5 | AI `needs_human=true` | needs_human | ai_needs_human |
| 6 | AI `payout_grade=false`（反証なし） | inconclusive | ai_no_prize_grade |
| 7 | AI 賞金級 かつ 再現 `not_run`（T1 デフォルト） | needs_more | reproduction_pending |
| 8 | AI 賞金級 かつ 再現 `mismatched` | refuted | reproduction_mismatch |
| 9 | AI 賞金級 かつ 再現 `matched` | **confirmed** | hybrid_confirmed |

- 確定＝3条件AND。T1 の stub は not_run を返すため **confirmed は到達不能（敷居を下げない）**。AND 配線は mock 注入テストで実証。
- 却下は3種の明確な反証のみ。証明不足だけでは決して却下しない。
- AI 例外（LLM/JSON parse 失敗）は握りつぶさず伝播（fail-closed・T2 配線で catch 予定）。
- VdpEvidenceValidator は無変更・無関係（import しない）。hybrid の confirmed は swarm 経路の助言的確定であり canonical 署名確定ではない（docstring に明記・reporting/gate から canonical として扱わない）。

### C. poc_judge プロンプト改修（additive・製品非依存）
現行 fail-closed 方針を維持し次を追加:
- 証拠帰属（幻覚防止）: 証拠に無い事実・観測を確認済みと記述しない／各肯定判断は証拠内箇所を `evidence_refs` で引用／引用できない主張は unsupported とし `payout_grade=true` にできない／`counter_evidence=true` は証拠内の矛盾実測がある場合のみ。
- 出力 JSON を additive 拡張: `payout_grade`（維持）＋`is_real`・`has_actual_impact`・`counter_evidence`・`needs_human`・`evidence_refs`。
- 秘密: reason に API キー・トークン・資格情報・セッション値を含めない。製品非依存: 既知の製品・期待答えを前提にしない。
- config/shigoku.yaml は変更不要（poc_judge role 定義は既存のまま・D6）。

### D. 再現裏取り差込口
```python
class ReproductionChecker(Protocol):
    def check(self, finding: Any) -> ReproductionOutcome: ...
class NoopReproductionChecker:  # T1 デフォルト・実送信は T3
    def check(self, finding): return ReproductionOutcome("not_run", "reproduction_wiring_t3")
```
`validate_finding(finding, *, ai_judge=None, reproduction_checker=None) -> HybridVerdict`／`validate_findings(...) -> list[HybridVerdict]` を全 swarm 向け共通契約として整備。実送信実装は T3（送信境界は既存 `assert_read_only_probe` GET-only ガードを利用）。

### E. レガシー互換の決定（D7 の具体化）
- インスタンス `validate()` / `validate_batch()` / `ValidationResult` は **無変更で温存**（manager.py 配線 `_finding_validator.validate` と funnel ゲートが依存。配線解除は T2）。
- 新契約はインスタンス `evaluate()` ＋ モジュール関数 `validate_finding` / `validate_findings`（旧モジュール関数は生産呼び出し0のため新契約へ変更）。`get_validator()` は維持。

### F. fixture self-checking（製品非依存・実装必須）
f1 フロア不足＋AI 賞金級発言→confirmed にしない／f2 フロア pass＋AI 証拠不足→confirmed にしない（inconclusive）／f3 証明不足のみ→却下しない（needs_more）／f4 refute signal→却下（フロアと無関係）／f5 3条件AND（mock matched）→confirmed／f6 T1 stub→confirmed 到達不能／f7 AI counter_evidence→却下／f8 AI needs_human→needs_human／f9 マスク（AI reason 内 secret が verdict に生値で残らない）／f10 再現 mismatched→却下／f11 ai_judge=None→needs_more（ai_judgement_pending）／f12 promise_score・evidence_refs union・PoCJudge JSON parse（不正→ValueError）。

### G. 検証手順（完了条件対応）
1. `tests/core/validation/` 全テスト＋manager 配線テスト（test_finding_funnel_swarm_hooks.py 等）で回帰0。
2. `.venv/bin/pytest tests/ -m "not slow and not requires_api"`（CI 同条件）。
3. `python3 scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --denylist config/diagnostics/sealed_product_denylist.txt` → exit 0。
4. PCR-P1 diff 0（task_queue.py）・禁則 diff 0（task_queue.py / vdp_evidence_validator / vdp_admission / admission_policy / src/reporting/）。
5. `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py` 0 エラー。
