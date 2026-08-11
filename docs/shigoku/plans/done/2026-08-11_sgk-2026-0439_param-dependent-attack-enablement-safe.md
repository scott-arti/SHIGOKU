---
task_id: SGK-2026-0439
doc_type: plan
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/reports/2026-08-10_sgk-2026-0438_followup-firing-breadth-admission-diagnosis_work_report.md
- docs/shigoku/reports/2026-08-08_sgk-2026-0432_gap-closure-causal-diagnosis_work_report.md
created_at: '2026-08-11'
updated_at: '2026-08-11'
tags:
- shigoku
- vdp
- security-sensitive
target: src/core/engine/vdp_observation_adapter.py,src/core/engine/master_conductor.py,src/core/security/pii_masker.py
---

# 実装計画: param 依存攻撃（注入系）を「マスク＆復元」設計に合わせて安全に撃てるようにする

## 背景 / 確定した食い違い（2026-08-11 コード確認）

- **システム全体の秘密取り扱いの正本は「マスク＆復元」**: `src/core/security/pii_masker.py`（PIIMasker）は
  秘密を `[PII:TYPE:TOKEN]` に**マスク**し、`token_map`（TOKEN→元値）を保持、実行時に `unmask()` で**元の値を復元**する
  双方向設計。記録には秘密を出さないが**本物の値は生きている**。
- **ところが VDP の攻撃観測経路（`vdp_observation_adapter.py`）はこの正本を使わず、param 値を完全破棄**している
  （`Values are discarded`。名前・場所・boolean のみ・復元不能）。PIIMasker は LLM/ログ経路にのみ配線され、
  VDP 攻撃経路には繋がっていない。
- この **VDP だけの逸脱**が、param 必須の攻撃（注入系: SQLi/XSS/コマンド注入/LFI/オープンリダイレクト = scn_03）を
  撃てなくしている（12カテゴリ中 scn_03 が実質未検証）。
- 破棄のもう一つの理由「観測IDの決定性（値をハッシュに入れない）」は、**ハッシュから値を除けば満たせる**ので、
  値の破棄は不要。マスク＆復元なら「ID安定・記録マスク・実行時は本物」が両立する。

## 目的

**VDP 攻撃経路を、システム正本の「マスク＆復元」設計に合わせる。** これにより param 依存攻撃（注入系）を撃てるようにする。
新しい秘密取り扱いは作らない（既存 PIIMasker を再利用）。confirmed 件数は成功指標にしない。Evidence Validator・閾値は緩めない。

## このタスクの性質：診断先行 ＋ 設計承認関門（安全のため必須）

秘密取り扱いに触れるため、**実装前に「診断＋統合設計」を提示して承認を得る**こと。無承認で値保持/復元の実装をしない。

### 診断で確定すること
1. 注入系 follow-up が撃たれない**正確な機構**（観測での値破棄が原因か、`_queue_vdp_follow_ups` の skip か、payload 生成経路の欠如か）。
2. 注入に本当に必要なのは「**元の param 値の復元**」か「**param 名・場所＋生成 payload の注入**」か（＝復元が要るのか、payload 変異で足りるのか）。両方を実証で切り分ける。
3. PIIMasker を VDP 攻撃経路へ配線する際の接続点（マスクする箇所・token_map の所在・`unmask()` で復元する実行直前の箇所）。

### 統合設計（承認対象・どちらの方針でも死守）
- **VDP 攻撃経路を PIIMasker に通す**: 記録・AI 文脈にはマスク後の値のみ、**実行直前に元の値を復元**して封印ターゲットへ送る。
- **token_map（元の値。秘密を含み得る）は絶対に永続化しない**: メモリ内・run スコープのみ。
  **session / report / log / checkpoint / 例外に token_map と元値を一切書かない**（第二の防御線 redaction は維持）。
- **秘密判定は deny-by-default**（既存 `_AUTH_HEADER_KEYS_LOWER` / `_COOKIE_KEYS_LOWER` / `_TOKEN_KEYS_LOWER` /
  `_SECRET_PATH_KEYWORDS` を正本）。Authorization/Cookie/token/password/credential/PII は必ずマスク。疑わしきはマスク（fail-closed）。
- **観測IDの決定性は維持**（ID ハッシュには従来どおり値を入れない）。
- 注入は**封印ローカルのみ・GET のみ**（本タスクのエンベロープ内）。状態変更・破壊的副作用のある注入は m3a では撃たない。

## 完了条件（設計承認後）

1. 注入系 follow-up が封印 run で**実際に撃たれる**（attempted 増・攻撃 payload が param に載る実測）。
2. **秘密漏洩 0**: session/report/log/checkpoint/例外に credential/token/cookie/password/元 token_map が平文で出ない（secret-scan で実証）。
3. 観測IDの決定性が不変（同一入力→同一ID）。
4. Evidence Validator・閾値・admission の安全判定・PCR-P1 は無改変。
5. preflight exit 0・docs opaque・validator 0・安全0・実行1回・consistent。

## NOT in scope

- 新規の秘密取り扱い機構の発明（既存 PIIMasker を再利用）。秘密判定の緩和・秘密の永続化。
- 証拠条件/閾値の緩和・confirmed 件数の指標化。
- 状態変更を伴う注入（m3a read-only の範囲外）・実VDP外部。

## 参照

- `src/core/security/pii_masker.py`（正本：マスク＆復元・token_map・`unmask()`）。
- `src/core/engine/vdp_observation_adapter.py`（現状：値破棄・秘密判定キー・決定性ID）。
- `src/core/engine/master_conductor.py` `_queue_vdp_follow_ups`（非比較 gap の param skip）。
- 0425 §5.1（値破棄の由来）・0434（S07 honest block）・0438（比較 gap 解放）。
