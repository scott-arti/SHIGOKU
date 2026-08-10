---
task_id: SGK-2026-0439
doc_type: plan
status: active
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
target: src/core/engine/vdp_observation_adapter.py,src/core/engine/master_conductor.py,src/core/engine/vdp_follow_up_executor.py
---

# 実装計画: param 依存攻撃（注入系）を安全に撃てるようにする

## 背景 / 観測

- 現状、観測境界（`vdp_observation_adapter.py`, 0425 §5.1 の安全契約）で **param の値を全て破棄**し、名前・場所・
  安全 boolean（has_auth_header / has_cookie）のみ残す。目的は**秘密（Authorization/Cookie/token/password/credential）を
  診断・session・report に残さない**こと。
- この「値の全破棄」の巻き添えで、**param が必須の攻撃（注入系: SQLi/XSS/コマンド注入/LFI/オープンリダイレクト等）が撃てない**。
  0438 後も、非比較 gap（payload_request_mismatch 等）は param 付き観測を queue 前に skip する（`_queue_vdp_follow_ups`）。
- 結果、12カテゴリのうち注入系（scn_03）が実質未検証のまま。

## 目的

**注入系など param 依存の攻撃を実際に撃てるようにする。ただし秘密情報の保護契約は一切弱めない。**
confirmed 件数を成功指標にしない。Evidence Validator・閾値は緩めない。

## このタスクの性質：診断先行 ＋ 設計レビュー関門（安全のため必須）

安全契約に触れるため、**実装前に「診断＋安全設計」をユーザー/Claude に提示して承認を得る**こと。無承認で境界の値保持を実装しない。

### 診断で確定すること
1. 注入系 follow-up が撃たれない**正確な機構**（`_queue_vdp_follow_ups` の skip か、executor の admission か、payload 生成の欠如か）。
2. 注入攻撃に本当に必要なのは「観測した**元の値**」か、それとも「param 名・場所＋**生成した攻撃 payload**」か
   （＝元の値保持が要るのか、既知 param への payload 変異で足りるのか）を切り分ける。

### 安全設計（どちらの方針でも死守）
- **秘密は絶対に保持しない**: 既存の秘密判定（`_AUTH_HEADER_KEYS_LOWER` / `_COOKIE_KEYS_LOWER` / `_TOKEN_KEYS_LOWER` /
  `_SECRET_PATH_KEYWORDS`）を正本として **deny-by-default**。疑わしきは破棄（fail-closed）。Authorization/Cookie/token/
  password/credential/PII の値は従来どおり boolean のみ。
- 仮に非秘密 param 値を保持する設計にする場合も、**対象攻撃 param のみ・最小限**とし、
  **session/report/log への永続化は従来どおり redaction（第二の防御線）を維持**。
- 注入 payload を送る場合は **封印ローカルのみ・GET のみ**（本タスクのエンベロープ内）。危険な副作用のある注入は m3a では撃たない。

## 完了条件（設計承認後）

1. 注入系 follow-up が封印 run で**実際に撃たれる**ことを実測（attempted 増・payload が param に載る）。
2. **秘密漏洩 0**: session/report/log/checkpoint/例外に credential/token/cookie/password が平文で出ない（secret-scan で実証）。
3. Evidence Validator・閾値・admission の安全判定・PCR-P1 は無改変。
4. preflight exit 0・docs opaque・validator 0・安全0・実行1回・consistent。

## NOT in scope

- 秘密判定の緩和・秘密値の保持。証拠条件/閾値の緩和・confirmed 件数の指標化。
- 状態変更を伴う注入（m3a read-only の範囲外）・実VDP外部。

## 参照

- `src/core/engine/vdp_observation_adapter.py`（値破棄と秘密判定の正本）。
- `src/core/engine/master_conductor.py` `_queue_vdp_follow_ups`（非比較 gap の param skip）。
- 0425 §5.1（値破棄契約）・0434（S07 honest block）・0438（比較 gap の解放）。
