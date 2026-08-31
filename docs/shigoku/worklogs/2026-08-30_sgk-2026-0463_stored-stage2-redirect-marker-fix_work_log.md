---
task_id: SGK-2026-0463
doc_type: work_log
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/2026-08-30_sgk-2026-0463_stored-stage2-redirect-marker-fix.md
- docs/shigoku/reports/2026-08-30_sgk-2026-0463_stored-stage2-redirect-marker-fix_work_report.md
- docs/shigoku/plans/done/2026-08-30_sgk-2026-0462_canonical-save-endpoints-wiring.md
created_at: '2026-08-30'
updated_at: '2026-09-01'
tags:
- shigoku
- vdp
- detection
- xss
- stored
---

# SGK-2026-0463 作業ログ — 保存型XSS第2段階の303-redirect誤早期リターン修正（検出側 smart_xss）

## 日時

2026-08-30（実装・単体・回帰・gate・token0・docs を一貫して実施）

## 作業内容

### 1. 実装（`src/core/agents/swarm/injection/smart_xss.py`・+8/-2・最小）

- `_attempt_stored_revisit_validation` の marker POST（json/data 両経路）に **`allow_redirects=False`** を追加（SGK-2026-0463 コメント付き）。
- 意図: 3xx（例: 303 → GET /）を追従せず「POST 応答自体の marker 反射」だけを見る。追従すると実効本文（GET /）が保存済み marker を描画し marker 早期リターンが誤発火していた。
- fire POST（実 payload 再保存）は現状維持（追従可）。
- 判定・閾値・発火基準の緩和なし・fail-closed 維持・バー5無改変。

### 2. テスト（新規3件）

`tests/core/agents/swarm/injection/test_smart_xss_stored_revisit.py` に追加:

- T4: marker POST が `allow_redirects=False` で送られる／fire POST は allow_redirects 指定なし（現状維持）。
- T5: 3xx 保存sink（POST 303・marker 非反射）→ 早期リターンせず revisit スイープ → 反射 URL 発見 → 実 payload 保存 → dialog 観測 → stored finding（練習台5008 シナリオの単体再現）。
- T6: 200 で marker を反射する sink は従来どおり早期リターン（委譲・fail-closed・退行なし）。

### 3. 検証コマンド（実出力）

```
$ .venv/bin/pytest tests/core/agents/swarm/injection/test_smart_xss_stored_revisit.py -q
8 passed in 1.34s

$ .venv/bin/pytest tests/core/agents/swarm/injection/ tests/core/agents/swarm/test_smart_xss.py -q
632 passed in 249.34s

$ .venv/bin/pytest tests/integration/test_smart_xss_hunter_integration.py -q
5 passed in 42.30s

$ git diff --quiet HEAD -- src/core/agents/swarm/injection/payout_grade.py src/prompts/roles/poc_judge.md src/core/engine/task_queue.py src/core/validation/finding_validator.py src/core/validation/sealed_reproduction_checker.py && echo BAR_UNCHANGED
BAR_UNCHANGED

$ python3 scripts/check_initial_release_gate.py --report workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md
status: fail / reason_codes: ["candidate_above_maximum"] / findings_summary: candidate_count=5・confirmed_count=18（既知安全保留・SGK-2026-0462 と同一）

$ python3 scripts/verify_report_session_consistency.py --report workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md
status: consistent / rerun_required: false

$ python3 scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --denylist config/diagnostics/sealed_product_denylist.txt
verdict: pass / checks 6/6 ok / total_token_hits: 0
```

### 4. 実走行（CB-1）

- 本ログ作成時点では未実施。**Claude 独立再検証で最終確認**（計画書 L67 の分業契約・フル走行は重いため）。
- 環境稼働確認: 練習台5008 = 200 / Caido8081 = 200（実走行可能状態）。

### 5. docs

- `docs/shigoku/plans/2026-08-30_sgk-2026-0463_stored-stage2-redirect-marker-fix.md`: 実装方針確定（allow_redirects=False・精密版）・検証結果セクションを更新
- `docs/shigoku/reports/2026-08-30_sgk-2026-0463_stored-stage2-redirect-marker-fix_work_report.md` 新規
- 本 work_log 新規

## 残課題

- 練習台5008 フル走行の formal confirmed=1（variant=stored・dialog_observed=True・consistency=consistent・混入0）→ Claude 独立再検証で最終確認（環境稼働中）。

## 参考ルール

rules/lessons.md、rules/codingrules.md、rules/task-ledger.md、rules/shigoku-docs.md、rules/python-tests.md、rules/report-session-consistency.md、rules/reporting.md
