---
task_id: SGK-2026-0463
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/2026-08-30_sgk-2026-0463_stored-stage2-redirect-marker-fix.md
- docs/shigoku/worklogs/2026-08-30_sgk-2026-0463_stored-stage2-redirect-marker-fix_work_log.md
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

# SGK-2026-0463 作業完了報告 — 保存型XSS第2段階の303-redirect誤早期リターン修正（検出側 smart_xss）

## 実施内容

`src/core/agents/swarm/injection/smart_xss.py`（+8/-2・最小・追加のみ）:

1. **marker POST を `allow_redirects=False` で送信**（`_attempt_stored_revisit_validation` の json/data 両経路・計2箇所）。
   - 従来は aiohttp 既定（True）で 303 → GET / を追従し、実効本文（GET /）が保存済み marker を描画 → marker 反射チェックが誤発火 → 早期リターン（反射経路へ委譲）→ `GET /comment`=405 → dialog 不可。
   - 追従を止めることで「POST 応答自体が marker を反射するか」という本来の意図どおりの判定になり、3xx 保存sink では revisit スイープへ進む → 反射 URL 発見 → 実 payload 保存 → `_validate_stored_runtime_xss` で dialog 観測へ到達できる。
   - 挙動変化は「3xx を返す保存sink」に限定。200 で反射する sink は従来どおり早期リターン・200 非反射・GET 系も従来どおり（退行なし）。
2. **fire POST（実 payload 再保存）は現状維持**（追従しても保存され、その後 reflection_url をブラウザで開くため・計画書どおり）。

テスト: `tests/core/agents/swarm/injection/test_smart_xss_stored_revisit.py` に T4/T5/T6 を追加（+3件）。

- T4: marker POST が `allow_redirects=False` で送られる／fire POST は allow_redirects 指定なし（現状維持）。
- T5: 3xx 保存sink（POST 303・marker 非反射）では早期リターンせず revisit スイープへ進み、反射 URL 発見 → 実 payload 保存 → dialog 観測で stored finding（練習台5008 シナリオの単体再現）。
- T6: 200 で marker を反射する sink は従来どおり早期リターン（委譲・fail-closed・退行なし）。

## 検証（実出力）

### 単体
- `tests/core/agents/swarm/injection/test_smart_xss_stored_revisit.py` → `8 passed in 1.34s`（既存5 + 新規3）。
- smart_xss 関連（logic / xcto10 / swarm / poc_judge_robust）→ `33 passed in 237.20s`（警告9件は既存の未 await coroutine 警告・本変更と無関係）。
- injection 全体 + `test_smart_xss.py` → `632 passed in 249.34s`。
- 統合 `tests/integration/test_smart_xss_hunter_integration.py` → `5 passed in 42.30s`。

### 実走行（CB-1）
- 本セッションでは実施せず、**Claude 独立再検証で最終確認**（計画書 L67 の分業契約どおり・フル走行は重いため）。
- 環境稼働確認: 練習台5008 = HTTP 200 / Caido 8081 = HTTP 200（実走行可能状態）。

### DVWA / バー / token0（CB-3）
- `python3 scripts/check_initial_release_gate.py --report workspace/projects/localhost:4280/reports/haddix_report_20260727_095226.md` → `status: fail` / `reason_codes: ["candidate_above_maximum"]` / `findings_summary.candidate_count: 5` / `confirmed_count: 18`（DVWA 既知安全保留・SGK-2026-0462 と完全同一）。
- `python3 scripts/verify_report_session_consistency.py --report …095226.md` → `status: consistent` / `rerun_required: false`。
- `git diff --quiet HEAD -- src/core/agents/swarm/injection/payout_grade.py src/prompts/roles/poc_judge.md src/core/engine/task_queue.py src/core/validation/finding_validator.py src/core/validation/sealed_reproduction_checker.py` → **BAR_UNCHANGED**。
- `python3 scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --denylist config/diagnostics/sealed_product_denylist.txt` → `verdict: pass` / `checks 6/6 ok` / **total_token_hits: 0**（製品名・DVWA/juice パス片はテストにも不使用・`/app/...` 汎用のみ）。

## 完了契約との対応

- **CB-1（練習台5008 フル走行で formal confirmed=1・variant=stored・dialog_observed=True・consistency=consistent・混入0）: Claude 独立再検証で最終確認**（環境稼働確認済み・単体 T5 で 3xx 保存sink → dialog 観測の経路を実証済み）。
- **CB-2（確定バー5ファイル無改変・判定緩和なし・0461 B 変更禁止）: PASS**（BAR_UNCHANGED・`allow_redirects=False` のみの追加・判定・閾値・発火基準は不変・fail-closed 維持）。
- **CB-3（token0・DVWA 既知安全保留不変・新規/変更ユニット緑）: PASS**。

## deferred_tasks

```yaml
deferred_tasks: []
```

（CB-1 の実走行確認は計画書 L67 の承認済み分業契約「Claude が独立検証（単体・実走行 confirmed=1・DVWA gate・バー無改変・token0）」に基づく Claude 側再検証フェーズであり、追跡タスクではない。）

## 参考ルール

rules/lessons.md、rules/codingrules.md、rules/task-ledger.md、rules/shigoku-docs.md、rules/python-tests.md、rules/report-session-consistency.md、rules/reporting.md
