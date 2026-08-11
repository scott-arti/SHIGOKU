---
task_id: SGK-2026-0439
doc_type: work_log
status: done
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/done/2026-08-11_sgk-2026-0439_param-dependent-attack-enablement-safe.md
- docs/shigoku/reports/2026-08-11_sgk-2026-0439_param-dependent-attack-enablement-safe_work_report.md
created_at: '2026-08-11'
updated_at: '2026-08-11'
tags:
- shigoku
- vdp
- security-sensitive
---

# 作業ログ: SGK-2026-0439（param 依存攻撃の「マスク＆復元」化）

## 実施内容

1. **診断（exp-1/exp-2・読取のみ）**: 注入系が撃たれない3重関門
   （観測境界の値破棄 / queue skip / S07 block）と payload 生成経路の欠如を
   一次証拠で確定。生 URL（値入り）がメモリ上に存在することを確認
   （破棄はマスクで置換可能）。「元値の復元」が必須と実証（S07 rationale が
   「名前だけの probe は捏造された generic リクエスト」と明言）。
   PIIMasker が fail-open（未認識値素通し）であることも発見 → deny-by-default
   プリミティブの追加が必要と設計に反映。
2. **統合設計提示 → ユーザー承認**（マスク箇所・token_map run スコープ・
   unmask 実行直前点・非永続化・決定性・fail-closed の死守項目）。
3. **実装（fix-1）**: PIIMasker に `mask_url_query_values()`（deny-by-default）+
   `has_tokens()` 追加。Observation に additive `masked_request_url`（canonical
   payload に含めず観測ID不変）。`_queue_vdp_follow_ups` は「値が本当に破棄
   されている場合のみ skip」へ変更。S07 は spec が masked_request_url を
   持つ場合のみ通過。executor 送信境界（fingerprint チェック後）で unmask・
   未解決トークン残存は MANUAL_REVIEW（fail-closed）。単体テスト新規15件。
4. **リーク面封鎖（fix-2/fix-3）**: network_client 全ログ/イベント/例外/
   キャッシュキーを `log_safe_url` 化。SESSION_EXPIRED イベントに additive
   `log_safe_url` を追加し、MC のログ/台帳は safe_url・reauth orchestrator は
   raw url 維持（SGK-2026-0280 契約不変）。
5. **テスト更新（fix-4）**: realpath 0423 を新契約へ（payload spec は実行・
   material-less spec の S07 block を回帰として追加）。
6. **独立検証**: 主要テスト 111 passed・PCR-P1 diff 0・禁則ファイル無変更。
   2 failures（M0 evidence_set_mismatch）は stash 検証で HEAD（0438 verified）
   でも同一失敗 → pre-existing と確定（D01 として追跡）。
7. **封印 run（session_20260811_002205）**: **attempts 3 → 5・evidence 3 → 5**。
   payload_request_mismatch（注入系）と insufficient_timing_validation が
   S07 block なしで実行。GET-only（session 内 method 全 GET）・安全0・
   secret 0（spec は [PII:VALUE:...] マスク形のみ・credential 値 0・
   ログにトークン/元値 0）・consistent・preflight exit 0・config/
   runtime surface byte-identical・所有権 bbb。phase 9 evaluator は harness
   内で出力欠落したため同一コマンドを手動再実行（first_failure +
   external_audit 生成）。

## 観測メモ

- token_map は run スコープの専用 PIIMasker インスタンスに保持・
  repo 全体で serialization 経路ゼロ（非永続化は構造的に成立）。
- 観測ID決定性は canonical payload に値フィールドを含めないことで維持。
- 新規テストの LSP 型問題1件（spy の getattr 化）を修正・4 passed 確認。
  他 LSP 警告は全て HEAD に存在する既存由来（タッチせず）。

## 成果物

- 変更: src/core/security/pii_masker.py / vdp_observation_adapter.py /
  vdp_hypothesis_generator.py / master_conductor.py / vdp_follow_up_executor.py /
  network_client.py + テスト6ファイル
- session: workspace/projects/localhost:3000/sessions/session_20260811_002205.json
- report: workspace/projects/localhost:3000/reports/haddix_report_20260811_002205.md
- evaluator: /tmp/opencode/m5-out-0439/first_failure_juiceshop_v1.json
