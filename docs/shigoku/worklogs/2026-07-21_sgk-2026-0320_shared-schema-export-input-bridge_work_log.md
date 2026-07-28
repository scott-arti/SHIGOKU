---
task_id: SGK-2026-0320-WL
doc_type: work_log
status: done
parent_task_id: SGK-2026-0320
related_docs:
  - docs/shigoku/plans/done/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
  - docs/shigoku/reports/2026-07-21_sgk-2026-0320_shared-schema-export-input-bridge_work_report.md
title: 'SGK-2026-0320 作業ログ: shared schema / export / input bridge'
created_at: '2026-07-21'
updated_at: '2026-07-28'
---

# SGK-2026-0320 作業ログ

## 2026-07-21

### Unit 1: shared schema 固定
- `IntentCommand` allowlist を Enum 化
- `AttackTargetSpec` / `ExportManifest` / `AttackTargetBundle` を dataclass 化
- `manifest_hash` 再計算、`allowed_hosts` fail-closed 検証、atomic write を追加

### Unit 2: 0326 single-session export
- `endpoint_extractor.py` 新設
- session 内の tagged URL 参照と canonical findings から target 候補を抽出
- `attack_targets.json`, `endpoints.json`, `endpoints.csv`, `endpoints.md` を出力
- `shigoku-ops session export-targets` と `report export-targets` を追加

### Unit 3: 0325 input bridge 最小版
- `--attack-targets` / `--wordlist` を `main.py` へ追加
- `InteractiveBridge` で bundle を load / validate
- signal bundle へ変換し、既存 `_create_attack_tasks_from_recon()` に接続
- manifest metadata を `target_info` へ保存

### Unit 4: 回帰と実 artifact 検証
- 4 新規テストファイル追加
- 既存 `shigoku_ops_cli`, `session_finding_inspector`, `interactive_bridge`, `import_recon` 近接テストを再実行
- real session artifact で export 実行し、13 件の target bundle 生成を確認

### Unit 5: 0325 intent parser / preview-confirmation loop
- `src/cli/intent_parser.py` を新設
- `ops_intent` role / prompt / config を追加
- `shigoku-ops ops intent` で NL→allowlist command preview を追加
- attack 系は `report.export-targets -> main.attack-targets` の 2-step preview を返す

### Unit 6: non-TTY fail-closed の追加
- `InteractiveBridge` に `SHIGOKU_ATTACK_TARGETS_APPROVED` を使う non-TTY preapproval gate を追加
- `ops intent --execute` から実行する場合のみ子プロセスへ preapproval env を引き渡す

### Unit 7: 0326 report 起点運用拡張
- `shigoku-ops report findings`, `report/session endpoints` を追加
- real report artifact で consistency → endpoints → export-targets → intent preview を確認

### Unit 8: cross-session findings export と safe end-to-end
- `shigoku-ops findings list/search/stats/export-targets` を追加
- mixed-scope findings DB に対する `cross_session_scope_required` fail-closed を追加
- `ops intent --execute --approve --main-dry-run` と `SHIGOKU_SKIP_ENTRY_GATE=1` の内部検証経路を追加
- external agent 向け `ops intent` function schema / 運用例を詳細コマンドリファレンスへ追記

### Unit 9: failure-path hardening / artifact redaction
- `ops intent` handler に対して `approval deny`, `command_timeout`, `ops_intent_kill_switch` の回帰テストを追加
- bundle helper に対して `allowed_hosts mismatch` と `scope外 target` の回帰テストを追加
- `write_attack_target_artifacts()` を更新し、`attack_targets.json` は machine-readable 正本のまま維持しつつ、`endpoints.{json,csv,md}` には既存 redactor を通すようにした

### Unit 10: freshness / provenance hardening
- `load_attack_target_bundle()` で `generated_at`, `ttl_days`, `scope_snapshot`, source provenance の欠落と expired bundle を fail-closed にした
- `build_attack_target_bundle_from_session()` / `build_attack_target_bundle_from_findings()` に `scope_snapshot` を埋めるようにした
- `recon_importer` は `recon_state.json` の `saved_at` を freshness 正本として扱い、欠落時は `missing_provenance` で reject するようにした
- `ops intent` の `malformed intent` で LLM fallback 初期化に失敗しても、CLI がクラッシュせず `intent_llm_unavailable` で止まるようにした

### Unit 11: TTY 実運用確認と親ロードマップのクローズ
- real TTY で `shigoku-ops ops intent --execute --main-dry-run` を承認付きで実行し、preview/confirmation loop の手動シナリオを完了
- operator manual に `ops_intent.feature_flag`, `ops_intent.kill_switch`, `ops_intent.daily_llm_budget`, preview-only へ戻す停止条件を追記
- `SGK-2026-0325` と `SGK-2026-0326` を done 化し、親ロードマップ `SGK-2026-0320` は done、P3 downstream continuation は `SGK-2026-0324` active で分離追跡する形に整理
