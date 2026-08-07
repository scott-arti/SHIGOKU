---
task_id: SGK-2026-0413
doc_type: work_report
status: done
parent_task_id: null
related_docs:
- docs/shigoku/plans/done/2026-07-31_execution-pipeline-dependency-admission-consistency_plan.md
- src/core/engine/lane_policy.py
- src/core/engine/master_conductor.py
- tests/unit/engine/test_lane_policy.py
- tests/core/engine/test_master_conductor_phase5_parallelism.py
- tests/core/engine/test_master_conductor_execution_admission.py
- docs/shigoku/worklogs/2026-07-31_sgk-2026-0413_execution-pipeline-dependency-admission-consistency_work_log.md
created_at: '2026-07-31'
updated_at: '2026-08-07'
deferred_tasks: []
---

# 作業報告：探索・実行判定・カバー率ガードの依存整合性修正

## 実施内容

- 実行する担当名と、並列実行で使う資源分類を分離した。偵察のようなレート制限付き読み取り専用タスクは、担当名ではなく `intel_active` として実行する。
- 初期の偵察タスクに、対象範囲確認の成功を待つ明示的な依存関係を追加した。
- 依存先の欠落・失敗・循環、または入場判定の拒否を、理由付きの `skipped` と実行記録として残すようにした。
- 攻撃フェーズが開く前には、カバー率用のXSS・CSRF・外部通信チェックを先回りで追加しないようにした。
- 未完了のまま残るタスクがあれば、サマリーを `completion_status: incomplete` とし、「正常に完了」と表示しないようにした。

## 判断理由

提示されたJuice Shopセッションでは、偵察タスクは選択済みなのに実行結果がなく、`pending` のまま終了していた。原因は、担当名 `recon_master` をそのまま並列実行カテゴリとして扱い、厳格なカテゴリ確認で拒否していたことだった。

修正はJuice ShopやDVWAのURL・画面・脆弱性名を条件にしていない。既存の安全分類、レート制限、範囲確認、攻撃フェーズ解放を共通の根拠として使う。

## 検証

- `venv/bin/pytest -q tests/core/engine/test_master_conductor_execution_admission.py tests/core/engine/test_master_conductor_phase5_parallelism.py tests/unit/engine/test_lane_policy.py tests/core/engine/test_master_conductor_vuln_family_gate.py`
  - 結果: 87件成功。
- `venv/bin/pytest -q tests/core/engine/test_master_conductor_failure_reason_codes.py -k 'not async_save_session_persists_normalized_skipped_reason_codes'`
  - 結果: 3件成功、1件は今回と無関係な既存失敗のため除外。
- `graphify update .`
  - 結果: コード関係図を更新。既存グラフデータの `source_file` 欠落に関する警告が1件あるが、実装対象の実行経路には影響しない。
- `python3 scripts/sync_shigoku_updated_at.py` と `python3 scripts/validate_shigoku_docs.py`
  - 結果: Front Matterとリンクのエラーは0件。今回と無関係な古い台帳参照2件のため、台帳全体の検証は `REGISTRY_ISSUES=2` となった。
- 実ターゲットへの通信・再実行は行っていない。利用者の明示指示が必要である。

## 残るリスク

- 広い既存テスト群は、この環境の `venv` に `psutil` がないため、完全には実行できない。また一部の既存テストはポリシー設定がない状態で攻撃タスク生成を試み、今回の変更と無関係に失敗する。
- 台帳全体には、`task_243` のrunbookと `task_268` のsubtask planへの既存の欠落参照があり、今回の文書だけでは全体検証を0件にできない。
- 実アプリへの再実行は未実施である。許可済みの対象で再実行し、scope → recon → attack の実行履歴とセッションの終端状態を確認する必要がある。

## 次のステップ

利用者が許可する対象で1回再実行し、偵察が `intel_active` として実行され、偵察結果の後に攻撃フェーズ・カバー率チェックが進むことを確認する。
