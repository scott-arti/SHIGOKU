---
task_id: SGK-2026-0415
doc_type: work_report
status: done
parent_task_id: null
related_docs:
- docs/shigoku/plans/done/2026-07-31_sgk-2026-0415_external-tool-command-and-recon-outcome-consistency_plan.md
- src/core/config/settings.py
- src/recon/tool_runner.py
- src/recon/pipeline.py
- src/tools/custom/httpx.py
- src/core/engine/master_conductor.py
- tests/unit/config/test_tool_command_resolution.py
- tests/recon/test_step3_livecheck.py
- tests/recon/test_step3b_hybrid_url.py
- tests/unit/test_robustness_phase4.py
- tests/tools/test_batch_execution.py
- tests/core/engine/test_master_conductor_execution_admission.py
- docs/shigoku/worklogs/2026-07-31_sgk-2026-0415_external-tool-command-and-recon-outcome-consistency_work_log.md
created_at: '2026-07-31'
updated_at: '2026-08-07'
deferred_tasks: []
---

# 作業報告：外部ツール実行契約と偵察結果表示の整合性修正

## 実施内容

- 空文字または空白だけの `tool_httpx_path` を、標準コマンド `httpx` として解決する共通処理を追加した。設定済みの独自パスは一つの実行ファイル名としてそのまま使う。
- 偵察パイプラインのhttpxについて、利用可能かの確認と実行に同じ解決済みコマンドを使うようにした。空文字をOSへ渡して失敗する経路をなくした。
- 実コマンドを起動する前に、空のコマンドを分かりやすい設定エラーとして止める確認を追加した。開発モードのモック実行は従来どおり先に動く。
- Step 3bが、プロキシ未設定時に `127.0.0.1:8080` へ勝手に送る既定値を削除した。明示設定されたプロキシは従来どおり渡す。
- タスクの未完了判定は変えず、利用者向けに `succeeded`、`completed_with_failures`、`incomplete` の結果状態を追加した。失敗したタスクがある実行は「正常に完了」と表示せず、最終表にも `Outcome` を出す。

## 判断理由

原因は Juice Shop や `/#/` 固有ではない。設定辞書の `get` はキーが存在して値が空文字なら空文字を返すため、既定値 `httpx` に置き換わらず、空の実行ファイルを起動しようとしていた。

このためアプリ名・URL・SPAフラグメントを条件にした例外処理は追加していない。設定、外部コマンド、プロキシ、終了表示という共通の境界を直した。既存のスコープ、レート制限、タイムアウト、引数リストでの安全な起動方法、セッション保存の意味は変更していない。

## 検証

- 修正前の回帰テスト: 10件失敗、36件成功。空コマンドの `Permission denied: ''`、独自パスの不一致、未設定プロキシ、結果状態の欠落を再現した。
- `venv/bin/pytest -q tests/unit/config/test_tool_command_resolution.py tests/unit/test_robustness_phase4.py tests/recon/test_step3_livecheck.py tests/recon/test_step3b_hybrid_url.py tests/tools/test_batch_execution.py tests/core/engine/test_master_conductor_execution_admission.py`
  - 結果: 46件成功。
- `venv/bin/pytest -q tests/unit/config/test_tool_command_resolution.py tests/unit/config/test_caido_proxy_resolution.py tests/unit/test_robustness_phase4.py tests/recon/test_recon_pipeline_proxy_gate.py tests/recon/test_step3_livecheck.py tests/recon/test_step3b_hybrid_url.py tests/tools/test_batch_execution.py tests/core/engine/test_master_conductor_execution_admission.py tests/core/engine/test_master_conductor_phase5_parallelism.py`
  - 結果: 82件成功。
- `venv/bin/python -B -c '...ast.parse(...)...'`
  - 結果: 変更した5つのPythonファイルの構文確認に成功。
- `graphify update .`
  - 結果: 関係図を更新。既存グラフデータの `source_file` 欠落警告が1件あるが、今回の5ファイルの解析は完了した。
- 実ターゲットへの再実行・通信は、利用者から今回明示的な依頼がないため行っていない。

## 残るリスク

- 実アプリでの再実行は未実施である。次回は、`Permission denied: ''` が出ず、偵察タスクがhttpxを起動して成果物を後続処理へ渡せることを確認する。
- 実行が成功してもSPAの画面内ルートが十分に拾えない場合は、別の一般的なブラウザ探索の課題として調査する。今回の原因とは混同しない。
- `graphify update .` の入力データ警告は今回の実装と無関係だが、別途グラフの完全性を確認する余地がある。

## 次のステップ

利用者が同じ `http://localhost:3000/#/` を再実行し、偵察ログで `httpx` が空でなく起動されることを確認する。タスクが失敗した場合は、終了メッセージと `Outcome` が `completed_with_failures` になり、「正常に完了」とは表示されない。
