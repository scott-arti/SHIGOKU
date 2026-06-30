---
task_id: SGK-2026-0240
doc_type: work_report
status: done
parent_task_id: SGK-2026-0220
related_docs:
- docs/shigoku/plans/2026-05-23_sgk-2026-0240_ssrf-p0-fp_plan.md
- docs/shigoku/plans/2026-05-19_sgk-2026-0220_b-2-ssrf-tester_plan.md
- docs/shigoku/worklogs/2026-05-23_sgk-2026-0240_ssrf-quality-gate_work_log.md
created_at: '2026-05-23'
updated_at: '2026-06-30'
---

# Work Report: SGK-2026-0240 SSRF P0 判定品質強化

## 実装内容
- `src/core/attack/ssrf_tester.py`
  - `confidence_score` / `confidence_level` / `confidence_breakdown` を `SSRFResult` へ追加
  - `final_url`, `redirect_chain`, `destination_class`, `resolved_ips` を結果へ追加
  - baseline 比較 (`BASELINE_PROBE`) と差分シグナル評価を追加
  - `response.url` / `response.history` を使う最終到達評価を追加
  - open redirect only 減点 + 内部到達強証拠での救済加点を追加
  - payload type 別 baseline サイズ差分閾値を導入
  - `config/features.yaml` から `ssrf_quality` をロードして閾値/重みを外部設定化
- `tests/core/attack/test_ssrf_tester.py`
  - breakdown スキーマ固定（`schema_version` 含む）検証
  - open redirect 減点/救済の挙動検証
  - payload type 別 baseline 閾値検証
  - features.yaml ロード上書き検証
- `tests/integration/test_ssrf_quality_gate.py`（新規）
  - KPI相当テスト（FP抑制、強証拠検出維持、スキーマ完全性）を追加
- CI / 運用統制
  - `.github/workflows/test.yml` に `ssrf-quality-gate` と `ssrf-pr-policy` ジョブを追加
  - `.github/workflows/ssrf-quality-rollback.yml` を追加（workflow_run / workflow_dispatch）
  - `scripts/ssrf_quality_rollback.py` を追加（stable プロファイルへの復元）
  - `config/ssrf_quality_profiles/stable.yaml` を追加
  - `scripts/check_ssrf_pr_policy.py` を追加（閾値変更PRの必須記載チェック）
  - `.github/PULL_REQUEST_TEMPLATE.md` と `.github/CODEOWNERS` を追加
- ドキュメント整合ブロッカー解消
  - `docs/shigoku/manuals/external_tools_operations.md` に必須 Front Matter を追加

## 判断理由
- SSRF判定品質の負債は、検出ロジック単体の改善だけでは再発しやすいため、
  「判定ロジック + KPIテスト + PRポリシー + rollback導線」を同時に導入した。
- 閾値/重みを設定化して、コード改修なしで品質調整できる運用性を優先した。

## 検証結果
- `.venv/bin/pytest tests/core/attack/test_ssrf_tester.py tests/integration/test_ssrf_quality_gate.py -q`
  - `10 passed`
- `python3 scripts/ssrf_quality_rollback.py --dry-run --summary /tmp/ssrf_rollback_summary.json`
  - 実行成功、before/after 差分サマリー出力を確認
- `python3 scripts/sync_shigoku_updated_at.py && python3 scripts/validate_shigoku_docs.py`
  - 最終的に `FRONT_MATTER_ISSUES=0`, `BROKEN_LINKS=0`, `REGISTRY_ISSUES=0`

## リスク
- `ssrf-pr-policy` / `ssrf-quality-gate` を GitHub の Branch Protection へ必須登録しないと、
  CI上のジョブ追加だけでは強制力が不足する。
- `ssrf-quality-rollback` は default dry-run のため、即時自動復元を有効化するには
  運用判断（workflow_dispatch で non-dry-run もしくはルール拡張）が必要。

## deferred_tasks
- id: SGK-2026-0240-D1
  title: SSRF rollback の自動PR作成を本番運用条件で常時有効化
  reason: 誤発火リスク評価のため、まず dry-run 観測を優先
  impact: KPI失敗時の復旧が半自動（手動トリガ起点）に留まる
  planned_followup: 監視期間後に non-dry-run の常時運用へ切替
- id: SGK-2026-0240-D2
  title: Branch Protection の required checks 反映完了確認
  reason: リポジトリ設定はコード内で完結しない
  impact: 設定反映前はガードが運用規約依存
  planned_followup: `ssrf-pr-policy`, `ssrf-quality-gate` を required checks に登録して証跡化
