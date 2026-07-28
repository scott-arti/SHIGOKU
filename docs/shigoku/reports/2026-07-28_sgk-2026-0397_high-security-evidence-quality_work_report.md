---
task_id: SGK-2026-0397
doc_type: work_report
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/subtasks/done/2026-07-28_high-security_subtask_plan.md
created_at: '2026-07-28'
updated_at: '2026-07-28'
---

# 作業報告: High実行の誤昇格防止とSecurityレベル別期待値評価

## 実施内容

- OpenAPI / Swagger / AsyncAPI形式の公開仕様書を、認可不備のconfirmed findingにしない共通証拠判定を追加した。
- session fixationをconfirmedにするには、攻撃者が設定した識別子、被害者のログイン、攻撃者側での認証済み再利用の3証拠を要求するようにした。
- `expected-detections` はsessionの`security` cookieからSecurityレベルを解決し、low専用matrixをHighへ流用しない。未定義レベルは比較不能としてfail-closedで返す。

## 判断理由

High実行で確認された公開OpenAPI文書とCookie不変は、URL名の例外ではなく、認可影響とsession takeoverが未証明という共通の欠落だった。個別のDVWAルールではなくevidence quality validatorへ実装した。

## 検証

- `uv run --with pytest pytest -q tests/unit/reporting/test_haddix_evidence_quality_gate.py tests/unit/reporting/test_expected_detection_matrix.py tests/unit/scripts/test_shigoku_ops_expected_detection_cli.py tests/unit/reporting/test_haddix_submission_internal_sections.py` -> 213 passed。
- High sessionをformatterで再評価し、confirmedがcommand injection 1件とXSS 3件だけになり、OpenAPI文書とsession fixationがcandidateへ移ることを確認。
- `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260728_002447.md` -> consistent。
- `shigoku-ops report expected-detections` はHighで`expected_detection_profile_not_defined_for_security_level`を返し、Low基準の不足を生成しないことを確認。

## 残るリスク

- 既に生成済みのHighレポート本文は自動的には書き換わらない。次回レポート生成時から新しい判定が反映される。
- High向けの独立した期待値プロファイルは未定義であり、現時点では意図的に比較をblockedにする。

## 次のステップ

許可済みの次回DVWA High実行で、新生成レポートのconfirmedが4件であり、OpenAPI文書とsession fixationが提出範囲外のcandidateに残ることを確認する。
