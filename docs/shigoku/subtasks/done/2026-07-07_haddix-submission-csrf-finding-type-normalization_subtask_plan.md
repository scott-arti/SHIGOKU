---
task_id: SGK-2026-0348
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0347
related_docs:
- docs/shigoku/plans/2026-07-07_haddix-report-bugbounty-quality-optimization_plan.md
- docs/shigoku/reports/2026-07-07_sgk-2026-0348_csrf-normalization_work_report.md
- docs/shigoku/worklogs/2026-07-07_sgk-2026-0348_csrf-normalization_work_log.md
- workspace/projects/127.0.0.1:4280/reports/haddix_report_20260707_135302.md
- workspace/projects/127.0.0.1:4280/sessions/session_20260707_163939.json
title: Haddix submission CSRF finding type normalization
created_at: '2026-07-07'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/reporting/haddix_submission_internal_formatter.py, src/reporting/haddix_evidence_quality.py,
  tests/unit/reporting/test_haddix_submission_internal_sections.py
---

# 実装計画書：Haddix submission CSRF finding type normalization

## 1. 達成したいゴール（ユーザー視点）
- [x] 既存 `session_20260707_163939.json` から `haddix-submission-internal` レポートだけを再生成したとき、CSRF finding が `misconfiguration` 扱いで提出用 confirmed に残らないこと。
- [x] title / URL / evidence から CSRF と判定できる finding は、report-time の submission quality 評価では `csrf` として扱われること。
- [x] `csrf_state_change.before_state` / `after_state` が無い CSRF finding は `state_change_not_verified` 付き candidate として内部評価側に移動すること。
- [x] CSRF finding の修正案は CORS ではなく、CSRF token / SameSite / Origin or Referer validation / re-auth を中心に表示されること。
- [x] 既存 session artifact は書き換えず、レポート生成時の分類補正のみで再生成できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/reporting/haddix_submission_internal_formatter.py`: （修正）submission/internal split formatter。report-time CSRF 正規化、enforcement split、candidate reason code 表示を担当する。
  - `src/reporting/haddix_evidence_quality.py`: （原則維持、必要なら小修正）`vuln_type="csrf"` に対して `csrf_state_change` 不足を `state_change_not_verified` にする validator。
  - `src/reporting/haddix_formatter.py`: （必要なら小修正）CSRF remediation helper。`vuln_type` 正規化後に CORS remediation が選ばれないことを確認する。
  - `tests/unit/reporting/test_haddix_submission_internal_sections.py`: （修正）実レポートで起きた `CSRF title + vuln_type=misconfiguration` の回帰テストを追加する。
  - `tests/unit/reporting/test_haddix_evidence_quality_gate.py`: （既存確認、必要なら補強）CSRF state-change 要件の単体テスト。
- **データの流れ / 依存関係:**
  - 既存 session の raw finding (`vuln_type=misconfiguration`, title=`CSRF Protection Missing...`) -> `HaddixSubmissionInternalFormatter.add_finding()` / `_get_enforced_split()` -> report-time CSRF 正規化 -> `HaddixEvidenceQualityValidator(mode="enforce")` -> `state_change_not_verified` candidate -> `Non-Submission Candidates` に表示。
  - raw session JSON と evidence JSON は immutable input として扱い、正規化結果はレポート生成中の `HaddixFinding` にだけ反映する。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - `HaddixFinding.title`: `CSRF`, `Cross Site Request Forgery`, `Tokenless Stateful Form` を含む可能性がある文字列。
  - `HaddixFinding.vuln_type`: 既存 session では `misconfiguration` になる場合がある。
  - `HaddixFinding.target_url`: `/vulnerabilities/csrf/` など CSRF endpoint を示す URL。
  - `HaddixFinding.summary` / `additional_info`: `anti-CSRF token`, `forged_request_succeeded`, `active_verify`, `csrf_state_change` などの補助 signal。
- **出力/結果 (Output):**
  - CSRF と推定できる finding は `vuln_type="csrf"` として evidence quality validator に渡る。
  - `csrf_state_change` が無い場合、提出用 scope には出ず、内部 candidate として `state_change_not_verified` を表示する。
  - `csrf_state_change` がある強い CSRF finding は confirmed に残ってよいが、remediation は CSRF 対策文言になる。
- **制約・ルール:**
  - raw session / raw evidence artifact は書き換えない。
  - `misconfiguration` 全体を CSRF に寄せない。CSRF title / URL / evidence signal がある場合だけ補正する。
  - `HaddixEvidenceQualityValidator` の既存 `csrf` ルールを再利用し、別の重複 gate を作らない。
  - secret redaction 境界は維持し、Cookie / PHPSESSID / security 値を提出用 scope に出さない。
  - report/session consistency checker が読む `Generated`, `Source Session`, scenario coverage 行の互換性を壊さない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `tests/unit/reporting/test_haddix_submission_internal_sections.py` に回帰テストを追加する。
  - `vuln_type="misconfiguration"`、title=`CSRF Protection Missing (Tokenless Stateful Form)`、target_url=`http://127.0.0.1:4280/vulnerabilities/csrf/`、`csrf_state_change` なしの finding を作る。
  - `HaddixSubmissionInternalFormatter` で markdown を生成し、提出用 scope に `CSRF Protection Missing` が出ないことを assert する。
  - 内部 candidate 側に `state_change_not_verified` が出ることを assert する。
  - 提出用 scope に `Access-Control-Allow-Origin` 型の CORS remediation が出ないことを assert する。
- [x] ステップ2: `HaddixSubmissionInternalFormatter` に report-time CSRF 正規化 helper を追加する。
  - 例: `_normalize_submission_quality_finding(finding: HaddixFinding) -> HaddixFinding`。
  - title / summary / target_url / additional_info を見て CSRF signal を検出する。
  - `vuln_type` が `misconfiguration` / `other` / `unknown` でも CSRF signal が強い場合だけ、formatter 内部用 copy の `vuln_type` を `csrf` にする。
  - `additional_info["normalized_vuln_type_from"]` と `additional_info["normalization_reason"]` を内部診断用に残す。
- [x] ステップ3: `_get_enforced_split()` または `_enforced_split()` の validator 前に正規化 helper を適用する。
  - confirmed / candidate に分ける前、または validator に渡す直前に全 finding へ適用する。
  - validator の verdict が `state_change_not_verified` を返した場合、candidate 表示に使えるよう `finding.additional_info["reason_codes"]` へ反映する。
  - 既存 candidate は不必要に confirmed へ昇格しない。
- [x] ステップ4: CSRF remediation の表示を確認・必要なら補正する。
  - `vuln_type="csrf"` の confirmed finding では `全状態変更リクエストにCSRFトークン検証とSameSite Cookie設定を適用する。` など CSRF 対策が出ることをテストする。
  - `misconfiguration` のままの CORS finding は既存 CORS remediation を維持する。
- [x] ステップ5: targeted tests を実行する。
  - `.venv/bin/pytest -q tests/unit/reporting/test_haddix_evidence_quality_gate.py tests/unit/reporting/test_haddix_submission_internal_sections.py`
  - 期待結果: 全件 pass。
- [x] ステップ6: 既存 session から新 timestamp report を再生成し、実 artifact を検証する。
  - report-only entrypoint は既存 CLI の `--format haddix-submission-internal` 経路を使う。
  - 元の `haddix_report_20260707_135302.md` は上書きしない。
  - 新 report に対して次を実行する:
    - `python3 scripts/verify_report_session_consistency.py --report <new-report> --session /home/bbb/Documents/App/Shigoku/workspace/projects/127.0.0.1:4280/sessions/session_20260707_163939.json`
    - `python3 scripts/check_initial_release_gate.py --report <new-report>`
  - 内容確認として、提出用 scope に CSRF が残らず、内部 candidate に `state_change_not_verified` が出ることを確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] title / URL ベースの正規化は heuristic である。誤分類を避けるため `misconfiguration` から `csrf` へ補正する条件を CSRF 固有 signal に限定する。
- [ ] [重要度:中] 既存 session には `vuln_type=misconfiguration` として保存済みのため、raw session と report 表示の分類が異なる。内部診断に `normalized_vuln_type_from` を残し、report-time 補正であることを追跡可能にする。
- [ ] [重要度:低] 将来的には CSRF 検出側で `vuln_type=csrf` と保存する方が望ましい。本タスクでは report-only 再生成を優先し、検出側修正は別タスクで扱う。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0348-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
