---
task_id: SGK-2026-0397
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
- docs/shigoku/subtasks/2026-07-27_dvwa-medium-crlf_subtask_plan.md
title: High実行の誤昇格防止とSecurityレベル別期待値評価
created_at: '2026-07-28'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/reporting;tests/unit/reporting;tests/unit/scripts
---

# 実装計画書：High実行の誤昇格防止とSecurityレベル別期待値評価

## 1. 達成したいゴール（ユーザー視点）
- [ ] 公開API仕様書や一般公開情報を、認可不備の confirmed finding として提出用レポートへ載せないこと。
- [ ] セッション固定を confirmed とするのは、ログイン前後の識別子継続だけでなく、攻撃者が指定した識別子による認証済み利用まで実証できた場合だけであること。
- [ ] `shigoku-ops report expected-detections` はSecurity=low専用の期待値をHighへ適用せず、対象Securityレベルを解決できない場合は比較を拒否すること。
- [ ] 上記はDVWAのURL名や固定レスポンスではなく、認可影響・セッション成立・Securityレベルという共通証拠契約で判定すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/reporting/haddix_evidence_quality.py`: 共通のconfirmed/candidate証拠判定。認可、セッション固定、ファイルアップロードの脆弱性種別を同じ根拠で判定する。
  - `src/reporting/haddix_submission_internal_formatter.py`: evidence qualityのenforce結果を提出用confirmed/candidateへ反映する既存経路を維持する。
  - `src/reporting/expected_detection_matrix.py`: low専用matrixの選択と、未定義のSecurityレベルをfail-closedで比較不能にする結果を提供する。
  - `scripts/shigoku_ops_cli.py`: report/sessionからSecurityレベルを読み、expected-detectionsへ渡す。
  - `tests/unit/reporting/test_haddix_evidence_quality_gate.py`, `tests/unit/reporting/test_expected_detection_matrix.py`, `tests/unit/scripts/test_shigoku_ops_expected_detection_cli.py`: 実証要件とCLI契約を固定する。
- **データの流れ / 依存関係:**
  - raw finding + structured evidence -> `HaddixEvidenceQualityValidator` -> enforce済み confirmed/candidate -> Haddix submission report
  - consistent report -> source sessionのSecurity文脈 -> low matrix選択または未定義レベルのblocked結果 -> expected-detections出力

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** canonical finding (`dict` / `HaddixFinding`)、`additional_info`内のauthz/session証拠、consistent sessionのSecurityレベル。
- **出力/結果 (Output):** 証拠不足なら標準reason code付きcandidate、比較可能なSecurityレベルなら対応matrixの結果、不明または未対応レベルなら`status=blocked`とreason code。
- **制約・ルール:**
  - URL名・OpenAPIの文言・DVWA固有の固定値で例外化しない。公開かどうかは、認証/認可差分と非公開・機密データまたは権限外操作の実証で判断する。
  - セッション固定は、before/afterのID一致、攻撃者が設定したID、被害者ログイン後に攻撃者側で認証済み利用できることを同一evidenceで要求する。Cookie値はreportへ平文出力しない。
  - `DEFAULT_DVWA_LOW_EXPECTED_DETECTIONS`はlow専用として保持し、Highに流用しない。Highのmatrixは「Highで防がれるべきLowの検知」をrequired missにしない。
  - 既存schemaは削除・転用せず、reason codeと評価metadataは加算的に扱う。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: evidence quality validatorとreport formatterのconfirmed/candidate経路を追跡し、公開文書・セッション固定・High matrix誤適用を表す失敗テストを追加する。
- [x] ステップ2: 認可影響とセッション固定を共通証拠契約で評価する。公開情報、200->200、単なるID不変はcandidateにし、完全な権限外データ/操作またはsession takeover evidenceだけをconfirmedにする。
- [x] ステップ3: Securityレベルをsessionから正規化してexpected-detectionsへ渡し、low matrixだけを明示的に選択する。レベル不明・未対応ならrequired missを捏造せずblockedで返す。
- [x] ステップ4: targeted pytest、CLI integration test、既存High report/sessionのconsistency checkとexpected-detectionsを実行して、公開仕様書・session fixationがconfirmedから除外されることを確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] Highの実アプリ横断ベンチ - Securityレベル名に依存しない外部アプリで、共通証拠契約の妥当性を確認する。
- [ ] [重要度:中] 2アカウントを要する認可検証 - ユーザーが許可した安全な二者テスト文脈がある場合だけ、candidateを実証済みへ進める。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0397-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
