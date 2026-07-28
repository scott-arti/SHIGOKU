---
task_id: SGK-2026-0393
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
- docs/shigoku/reports/2026-07-27_sgk-2026-0393_dvwa-low-candidate-hygiene-and-expected-detection-strictness_work_report.md
- docs/shigoku/worklogs/2026-07-27_sgk-2026-0393_dvwa-low-candidate-hygiene-and-expected-detection-strictness_work_log.md
title: DVWA low candidate hygiene and expected detection strictness
created_at: '2026-07-27'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA low / expected detections / AuthZ CORS CSRF candidate hygiene
---

# 実装計画書：DVWA low candidate hygiene and expected detection strictness

## 1. 達成したいゴール（ユーザー視点）
- [x] `shigoku-ops report expected-detections` が「候補があるだけ」で required confirmed を満たした扱いにしないこと。
- [x] 同じ `/vulnerabilities/api/v2/user/` の AuthZ/API BFLA 候補が、レポートの候補件数を不当に膨らませないこと。
- [x] CORS / CSRF は、攻撃成功証拠が足りない場合に confirmed ではなく candidate として残り、理由コードで説明されること。
- [x] 既存レポートと source session の整合性を確認したうえで、次回生成時の候補件数が改善することを確認すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/reporting/expected_detection_matrix.py`: required confirmed / candidate の判定を、raw finding の有無ではなく evidence quality verdict で判定する。
  - `src/reporting/haddix_formatter.py`: AuthZ / CORS / CSRF 候補の重複集約キーとメタデータ統合を追加する。
  - `src/reporting/haddix_submission_internal_formatter.py`: enforcement 後の候補リストを集約し、理由コード内訳と候補詳細に反映する。
  - `tests/unit/reporting/test_expected_detection_matrix.py`: required confirmed と candidate_to_confirm の期待動作を固定する。
  - `tests/unit/reporting/test_haddix_submission_internal_sections.py`: API AuthZ 候補が重複カウントされないことを固定する。
- **データの流れ / 依存関係:**
  - session raw findings -> `HaddixEvidenceQualityValidator` -> expected detection matrix の `match_status` / `reason_codes`
  - session raw findings -> Haddix report formatter -> enforcement split -> candidate dedup -> Submission Readiness Diagnostics

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** DVWA low session JSON、Haddix report path、raw findings。
- **出力/結果 (Output):** expected detection JSON、Haddix report の confirmed/candidate 件数、候補理由コード。
- **制約・ルール:**
  - DVWA固有の不自然な仕様へカーブフィットしない。
  - 実アプリでも存在しそうな見逃し・未検証・証拠不足だけを扱う。
  - CORS wildcard public data、CSRF state change 未確認、2アカウント未設定 AuthZ は confirmed にしない。
  - 候補の重複集約は同一URL・同一AuthZ/CORS/CSRFシナリオに限定し、別種の攻撃検知は畳まない。
  - 既存レポートは過去生成物なので内容は変わらない。修正効果は同一 session からの次回レポート生成で確認する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: expected detection matrix に evidence quality verdict を接続し、required confirmed は confirmed match が無い場合に missing_required へ残す。
- [x] ステップ2: candidate_to_confirm は candidate match を許容し、CSRF/CORS/API BFLA の未確定理由を JSON に出す。
- [x] ステップ3: Haddix report の enforcement 後 candidate list に AuthZ/CORS/CSRF の限定的な重複集約を入れる。
- [x] ステップ4: 候補理由コード内訳を複数コード対応にし、集約された候補詳細に raw candidate 数を表示する。
- [x] ステップ5: unit tests、expected-detections CLI、実レポート consistency、同一 session 一時レポート生成で検証する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] 一時生成レポートでも candidate は 5 件残る。これは重複ではなく、API BFLA / AuthBypass / weak_id / CORS / CSRF の未確定候補である。次回は2アカウント証明や CSRF state change 証明など、候補を本当に確定または除外する作業で扱う。
- [ ] [重要度:低] 既存 `haddix_report_20260727_083300.md` は過去生成物なので candidate 10 のまま。再生成または次回フル実行で candidate 5 の出力を確認する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0393-D01
    title: "AuthZ / CORS / CSRF の候補を実証で確定または除外する"
    reason: "今回の範囲は候補の重複集約と厳密な分類まで。攻撃成功証拠の追加は別スライス。"
    impact: medium
    tracking_task_id: SGK-2026-0385
    recommended_next_action: "2アカウント設定、CSRF before/after state、CORS credentialed/sensitive impact の検証を続ける"
```
