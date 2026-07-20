---
task_id: SGK-2026-0367
doc_type: plan
status: done
parent_task_id: SGK-2026-0122
related_docs:
- docs/shigoku/specs/fix_injection_swarm.md
- docs/shigoku/plans/done/2026-07-15_sgk-2026-0365_injection-timeout-trace-selection-observability_plan.md
- docs/shigoku/reports/2026-07-15_sgk-2026-0365_work_report.md
- docs/shigoku/plans/2026-07-16_dom-xss-latent-parameter-inference-hardening_plan.md
- workspace/projects/localhost:4280/reports/haddix_report_20260715_151429.md
title: Injection task ownership normalization and no-signal Phase2 suppression
created_at: '2026-07-16'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/recon/pipeline.py, src/core/engine/master_conductor.py, src/core/engine/task_expander.py,
  src/core/agents/swarm/injection/manager.py, src/core/agents/swarm/injection/smart_xss.py
---

# 実装計画書：Injection task ownership normalization and no-signal Phase2 suppression

## 1. 達成したいゴール（ユーザー視点）
- [ ] 最新 DVWA run で確認された `xss_candidate` の二重実行を解消し、同一 URL 群が `InjectionManagerAgent` と `InjectionSwarm` の両方から重複して叩かれないこと。
- [ ] `http://localhost:4280/vulnerabilities/javascript/` のような no-signal XSS ターゲットで、根拠のない長時間 Phase 2 に入らず、説明可能な条件で早く打ち切れること。
- [ ] 速度最適化の結果として検出品質を落とさないよう、subtask 化後も recon 由来の per-URL evidence が保持され、XSS 判定に使われること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/pipeline.py`: recon 完了直後に enqueue している `InjectionManagerAgent` 系タスクの役割を見直し、MasterConductor 側の attack task 生成と owner が衝突しないようにする。
  - `src/core/engine/master_conductor.py`: recon 結果から作る attack task の canonical owner と `phase2_on_empty_phase1` の付与条件を整理する。
  - `src/core/engine/task_expander.py`: `targets_file` 展開後も `source_file` / `forms_by_url` / `url_evidence_by_url` などの recon evidence を subtask に保持する。
  - `src/core/agents/swarm/injection/manager.py`: Phase 1 no-signal 時の Phase 2 進入条件を tightening し、skip reason を session に残す。
  - `src/core/agents/swarm/injection/smart_xss.py`: per-URL evidence が渡ったときに candidate param 選定へ反映される前提を回帰で守る。
  - `tests/core/agents/swarm/`, `tests/core/engine/`: duplicate suppression / evidence preservation / no-signal Phase 2 suppression の回帰テストを追加する。
- **データの流れ / 依存関係:**
  - `tagged_xss_candidate.jsonl` などの recon 出力 -> `master_conductor._create_attack_tasks_from_recon()` -> `task_expander` subtask 化 -> `InjectionManagerAgent.dispatch()` -> session `url_results`
  - 今回の根因はこの途中で `1) owner が二重化` し、さらに `2) subtask 側で evidence が薄いまま no-signal Phase 2 に入る` ことにある。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - recon が生成した category/file/count 情報
  - tagged URL JSONL の `url`, `forms`, `response_headers`, `response_body_snippet`, `has_form_tag`
  - Injection task の `targets`, `target`, `_context`, `phase2_on_empty_phase1`
- **出力/結果 (Output):**
  - ownership の判定単位を `(normalized_url, vuln_family, execution_path)` とし、同一 key を二つの injection 実行経路が同時所有しない task plan
  - 同一 family / 同一 execution path の二重所有は禁止する一方、family が異なる場合の同一 URL 再利用は許可する
  - subtask 化後の各タスクが `count=1`, `targets=[target]`, 対象 URL 1件分だけの `forms_by_url` / `url_evidence_by_url` / `selection_origin` を保持すること
  - no-signal XSS subtasks が `phase1_summary` で終了したことを示す session evidence
  - `phase1_safe_skip_no_signal` 時に `selection_origin`, `priority_score`, `priority_signals`, `response_status`, `has_form_tag`, `query_keys`, `phase2_block_reason` を session に残すこと
  - duplicate suppression と evidence preservation を壊さない回帰テスト
- **制約・ルール:**
  - 本タスクの適用スコープは二段で分ける。ownership 正規化は `xss_candidate` / `api_candidate` / `id_param` / `file_param` に適用し、no-signal Phase 2 suppression の詳細 tightening はまず `xss_candidate` を正本として固める。
  - `execution_path` の正規値は少なくとも `recon_tagged`, `history_replay`, `fallback`, `coverage_backfill`, `coverage_backfill_guard` を持ち、task / session の両方で同じ語彙を使う。
  - ownership の優先順位は `recon_tagged(通常)` > `history_replay` / `fallback` > `coverage_backfill` > `coverage_backfill_guard` を基本とし、claim は queue 追加前に行う。ownership の寿命は 1 実行セッション内に限定する。
  - Injection の並列化はこのタスクでは扱わない。逐次実行前提を維持したまま、無駄な重複だけを除去する。
  - Coverage gate を満たすための backfill / guard task は壊さない。必要な family coverage は維持する。
  - `coverage_backfill_guard` / `coverage_backfill` は通常の `xss_candidate` と同一扱いにせず、Phase 2 進入条件と suppression 条件を明示的に分岐させる。
  - no-signal Phase 2 suppression は `tool_error`, `weak_signal`, `high_risk_requires_phase2` がない場合に限定する。
  - `client_route_dom`, `javascript/`, hash-route, form が無くても query を持つ URL は no-signal suppression の例外候補として扱い、静的アセット扱いで即 suppress しない。
  - `method != GET`, `Content-Type: application/json`, `has_form_tag=true`, `discovered_params` / `candidate_params` / `params_list` が非空の target は、`phase1_safe_skip_no_signal` の候補から原則除外する。
  - evidence が落ちたまま `safe_skip` させない。subtask への evidence 継承を acceptance 条件に含める。
  - evidence 継承の対象には `forms_by_url` / `url_evidence_by_url` だけでなく、`discovered_params`, `candidate_params`, `params_list`, `selection_origin`, `source_file`, `source_category`, `execution_path` を含める。
  - replay / fallback で補完した target は `source=history_replay` または `source=fallback` を明示し、`xss_candidate` では既定で Phase 2 を強制しない。
  - low-value 除外は `forms=0` だけで判定せず、`query_keys`, route token, `response_body_snippet` の弱さが重なった場合に限定する。
  - DVWA report / session の before / after 比較は、`.venv/bin/shigoku-ops` または `python3 scripts/verify_report_session_consistency.py --report ...` で verdict が `consistent` の場合にだけ実施し、それ以外は blocker として扱う。
  - DOM `default` パラメータの高度な推定ロジックは原則別件とし、本タスクでは evidence 継承で改善する範囲までを先に固める。

## 4. 懸念点と対策（レビュー反映）

### 4.1 SRE / インフラ視点
- [ ] `【発生確率:高】【影響度:大】` `xss_candidate` だけ先に直しても、`api_candidate` / `id_param` / `file_param` で同じ二重 enqueue が再発する懸念。
  - 対策: ownership key を `(normalized_url, vuln_family, execution_path)` で統一し、少なくとも `xss_candidate` / `api_candidate` / `id_param` / `file_param` に同じ admission rule を適用する。
- [ ] `【発生確率:高】【影響度:大】` ownership の定義だけ先に決めても、実際にどこで reject するかが曖昧だと queue に積まれた後で重複が残る懸念。
  - 対策: ownership 判定は `_add_tasks()` またはその直前の task 生成時に実施し、queue 追加前に同一 ownership key の task を reject / suppress する。
- [ ] `【発生確率:高】【影響度:大】` ownership の寿命が未定義なままだと、replan / retry / restart 時に「前回の claim をどこまで有効扱いするか」が揺れて運用事故になる懸念。
  - 対策: ownership は 1 実行セッション内だけ有効とし、永続化しないこと、replan 時は同一実行中の queue admission で再計算することを仕様へ追記する。
- [ ] `【発生確率:高】【影響度:大】` recon 側と `master_conductor` 側に URL 解決・low-value 判定・履歴 replay が重複実装されており、片方だけ直しても再発する懸念。
  - 対策: URL 選定・evidence 抽出・low-value 判定は canonical path に寄せ、非 owner 側は pass-through または enqueue 禁止にして責務を分離する。
- [ ] `【発生確率:高】【影響度:大】` `history_replay` / `fallback` / `coverage_backfill` / `coverage_backfill_guard` の優先順位が曖昧だと、通常 task を押しのけて低品質ソースが owner を奪う懸念。
  - 対策: source 優先順位を `recon_tagged(通常)` > `history_replay` / `fallback` > `coverage_backfill` > `coverage_backfill_guard` と固定し、同一 ownership key で競合したときの勝者を明文化する。
- [ ] `【発生確率:中】【影響度:大】` no-signal suppress 後に「なぜ止めたか」を session から説明しにくい懸念。
  - 対策: `phase1_safe_skip_no_signal` 時に `selection_origin`, `priority_score`, `priority_signals`, `phase2_block_reason`, `response_status`, `has_form_tag`, `query_keys` を必須記録する。
- [ ] `【発生確率:中】【影響度:中】` 改善の効果を測る比較指標が計画書に無く、短縮できたか判断しにくい懸念。
  - 対策: before / after で `xss_candidate task数`, `Phase 2進入数`, `平均task時間`, `safe_skip件数` を残す。
- [ ] `【発生確率:中】【影響度:大】` safe-skip を即時有効化すると、過剰 suppress が起きたときに原因を切り分けにくい懸念。
  - 対策: 最初の検証では「止める判定だけ記録して実際には止めない shadow 記録モード」または同等の比較ログを 1 回用意し、`source_category` / `execution_path` / `phase2_block_reason` 別件数を before / after に残す。
- [ ] `【発生確率:中】【影響度:大】` safe-skip や ownership 正規化が強すぎたときの即時切り戻し手段が無いと、実行結果の悪化に対して運用側がすぐ復旧できない懸念。
  - 対策: ownership 正規化と no-signal safe-skip の双方に対して、設定フラグまたは段階的 enable スイッチで即時無効化できる切り戻し経路を計画書へ明記する。

### 4.2 ソフトウェアアーキテクト視点
- [ ] `【発生確率:高】【影響度:大】` canonical owner の定義域が曖昧で、URL 単位・family 単位・execution path 単位のどこで重複禁止するか不明瞭な懸念。
  - 対策: ownership の正本定義を `(normalized_url, vuln_family, execution_path)` と明文化し、禁止する重複と許可する再利用を計画書に固定する。
- [ ] `【発生確率:高】【影響度:大】` ownership 正規化は複数カテゴリに広げる一方、Phase 2 suppression は XSS 起点で段階導入したいのに、そのスコープ分離が計画書上で曖昧な懸念。
  - 対策: 「ownership 正規化は `xss_candidate` / `api_candidate` / `id_param` / `file_param` に適用」「no-signal suppression tightening はまず `xss_candidate` のみ」を仕様として分離記載する。
- [ ] `【発生確率:高】【影響度:大】` `execution_path` の値集合が未定義だと、実装者ごとに別名が生まれて ownership key が実質不安定になる懸念。
  - 対策: `execution_path` の正規値を `recon_tagged`, `history_replay`, `fallback`, `coverage_backfill`, `coverage_backfill_guard` などで固定し、task / session / test が同じ語彙を使うようにする。
- [ ] `【発生確率:中】【影響度:大】` URL の正規化ルールが曖昧だと、末尾スラッシュ、`http/https`、デフォルトポート、hash、query 順序の違いで ownership 判定がぶれて重複抑止が不安定になる懸念。
  - 対策: `normalized_url` の規則として、少なくとも末尾スラッシュ、hash、デフォルトポート、query key の並び順の扱いを明文化し、同一扱いにするものと区別するものを仕様に固定する。
- [ ] `【発生確率:中】【影響度:大】` recon 側の `_context` を共有辞書のまま task に流すと、別 task の evidence が混ざって誤判定を招く懸念。
  - 対策: task ごとに新しい `_context` を生成し、`self.state.__dict__` や共有 dict をそのまま使い回さず、必要な evidence のみをコピーして閉じ込める。
- [ ] `【発生確率:高】【影響度:大】` `task_expander` が親 task の集合メタデータを shallow copy すると、subtask 側の `count` や evidence の意味が壊れる懸念。
  - 対策: subtask は `count=1`, `targets=[target]`, 対象 URL 1件分の `forms_by_url` / `url_evidence_by_url` のみを持つ形へ正規化する。
- [ ] `【発生確率:中】【影響度:大】` `_context` を「新しく作る」とだけ書いても、list / dict のどこまで task-local にするかが曖昧だと shallow copy の再発を止めきれない懸念。
  - 対策: `forms_by_url[target]`, `url_evidence_by_url[target]`, `discovered_params`, `candidate_params`, `params_list` は subtask ごとに新しい dict / list として閉じ込め、親 task と可変オブジェクトを共有しないことを受け入れ条件へ追加する。
- [ ] `【発生確率:中】【影響度:大】` `coverage_backfill_guard` と通常 `xss_candidate` の Phase 2 条件が混ざると、ガード用 task の意味が崩れる懸念。
  - 対策: guard/backfill task の suppression 条件を通常 task と別ポリシーにし、どこで分岐するかを仕様に書く。
- [ ] `【発生確率:中】【影響度:中】` evidence 継承の成功条件が曖昧で、`smart_xss.py` 側が何を前提にしてよいか不明な懸念。
  - 対策: `forms`, `method`, `response_headers`, `response_body_snippet`, `has_form_tag` が target 単位で参照できることを受け入れ条件に含める。

### 4.3 デバッガー視点
- [ ] `【発生確率:高】【影響度:大】` テスト観点が粗く、どの層で壊れたか切り分けにくい懸念。
  - 対策: `master_conductor`, `task_expander`, `InjectionManagerAgent`, DVWA artifact の4層に分けて targeted test / 実 artifact 確認を実施する。
- [ ] `【発生確率:高】【影響度:大】` ownership と safe-skip の分岐が多いのに、どの入力条件を最低限回すかのテスト行列が無いと、壊れた条件を後追いでしか発見できない懸念。
  - 対策: `同一URL同一family`, `同一URL別family`, `normal vs backfill`, `backfill vs guard`, `history_replay`, `fallback`, `javascript/ 例外`, `hash-route+query 例外`, `POST/JSON 例外` を含む最小テスト行列を実装前に固定する。
- [ ] `【発生確率:中】【影響度:中】` 実 artifact の before / after 比較前に report/session 整合性を確認しないと、別セッションの時刻や内容を混ぜて誤判断する懸念。
  - 対策: DVWA artifact 比較前に `.venv/bin/shigoku-ops` を第一候補として使い、少なくとも `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260715_151429.md` を実行して verdict が `consistent` であることを確認する。
- [ ] `【発生確率:中】【影響度:大】` `phase2_block_reason` や新しい skip evidence を足しても、既存 reader / formatter がそれを読めないままだと「保存したが使えない」状態になる懸念。
  - 対策: 実装前に `phase1_summary`, `selection_evidence`, `phase2_block_reason`, `selection_origin` の reader を検索し、必要なら reader 側の回帰テストも追加する。
- [ ] `【発生確率:中】【影響度:大】` `phase1_safe_skip_no_signal` が evidence 不足なのか、本当に no-signal なのか区別できない懸念。
  - 対策: skip reason を `no_form_signal`, `no_candidate_param`, `low_priority_root_only`, `risk_not_met` などに分解して保存する。
- [ ] `【発生確率:中】【影響度:中】` 現在の `task_expander` テストが evidence 保持まで見ておらず、今回の本丸を守れない懸念。
  - 対策: `forms_by_url` / `url_evidence_by_url` が 1 URL に縮約されて subtask に残る回帰テストを追加する。
- [ ] `【発生確率:中】【影響度:中】` session に残る `selection_evidence` が圧縮されすぎて、判定根拠を後追いしにくい懸念。
  - 対策: 生の本文全文は残さずとも `body_shape=json`, `content_type`, `form_field_names` などの判定要約を残す。
- [ ] `【発生確率:中】【影響度:中】` consistency checker の verdict が `consistent` 以外だったときの扱いが曖昧だと、不整合 artifact を比較に混ぜて誤結論になる懸念。
  - 対策: verdict が `consistent` 以外なら before / after 比較を中止し、reason code をそのまま blocker として記録する手順を計画書へ明記する。
- [ ] `【発生確率:中】【影響度:中】` before / after 指標をどこに保存するかが未定義だと、後から比較結果を再確認できず、検証の再現性が落ちる懸念。
  - 対策: 比較指標の保存先を session / work_report / 補助 Markdown などのいずれかに固定し、最低でも `task数`, `Phase 2進入数`, `平均task時間`, `safe_skip件数`, `source_category別件数` を同じ形式で残す。

### 4.4 hacker 視点
- [ ] `【発生確率:高】【影響度:大】` no-signal suppression が強すぎると、DOM 型や遅延反映型 XSS を静かなだけで落とす懸念。
  - 対策: `client_route_dom`, `javascript/`, hash-route, form なし query あり URL は suppress 例外候補として別判定に回す。
- [ ] `【発生確率:高】【影響度:大】` `POST`, `PATCH`, `application/json`, `has_form_tag=true` のような入力面がある URL まで quiet 扱いで safe-skip すると、反射しにくい XSS や API 入力面を落とす懸念。
  - 対策: `method != GET`, `Content-Type: application/json`, `has_form_tag=true` のいずれかを満たす target は `phase1_safe_skip_no_signal` 候補から除外し、別の no-signal 例外経路で扱う。
- [ ] `【発生確率:中】【影響度:大】` low-value 判定が広すぎると、実際は入力面を持つフロントエンド route が巻き込まれる懸念。
  - 対策: static path だけで落とさず、query / route token / response body の弱さが重なったときだけ low-value 扱いにする。
- [ ] `【発生確率:中】【影響度:大】` `discovered_params` / `candidate_params` / `params_list` が subtask や XSS 実行器まで届かないと、本当は打つべきパラメータを「候補なし」と誤認する懸念。
  - 対策: evidence 継承契約に param hint 群を追加し、これらが残っている target は `no_candidate_param` 扱いで即 safe-skip しない。
- [ ] `【発生確率:中】【影響度:中】` history replay / discovered asset fallback が薄い根拠の target を再注入し、長い空振りを再発させる懸念。
  - 対策: replay / fallback 起点の target には明示ラベルを付け、`xss_candidate` では既定で Phase 2 を自動強制しない。
- [ ] `【発生確率:低】【影響度:中】` 重複解消を強くしすぎると、family が異なる観点の有効な再利用まで止めてしまう懸念。
  - 対策: 禁止するのは「同一 family / 同一 execution path の二重所有」のみとし、family が異なる再利用は許可する。
- [ ] `【発生確率:中】【影響度:大】` 同じ URL でも `query` / `form` / `json` / `dom` / `route-state` の入力面が異なるのに、それを区別せず重複扱いすると有効な再検証まで止まる懸念。
  - 対策: 入力面の違いは `execution_path` または補助メタデータとして task / session に残し、ownership 例外や safe-skip 判定で使えるようにする。

## 5. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `recon.pipeline` と `master_conductor` の両方で生成される injection task を棚卸しし、「ownership 正規化は `xss_candidate` / `api_candidate` / `id_param` / `file_param` に適用」「no-signal Phase 2 suppression の詳細 tightening はまず `xss_candidate` を正本とする」というスコープ境界を計画書内で固定する。
- [ ] ステップ2: `execution_path` の正規値を `recon_tagged`, `history_replay`, `fallback`, `coverage_backfill`, `coverage_backfill_guard` で統一し、必要な `source_category`, `selection_origin`, 入力面メタデータを task / session / テストで同じ語彙に揃える。あわせて `normalized_url` の規則として、末尾スラッシュ、hash、デフォルトポート、query key 順序の扱いを固定する。
- [ ] ステップ3: ownership の寿命を 1 実行セッション内に限定すること、優先順位を `recon_tagged(通常)` > `history_replay` / `fallback` > `coverage_backfill` > `coverage_backfill_guard` とすることを仕様へ追記し、最初の比較用に shadow 記録モードまたは同等の suppress 判定ログを残す手段を用意する。さらに、ownership 正規化と no-signal safe-skip を個別に即時無効化できる切り戻しフラグを用意する。
- [ ] ステップ4: ownership 判定を queue 追加前のどこで実施するかを固定し、`_add_tasks()` または task 生成直後で同一 ownership key の task を reject / suppress する admission point を実装する。競合時は source 優先順位に従って勝者を決め、通常 task と guard/backfill task の勝敗ルールも明示する。
- [ ] ステップ5: URL 解決・evidence 抽出・low-value 判定・history replay・fallback の責務を整理し、どちらが canonical path になるかを決める。非 owner 側では同じ category の二重 enqueue を発生させず、`history_replay` / `fallback` 起点の target には source ラベルを必ず付ける。
- [ ] ステップ6: task ごとに新しい `_context` を生成する方針へ整理し、共有 dict を使い回さずに必要な evidence だけを task-local に閉じ込める。`forms_by_url[target]`, `url_evidence_by_url[target]`, `discovered_params`, `candidate_params`, `params_list` は新しい dict / list として複製し、親 task の可変オブジェクトを共有しない。
- [ ] ステップ7: `task_expander` から subtask に落とす際、`count=1`, `targets=[target]`, `target`, `selection_origin`, `source_file`, `source_category`, `execution_path`, 対象 URL 1件分の `forms_by_url` / `url_evidence_by_url` / param hint 群だけを持つよう正規化し、親 task の集合メタデータをそのまま持ち込まない。
- [ ] ステップ8: `InjectionManagerAgent` の `phase2_on_empty_phase1` 条件を `xss_candidate` 向けに tightening しつつ、`client_route_dom`, `javascript/`, hash-route, form なし query あり URL に加えて、`method != GET`, `Content-Type: application/json`, `has_form_tag=true`, 明示 param hint あり target を safe-skip 例外候補として扱う。`phase1_safe_skip_no_signal` では `phase2_block_reason` と分解済み skip reason を session に残す。
- [ ] ステップ9: `smart_xss.py` と target prioritization の前提を回帰で固定し、subtask 化後も `forms`, `method`, `response_headers`, `response_body_snippet`, `has_form_tag`, `discovered_params`, `candidate_params`, `params_list` が param 候補選定と優先度計算に使われることを保証する。
- [ ] ステップ10: `phase1_summary`, `selection_evidence`, `phase2_block_reason`, `selection_origin` を読んでいる reader / formatter / report path を検索して影響範囲を棚卸しし、新しい session evidence を既存の読取経路が壊さないことを回帰で確認する。
- [ ] ステップ11: targeted test を `master_conductor`, `task_expander`, `InjectionManagerAgent` の各層で追加し、最低でも `同一URL同一family`, `同一URL別family`, `normal vs backfill`, `backfill vs guard`, `history_replay`, `fallback`, `javascript/ 例外`, `hash-route+query 例外`, `POST/JSON 例外` の行列をカバーする。
- [ ] ステップ12: DVWA session artifact を使った再確認の前に `.venv/bin/shigoku-ops` を第一候補として整合性確認を行い、少なくとも `python3 scripts/verify_report_session_consistency.py --report /home/bbb/Documents/App/Shigoku/workspace/projects/localhost:4280/reports/haddix_report_20260715_151429.md` を実行して `consistent` を確認する。verdict が `consistent` 以外なら before / after 比較を中止し、reason code を blocker として記録する。その上で「重複解消」「long empty XSS task の短縮」「guard/backfill の挙動維持」「source_category / execution_path / phase2_block_reason 別の件数」「before / after 指標の記録」を比較し、保存先を work_report または同等の比較 artifact に固定して残す。

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] `javascript/` の `default` パラメータ検出が evidence 継承だけで十分戻らない可能性がある - 追跡タスク `SGK-2026-0368` で `smart_xss.py` の DOM variant 向け param inference を強化する。
- [ ] [重要度:中] `api_candidate` / `id_param` / `file_param` については ownership 正規化を本タスクで揃える一方、family ごとの no-signal Phase 2 抑止閾値の微調整は XSS 差分観測後に段階展開する。
- [ ] [重要度:中] 人間的 quick reject（low-value shadow gate）は別系統の品質改善であり、本タスクには混ぜ込まない - telemetry を見ながら次タスク化する。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0367-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
