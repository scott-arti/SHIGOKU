---
task_id: SGK-2026-0385
doc_type: plan
status: active
parent_task_id: SGK-2026-0379
related_docs:
- docs/shigoku/plans/done/2026-07-23_sgk-2026-0379_dvwa-low-finding-regression-recovery_plan.md
- docs/shigoku/plans/done/2026-07-24_sgk-2026-0384_runtime-no-waste-guards-for-localhost-scanner-and-cors-phase2_plan.md
- docs/shigoku/subtasks/done/2026-07-25_dvwa-low-expected-detection-matrix_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-25_dvwa-low-regression-finding-restoration_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-25_dvwa-low-sqli-and-lfi-evidence-promotion_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-25_dvwa-low-command-injection-evidence-promotion_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-25_dvwa-low-browser-backed-xss-evidence-promotion_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-25_dvwa-low-file-upload-and-authswarm-skipped-result-recovery_subtask_plan.md
- docs/shigoku/subtasks/2026-07-25_dvwa-low-brute-force-captcha-csp-dedicated-detection_subtask_plan.md
title: DVWA low detection sufficiency and evidence quality recovery
created_at: '2026-07-25'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA Security=low / Haddix evidence quality / SHIGOKU detection pipeline
---

# 実装計画書：DVWA low detection sufficiency and evidence quality recovery

## 1. この計画の目的

DVWA Security=low に対する SHIGOKU の検知結果を、単なるタスク数や試行回数ではなく、次の観点で「必要十分」に近づける。

ただし、DVWA はテスト用に作られた脆弱なサーバーであり、現実のアプリには存在しにくい教材的な機能や設定も含む。この計画は DVWA に点を合わせるためのカーブフィッティングを目的にしない。DVWA は実アプリにありえる脆弱性クラスを検証する fixture として使い、DVWA 固有の不自然な仕様にだけ効く検知は作らない。

- 以前見えていた検知が落ちていないこと。
- 実アプリにも存在しそうな主要な脆弱性クラスに到達していること。
- Haddix レポートで、候補ではなく提出品質の confirmed finding を増やすこと。
- 無駄なタスク増殖を再発させないこと。
- ユーザーが許容している手動領域は、無理に自動化しないこと。
- DVWA 固有の教材ページだけに合わせた special case を作らないこと。

本計画は、直近の会話で合意した Task A〜E の親計画である。実装時に必要であれば、各 Task を個別の `subtask_plan` に分割してよい。

## 2. 前提となる実行結果と判断材料

この計画では、次の実行成果物を比較材料として扱う。レポートを使うときは必ず `scripts/verify_report_session_consistency.py` または `shigoku-ops report consistency` で対応セッションとの整合性を確認する。

| 位置づけ | Report | Session | 要点 |
|---|---|---|---|
| 機能追加前の参考値 | `workspace/projects/localhost:4280/reports/haddix_report_20260717_222441.md` | `workspace/projects/localhost:4280/sessions/session_20260717_222441.json` | 83 tasks。タスク数ではなく、当時見えていた検知内容の参考にする。 |
| 57 tasks 時代 | `workspace/projects/localhost:4280/reports/haddix_report_20260723_162936.md` | `workspace/projects/localhost:4280/sessions/session_20260723_162936.json` | 0 finding ではない。28 raw findings / 21 unique findings を確認済み。 |
| fuzzing 暴走例 | `workspace/projects/localhost:4280/reports/haddix_report_20260724_153123.md` | `workspace/projects/localhost:4280/sessions/session_20260724_153122.json` | 1000 tasks。`kg-end-*` fuzzing が同じ URL を繰り返した異常例。重複修正は別エージェントが対応中。 |
| 直近の改善後 | `workspace/projects/localhost:4280/reports/haddix_report_20260724_164750.md` | `workspace/projects/localhost:4280/sessions/session_20260724_164750.json` | 107 tasks。fuzzing は 50 URL × 1 回、queue 残り 0。22 raw findings。ただし Initial Release Gate は FAIL。 |

直近 107 tasks の状態は、1000 tasks のような暴走ではない。一方で、Haddix の Initial Release Gate は `confirmed_below_minimum` / `candidate_above_maximum` で FAIL しており、提出品質としてはまだ不足している。

## 3. ユーザー希望・方向性

この計画では、ユーザーの希望を次の制約として扱う。

- 83 tasks へ戻すこと自体は目的ではない。
- タスク数ではなく、以前見えていた検知の漏れと、提出品質の低さを直す。
- `scn_08_oob_external_channel_flow`, `scn_10_semantic_business_logic`, `scn_12_advanced_ssrf_internal_topology` は手動方針でよい。
- 並列化は今はやらない。
- 単に時間で切るだけの高速化は避ける。
- 「可能性がない」と判断するなら、人間が見ても納得できる決定的な根拠を持たせる。
- DVWA low は許可済み検証環境だが、SHIGOKU の bug bounty 方向性として、提出品質・証拠品質を重視する。
- 重複 fuzzing の後始末は別作業として進行中。本計画では、重複対応そのものを主目的にしない。
- DVWA には現実のアプリでは不自然な教材用機能もあるため、それだけに合わせた検知は作らない。
- 改善対象は、実アプリにもありえる脆弱性を見逃している、または分析はしたが調査・証拠化できていないケースに限定する。
- 「DVWA low にあるから必ず finding 化する」ではなく、「実アプリで同じパターンがあれば提出価値があるか」で優先度を決める。
- `scn_08`, `scn_10`, `scn_12` を手動方針に残すことと、OOB・multi-account・chain_builder を evidence 強化の部品として使うことは矛盾しない。自動化範囲は「提出品質の証拠づくり」に限定し、手動 scenario を無理に自動 PASS へ寄せない。
- 単一セッション、未配送リクエスト、未稼働 OOB、未再現の単発 signal を「脆弱でない」と扱わない。これらは `untested_*` または `payload_not_delivered_*` のような reason code として分離する。

## 3.1 2026-07-26 追加レビューで確認した事実

外部レビューの指摘をコード上で確認した結果、次の点は計画へ反映する。

| 指摘 | コード上の確認 | 計画上の扱い |
|---|---|---|
| IDOR/AuthBypass は 2 アカウントがないと確定しにくい | `src/core/agents/swarm/biz_logic_hunter.py` の `_verify_idor_with_second_account()` は secondary session がない場合 `second_account_not_available` を返す。`src/commands/hunt.py` も `attacker` / `victim` の両方を要求する。 | AuthBypass / IDOR / API BFLA の hard precondition に「2つの独立した認証アイデンティティ」を追加する。未設定時は `untested_no_second_account` とし、candidate / non-finding に混ぜない。 |
| OOB 基盤はあるが、攻撃成功証拠としての前提が弱い | `src/tools/oob/interactsh_client.py` は BBOT helper 不在時に OOB disabled。`src/core/detection/oob_correlator.py` の interactsh provider は placeholder。local listener は存在する。 | OOB を SCN08 自動化ではなく blind 系の強い証拠チャネルとして扱う。稼働確認できない場合は `oob_channel_unavailable` とし、OOB 不発だけで非脆弱扱いしない。 |
| chain_builder / attack path formatter は存在するが、本計画に統合されていない | `src/core/intelligence/chain_builder.py` と `src/reporting/attack_path_formatter.py` が存在し、MasterConductor から chain 推論を呼ぶ経路もある。 | confirmed primitive を chain_builder に渡す後段を追加する。ただし chain は session evidence で裏付けられるまで candidate/provisional とし、SCN11 の手動方針は維持する。 |
| 配送失敗と非脆弱性が混ざるリスク | upload / auth / injection 各所で `result=None` や request failure が成果物化されない経路がある。 | 全プローブで delivery telemetry を記録し、redirect-to-login / 500 / blocked / content-type mismatch などを `payload_not_delivered_*` として分離する。 |

## 4. 現在の不足

### 4.1 以前より落ちた可能性が高い検知

83 tasks 時代や 57 tasks 時代と比べ、直近 107 tasks で弱い、または消えている検知は次の通り。

| 対象 | 期待 | 現状の問題 |
|---|---|---|
| `/vulnerabilities/sqli/` | 通常 SQLi を finding として出す | 107 tasks では出ているが候補止まり。過去には見えていた。 |
| `/vulnerabilities/authbypass/get_user_data.php?id=2` | 権限昇格 / auth bypass を finding として出す | 107 tasks では AuthSwarm が skipped / result None で検知に繋がっていない。 |
| `/vulnerabilities/weak_id/?id=2` | 弱いセッション ID からの権限・セッション影響を出す | 107 tasks では weak_id 本体の候補はあるが、`?id=2` 付きの権限昇格系が落ちている。 |
| `/vulnerabilities/open_redirect/source/low.php?...` | open redirect / CRLF 系を正しく分類する | CRLF は出ているが、57 tasks 側にあった open_redirect finding は 107 tasks 側で消えている。 |

### 4.2 候補止まりの検知

直近 107 tasks では 22 raw findings があるが、Haddix レポート上は confirmed 2 / candidate 20 である。候補から確定に上げるべき主対象は次の通り。

| 対象 | 候補止まりの主理由 |
|---|---|
| SQLi | payload request mismatch / synthetic response evidence / timing or response difference 不足 |
| XSS | browser execution evidence missing |
| Command Injection | command execution not verified / synthetic response evidence |
| LFI | insufficient response difference / payload request mismatch |
| CSRF | state change not verified |
| Access Control / API | authz impact not proven |

### 4.3 タスクはあるが実行成果が無いもの

| 対象 | 現状 |
|---|---|
| File Upload | タスクは生成されるが `result=None` で finding に繋がっていない。 |
| AuthSwarm | `/vulnerabilities/authbypass/`, `/vulnerabilities/authbypass/get_user_data.php`, `/login.php` が skipped / result None になっている。 |

### 4.4 DVWA low 全体として条件付きで見る専用検知

Brute Force / CAPTCHA / CSP は fuzzing 対象には入っているが、DVWA の教材ページに合わせて専用検知を作るとカーブフィッティングになりやすい。

この領域は次の基準で扱う。

- Brute Force は、一般的なログイン画面・認証 API に対するレート制限、ロックアウト、認証差分として扱える場合のみ改善対象にする。
- CAPTCHA は、実アプリにありえる token reuse、server-side validation 不備、状態検証不備として説明できる場合のみ扱う。
- CSP は、単独 finding ではなく、危険な header policy や XSS 影響の補助 evidence として扱う。DVWA の教材用 CSP ページだけに合わせた finding 化はしない。
- いずれも SQLi / XSS / Command Injection / LFI / AuthBypass より後回しにする。

## 5. 必要十分の合格基準

### 5.1 共通ゲート

- 最新レポートとセッションの整合性が `consistent` である。
- `Coverage Gate` は PASS。
- Scenario Coverage は 9/12 以上。欠けてよいのは `scn_08`, `scn_10`, `scn_12` のみ。
- fuzzing は同じ URL を繰り返し大量生成しない。
- `task_queue` が異常に残らない。
- Initial Release Gate は、少なくとも `confirmed_below_minimum` を解消する。
- 可能であれば `candidate_above_maximum` も解消する。ただし候補抑制だけを目的に検知を隠してはならない。

### 5.1.1 攻撃成功を示すための共通 evidence ゲート

confirmed 昇格では、単なる「反応が違う」ではなく、次の evidence モデルを使う。

| ゲート | 内容 | 未達時の扱い |
|---|---|---|
| delivery telemetry | 各 probe で status、redirect chain、content-type、body length、login redirect、transport error、guard/WAF/block を記録する。 | ペイロードが sink に届いていない場合は `payload_not_delivered_<reason>`。非脆弱とは扱わない。 |
| proof_of_control | 一意 canary、payload 反射、ヘッダ制御、URL/パラメータ制御など、攻撃者入力が対象へ届いた証拠。 | control のみなら candidate。confirmed には原則しない。 |
| proof_of_impact | データ抽出、権限差分、コード/コマンド実行、ブラウザ実行、状態変更、OOB callback など、実害に近い影響証拠。 | impact がないものは candidate または補助 evidence。 |
| class-specific confirmation | SQLi error / boolean / timing / OOB、XSS browser execution、Command Injection output / timing / OOB、LFI file marker / wrapper impact など、クラス別の確認基準を使う。 | 一律の response diff だけで confirmed にしない。 |
| hard preconditions | IDOR/AuthBypass/API BFLA は 2つの独立した認証アイデンティティを必要条件にする。blind OOB 確認は OOB チャネル稼働確認を必要条件にする。 | 未設定時は `untested_no_second_account` / `oob_channel_unavailable`。candidate / non-finding に混ぜない。 |
| reproducibility | 安全に再試行できる検知は同一セッション内で独立再確認する。time-based / blind / execution 系は原則 3 回以上の再現を要求する。 | 再現不足は `provisional_confirmed` または candidate に留める。 |
| chain corroboration | confirmed primitive は chain_builder に渡して攻撃連鎖を評価する。ただし chain 自体は session evidence で裏付けられるまで confirmed finding にしない。 | chain は `chain_candidate` / `chain_blocked_<reason>` として扱う。SCN11 は手動方針を維持する。 |

このゲートは「検知を厳しくして隠す」ためではなく、配送失敗・前提不足・証拠不足を非脆弱と混同しないために使う。

### 5.2 DVWA low 期待検知マトリクス（実アプリ妥当性付き）

Task A でこの表を正本化する。実装中に追加・修正してよいが、各項目は「確定必須」「候補可」「条件付き」「今回は対象外」のいずれかに分類する。分類時は、DVWA にあるかではなく、実アプリでも同じ問題が提出価値を持つかを判断軸にする。

| クラス | DVWA low 対象 | 実アプリ妥当性 | 期待レベル | メモ |
|---|---|---|---|---|
| SQLi normal | `/vulnerabilities/sqli/` | 高 | 確定必須 | 通常応答との差分、SQL エラー、boolean 差分、抽出結果のいずれかを保存する。control canary と impact を分け、response diff 単独では confirmed にしない。 |
| SQLi blind | `/vulnerabilities/sqli_blind/` | 高 | 確定必須 | baseline N サンプル、true/false 非対称、統計的 time 差分、または OOB callback を保存する。OOB 未稼働時は `oob_channel_unavailable` とし、OOB 不発だけで非脆弱扱いしない。 |
| Command Injection | `/vulnerabilities/exec/` | 高 | 確定必須 | 安全な出力証拠、統計的 time 差分、または OOB callback を保存する。`;`, `&&`, `|`, `||`, newline, encoded newline, safe subshell などのメタ文字行列を guard 内で評価し、未評価文字は reason code 化する。 |
| Reflected XSS | `/vulnerabilities/xss_r/` | 高 | 確定必須 | ブラウザ実行証拠を保存する。HTML body / 属性 / JS 文字列 / URL / CSS / JSON / XML など、注入コンテキスト別に payload を選ぶ。 |
| Stored XSS | `/vulnerabilities/xss_s/` | 高 | 確定必須 | 投稿後の再表示と実行証拠を保存する。second-order として、保存面と読出し面を canary で紐づける。 |
| DOM XSS | `/vulnerabilities/xss_d/` | 高 | 確定必須 | ブラウザ実行証拠と DOM sink を保存する。URL fragment / query / DOM source と sink の対応を evidence に残す。 |
| LFI | `/vulnerabilities/fi/` | 高 | 確定必須 | 読み込まれたファイル内容や通常応答との差分を保存する。php://filter など非破壊 wrapper の確認を含め、RCE に進む wrapper は lab / 明示許可時だけ chain candidate として扱う。 |
| CSRF | `/vulnerabilities/csrf/` | 中 | 候補可から確定化を目指す | tokenless だけでなく、状態変更の before / after、token 削除、別セッション token 入替、GET/POST 差分、SameSite/Origin/Referer の観測を取る。 |
| Weak Session ID / Predictable ID | `/vulnerabilities/weak_id/` | 中 | 条件付き | 予測可能 ID だけでなく、セッション・権限・データ露出への影響が証明できる場合に扱う。2アイデンティティ未設定時は `untested_no_second_account` とする。 |
| AuthBypass / IDOR | `/vulnerabilities/authbypass/get_user_data.php?id=2` | 高 | 確定必須 | 2つの独立した認証アイデンティティで、認証・権限差分と機密データ露出を保存する。単一セッションのみでは confirmed にしない。 |
| API BFLA | `/vulnerabilities/api/v2/user/` | 高 | 候補可から確定化を目指す | unauth/auth に加え、必要なら attacker/victim の差分と機密フィールド確認を保存する。2アカウントが必要なケースは未設定時に `untested_no_second_account` とする。 |
| CORS | `/vulnerabilities/api/v2/user/` | 中 | 候補可 | public data read だけなら過大評価しない。credentialed read や機密情報露出がある場合に重視する。 |
| Open Redirect | `/vulnerabilities/open_redirect/source/low.php` | 中 | 条件付き | リダイレクト先制御が phishing / OAuth / SSO redirect abuse など実害に繋がる形で説明できる場合に扱う。 |
| CRLF | `/vulnerabilities/open_redirect/source/low.php` | 中 | 条件付き | 実レスポンスヘッダ差分があり、cache poisoning / header injection など実アプリの影響に繋がる場合に扱う。 |
| File Upload | `/vulnerabilities/upload/` | 高 | P2 で確定必須へ | 一般的な upload flow として再現可能な場合に扱う。まず `result=None` を解消し、upload request、保存先、取得可否、実行可否、content-type、login redirect を分けて記録する。 |
| Brute Force | `/vulnerabilities/brute/` | 中 | 条件付き P3 | 一般的な認証画面・API のレート制限/ロックアウト欠如として扱える場合のみ専用評価する。 |
| CAPTCHA | `/vulnerabilities/captcha/` | 低〜中 | 条件付き / 対象外可 | token reuse や server-side validation 不備として一般化できる場合のみ扱う。DVWA 教材ページ固有なら対象外。 |
| CSP | `/vulnerabilities/csp/` | 低〜中 | 補助 evidence / 対象外可 | 単独 finding ではなく、XSS 影響や危険 header policy の補助として扱う。DVWA 固有 bypass だけなら対象外。 |
| Error / Debug Disclosure | 複数 | 中 | 補助 evidence / 条件付き finding | SQL error、stack trace、内部パス、バージョン、debug page は一次確認チャネルまたは severity bump として体系的に保存する。単独 finding 化は機密度と実害で判断する。 |

## 6. 実装順序

### Task A: DVWA low 期待検知マトリクスの固定

目的: 直す前に、何が出れば合格かを固定する。

作業:

- 本計画の「DVWA low 期待検知マトリクス」を実装判断の正本として整備する。
- 各項目に、対象 URL、必要 evidence、confirmed / candidate 判定条件を定義する。
- 各項目に、実アプリ妥当性と「DVWA 固有なら対象外にできる条件」を定義する。
- レポート比較ではタスク数ではなく、`vuln_type + title + normalized target URL` を基本単位にする。
- SCN08 / SCN10 / SCN12 は手動扱いのままにする。
- DVWA の URL や教材機能だけに special case する実装は不可とする。

完了条件:

- 期待検知表が計画書または専用 spec に残っている。
- 後続 Task B〜E がこの表に基づいて評価できる。

### Task B: 以前出ていた検知の復旧

目的: 83 tasks / 57 tasks 時代に見えていた検知のうち、直近 107 tasks で弱くなったものを戻す。ただし、過去に出ていたという理由だけでは復旧対象にしない。実アプリでも同じ形で成立する見逃し、または調査・証拠化漏れだけを直す。

優先対象:

1. `/vulnerabilities/authbypass/get_user_data.php?id=2`
2. `/vulnerabilities/weak_id/?id=2`
3. `/vulnerabilities/open_redirect/source/low.php?redirect=...`
4. `/vulnerabilities/sqli/`

上記のうち、DVWA 固有の教材仕様にしか見えないものは、復旧ではなく reason-coded non-finding または対象外として整理する。

調査対象候補:

- `src/core/agents/swarm/auth_ninja.py`
- `src/core/agents/swarm/base_manager.py`
- `src/core/agents/swarm/injection/manager.py`
- `src/core/agents/swarm/injection/manager_internal/result_normalizer.py`
- `src/core/engine/master_conductor.py`
- `src/reporting/finding_extractor.py`
- `src/reporting/haddix_formatter.py`

完了条件:

- 最新 DVWA low run で、上記対象が raw finding として出る、または DVWA 固有の教材仕様として reason-coded non-finding / 対象外に整理される。
- 以前の結果と比較して、消えていた unique finding が戻る。戻さない場合は、実アプリ妥当性の観点で理由が説明されている。
- 追加タスクが異常増殖しない。
- `verify_report_session_consistency.py` が PASS。

### Task C 共通: confirmed 昇格の証拠モデル整備

目的: SQLi / LFI / Command Injection / XSS の個別修正に入る前に、候補・暫定確定・確定の境界を揃える。

作業:

- `proof_of_control` と `proof_of_impact` を evidence 上で分ける。
- payload delivery telemetry を全 injection probe で保存する。
- class-specific confirmation を使い、一律の response diff だけで confirmed にしない。
- time-based / blind / execution 系は、安全に再試行できる範囲で 3 回以上の再現確認を求める。
- OOB チャネルが必要な検証では、検知前に local listener / interactsh の稼働確認を行う。未稼働時は `oob_channel_unavailable` として扱う。
- confirmed primitive は chain_builder へ渡せる形に整える。ただし chain 自体は session evidence で裏付けられるまで candidate/provisional とする。

完了条件:

- `payload_not_delivered_*`, `untested_no_second_account`, `oob_channel_unavailable`, `provisional_confirmed`, `chain_candidate` のように、非脆弱とは異なる未達理由を表現できる。
- Haddix の evidence quality gate が、control-only と impact-proof を区別できる。

### Task C-1: SQLi / LFI の証拠強化

目的: 候補止まりの SQLi / LFI を confirmed に近づける。

理由: 実リクエスト・実レスポンス差分で証拠を作りやすく、Initial Release Gate 改善への効果が大きい。

作業:

- SQLi normal で、通常値 / true 条件 / false 条件 / error または data diff を保存する。
- SQLi blind で、baseline N サンプル、true / false 非対称、sleep payload の統計的差分、可能なら OOB callback を保存する。
- SQLi error / debug disclosure は、一次確認チャネルまたは severity bump の evidence として保存する。
- LFI で、payload 入り URL、レスポンスステータス、本文差分、既知ファイル断片を保存する。
- LFI は非破壊 wrapper (`php://filter` など) を評価し、RCE に進む wrapper やログポイズニングは lab / 明示許可時だけ chain candidate として扱う。
- evidence に synthetic ではなく実 HTTP の request / response を残す。

完了条件:

- `/vulnerabilities/sqli/`, `/vulnerabilities/sqli_blind/`, `/vulnerabilities/fi/` の候補理由が減る。
- `payload_request_mismatch`, `synthetic_response_evidence`, `insufficient_response_difference` が該当 findings で解消または減少する。

### Task C-2: Command Injection の証拠強化

目的: `/vulnerabilities/exec/` の Command Injection を confirmed に近づける。

作業:

- DVWA lab では安全な決定的 payload を使う。
- 可能なら command output を evidence に残す。
- time-based の場合は baseline / positive / negative を統計的に比較し、安全に再試行できる範囲で 3 回以上再現させる。
- `;`, `&&`, `|`, `||`, newline, encoded newline, safe subshell などのメタ文字行列を guard 内で評価する。未評価のメタ文字は `cmd_inj_metachar_<token>_untested` として残し、包括的な非脆弱扱いにしない。
- blind command injection では OOB callback を強い証拠として扱う。OOB 未稼働時は `oob_channel_unavailable` に分離する。
- bug bounty mode では危険 payload を自動で広げない。

完了条件:

- `command_execution_not_verified` が解消または減少する。
- evidence に実 request / response または強い比較証拠が残る。

### Task C-3: XSS のブラウザ証拠強化

目的: Reflected / Stored / DOM XSS を confirmed に近づける。

作業:

- 注入点を HTML body / 属性 / JS 文字列 / URL / CSS / JSON / XML / DOM source などの文脈に分類する。
- 文脈別 payload 行列を使い、1つの汎用 payload 集合だけで全点を否定しない。
- ブラウザ実行証拠を保存する。
- Reflected XSS は payload 反射だけでなく JS 実行を確認する。
- Stored XSS は投稿後の再訪問・別表示で確認し、保存面と読出し面を canary で紐づける。
- DOM XSS は URL fragment / query / DOM sink の実行を確認する。
- second-order は XSS だけのものと決め打ちせず、保存した canary が別画面/API/ログビュー等に出る場合は follow-up candidate として残す。

完了条件:

- XSS findings の `browser_execution_missing` が解消または減少する。
- report に再現手順と evidence が残る。

### Task C-4: confirmed primitive の chain review

目的: SQLi / LFI / Command Injection / XSS / File Upload / AuthBypass などの confirmed primitive を、単独 finding で止めずに攻撃連鎖候補へ接続する。

作業:

- confirmed primitive を chain_builder / attack_path_formatter に渡す。
- LFI→source disclosure / wrapper impact、File Upload→retrieval / execution、XSS→CSRF / ATO、AuthBypass→data exfiltration など、実アプリでも成立する chain candidate を抽出する。
- 破壊的または外部影響がある chain 実行は lab / 明示許可時だけにする。
- chain は session evidence で裏付けられるまで `chain_candidate` または `chain_blocked_<reason>` とする。

完了条件:

- confirmed primitive から attack path 候補が出る。
- chain が confirmed でない場合も、何が足りないかが reason code で分かる。
- SCN11 は手動方針を維持し、無理に scenario coverage を自動 PASS へ寄せない。

### Task D: File Upload / AuthSwarm skipped の修正

目的: タスクはあるのに `result=None` / skipped で成果物化されない問題を直す。

作業:

- File Upload の `LogicSwarm` がなぜ `result=None` になるかを調べる。
- AuthSwarm の `/vulnerabilities/authbypass/`, `/vulnerabilities/authbypass/get_user_data.php`, `/login.php` が skipped になる理由を調べる。
- File Upload / AuthSwarm の各 probe で delivery telemetry を保存し、redirect-to-login、500、content-type mismatch、body empty、transport error、guard block を `payload_not_delivered_*` として分離する。
- AuthBypass / IDOR / API BFLA は、2つの独立した認証アイデンティティが必要な場合に `untested_no_second_account` として扱う。
- 手動方針の scenario と、実行すべき Auth/FileUpload タスクを混同しない。
- 実行しない場合も、理由付き skipped として追跡可能にする。

完了条件:

- File Upload が finding になる、または明確な reason code 付きで非対象化される。
- AuthSwarm skipped が、手動方針ではなく実行漏れの場合は修正される。
- authbypass の raw finding が復旧する。

### Task E: Brute Force / CAPTCHA / CSP 条件付き専用評価

目的: Brute Force / CAPTCHA / CSP を、DVWA 教材ページに合わせて無理に finding 化しない。実アプリでも成立する問題だけを専用評価し、それ以外は reason-coded non-finding または補助 evidence として扱う。

作業:

- Brute Force は、一般的なログイン画面・認証 API のレート制限、アカウントロック、認証差分として評価する。
- CAPTCHA は、token reuse、server-side validation 不備、state validation 不備として一般化できる場合のみ評価する。
- CSP は、単独 finding ではなく header policy と XSS 影響の補助情報として評価する。
- CSRF を扱う場合は、tokenless だけでなく token 削除、別セッション token 入替、GET/POST 差分、SameSite / Origin / Referer 観測を評価する。
- DVWA の教材的なページ構造に依存する検知は作らない。

完了条件:

- fuzzing だけではなく専用 finding、補助 evidence、または reason-coded non-finding として扱える。
- Task C / D の成果を壊さない。

## 7. 検証手順

### 7.1 各タスク共通

```bash
python3 scripts/sync_shigoku_updated_at.py
python3 scripts/validate_shigoku_docs.py
```

レポートを使う場合:

```bash
python3 scripts/verify_report_session_consistency.py --report <absolute-haddix-report-path>
python3 scripts/shigoku_ops_cli.py --json report findings --report <absolute-haddix-report-path>
python3 scripts/shigoku_ops_cli.py --json report gate --report <absolute-haddix-report-path>
```

### 7.2 実行後の確認観点

- `findings_count` だけで判断しない。
- unique finding を `vuln_type + title + normalized target URL` で比較する。
- confirmed / candidate の内訳を見る。
- reason code が減ったかを見る。
- `Initial Release Gate` の理由を見る。
- `Coverage Gate` と `Scenario Coverage` を見る。
- fuzzing が URL 単位で再増殖していないかを見る。

## 8. 変更時の注意

- 既存の dirty worktree はユーザーまたは他エージェントの変更を含むため、無関係な差分を戻さない。
- レポートとセッションの時刻を混ぜて判断しない。
- report-only backfill を raw finding として扱わない。
- broad formatting はしない。
- 危険な payload や外部通信を増やす場合は、bug bounty mode と lab mode の制御を分ける。
- 固定 sleep や単純な経過時間だけで「無駄」と判断しない。
- DVWA のパスや教材ページ名だけを見て confirmed にする special case を作らない。
- 実アプリ妥当性が低い対象は、無理に finding 化せず reason-coded non-finding とする。
- Auth / session / credential まわりの cache は、認証値を含めた key を使う。
- MasterConductor の `__new__` テスト経路では lazy attrs に注意する。

## 9. この計画が完了したと言える状態

- Task A と Task B が完了している。
- Task C-1〜C-3 のうち、少なくとも SQLi / LFI / Command Injection / XSS の主要候補が confirmed へ昇格、または明確な reason code で候補扱いの理由が説明されている。
- confirmed 昇格では `proof_of_control` と `proof_of_impact` が分かれており、control-only を confirmed として扱っていない。
- delivery telemetry により、ペイロード未配送・ログインリダイレクト・transport error・block が非脆弱と混同されていない。
- IDOR/AuthBypass/API BFLA は 2アカウント前提の有無が reason code 化され、単一セッションだけで confirmed になっていない。
- time-based / blind / execution 系は、統計・OOB・再現性のいずれかで攻撃成功を説明できる。
- confirmed primitive から chain candidate が作られ、confirmed chain にできない場合も不足 evidence が説明されている。
- File Upload / AuthSwarm の `result=None` / skipped が、実行漏れではなく意図した状態になっている。
- DVWA 固有の教材機能だけに合わせた検知が増えていない。
- `haddix_report_*.md` と `session_*.json` の整合性が PASS。
- Initial Release Gate の `confirmed_below_minimum` が解消している。
- `candidate_above_maximum` が残る場合は、どの candidate を手動確認へ送るかが明確になっている。
- SCN08 / SCN10 / SCN12 は手動方針として残してよい。

## 10. 分割済み subtask_plan

本計画は親計画として維持し、実装作業は次の subtask_plan に分割して進める。

| 順 | Task ID | 役割 | Path |
|---|---|---|---|
| 1 | SGK-2026-0386 | Task A: DVWA low 期待検知マトリクスの固定 | `docs/shigoku/subtasks/done/2026-07-25_dvwa-low-expected-detection-matrix_subtask_plan.md` |
| 2 | SGK-2026-0387 | Task B: 以前出ていた検知の復旧 | `docs/shigoku/subtasks/done/2026-07-25_dvwa-low-regression-finding-restoration_subtask_plan.md` |
| 3 | SGK-2026-0388 | Task C-1: SQLi / LFI の証拠強化 | `docs/shigoku/subtasks/done/2026-07-25_dvwa-low-sqli-and-lfi-evidence-promotion_subtask_plan.md` |
| 4 | SGK-2026-0389 | Task C-2: Command Injection の証拠強化 | `docs/shigoku/subtasks/done/2026-07-25_dvwa-low-command-injection-evidence-promotion_subtask_plan.md` |
| 5 | SGK-2026-0390 | Task C-3: XSS のブラウザ証拠強化 | `docs/shigoku/subtasks/done/2026-07-25_dvwa-low-browser-backed-xss-evidence-promotion_subtask_plan.md` |
| 6 | SGK-2026-0391 | Task D: File Upload / AuthSwarm skipped の修正 | `docs/shigoku/subtasks/done/2026-07-25_dvwa-low-file-upload-and-authswarm-skipped-result-recovery_subtask_plan.md` |
| 7 | SGK-2026-0392 | Task E: Brute Force / CAPTCHA / CSP 条件付き専用評価 | `docs/shigoku/subtasks/2026-07-25_dvwa-low-brute-force-captcha-csp-dedicated-detection_subtask_plan.md` |

Task A と Task B はすぐ着手する。Task C は C 共通ゲート -> C-1 -> C-2 -> C-3 -> C-4 の順で進める。Task C-4 は、実装着手時に必要なら専用 subtask_plan として起票する。Task D は Task B の調査で AuthSwarm 原因が先に見えた場合、または delivery telemetry が C の阻害要因になった場合だけ前倒ししてよい。Task E は最後でよい。
