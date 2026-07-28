---
task_id: SGK-2026-0396
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
title: DVWA Medium コマンド注入完走と CRLF 証拠真正性の回復
created_at: '2026-07-27'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/core/agents/swarm;src/reporting;tests
---

# 実装計画書：DVWA Medium コマンド注入完走と CRLF 証拠真正性の回復

## 1. 達成したいゴール（ユーザー視点）

- [ ] 許可済みの DVWA Security=medium を実行したとき、コマンド注入検査がタイムアウトだけで終わらず、少なくとも「検査済みで安全」「攻撃成功」「未判定（配送失敗・タイムアウトなど）」を区別して記録できる。
- [ ] CRLF 注入は、実際に送信した攻撃リクエストと、その実応答のヘッダーが一致する場合にだけ confirmed finding とする。固定文字列や組み立てた見本を実証拠として提出しない。
- [ ] 報告書とセッションに、第三者が再確認できる最小限の証拠（リクエスト、応答、配送状態、判定理由）が残る。

対象は検知・証拠品質の修正であり、DVWA 固有のURLや単一の回避文字だけを特別扱いしない。許可済みスコープ、既存の安全ガード、HITL、2アカウント必須の認可検証方針は変更しない。

## 2. 全体像とアーキテクチャ

**確認済みの原因**

- Medium セッション `session_20260727_133637.json` の `cmd_focus_14265bc6` は、`/vulnerabilities/exec/` を対象に `cmd_ssrf` を実行したが、180秒で timeout した。`tested_params=[]`、finding 0件のため、攻撃失敗ではなく未判定である。
- `src/core/agents/swarm/injection/smart_crlf.py` は、実応答を検証せず `response_headers={...: "injected-via-crlf"}` と PoC応答を組み立てている。Medium レポートの4件はこの固定生成値と一致するため、実証拠ではない。

**対象コンポーネント/ファイル一覧**

- `src/core/agents/swarm/injection/manager.py`: `cmd_ssrf` の timeout、retry、tested parameter、delivery telemetry をセッションの試行記録へ残す入口。未判定を「安全」と誤表現しない。
- `src/core/agents/swarm/injection/smart_cmd_ssrf.py`: 実HTTP応答を使う安全なコマンド注入プローブと、タイムアウト時の中断可能な段階・理由コードを実装する中心。
- `src/core/agents/swarm/injection/smart_crlf.py`: 実際に送信した完全なリクエストURLと、実HTTP応答のヘッダー差分を照合する。合成したPoC応答を廃止する。
- `src/reporting/`: finding の delivery / evidence / reason code を、そのままセッションとHaddixレポートに表示する既存経路を確認し、必要最小限だけ補強する。
- `tests/core/agents/swarm/test_smart_cmd_ssrf.py`, `tests/core/agents/swarm/injection/test_smart_crlf.py`, `tests/core/agents/swarm/injection/test_crlf_pipeline.py`, `tests/core/agents/swarm/test_injection_manager.py`: 成功・安全・タイムアウト・証拠不一致を固定する回帰テスト。

**データの流れ / 依存関係**

`対象URL・認証済みリクエスト情報` → `InjectionManager` → `SmartCmdSSRFHunter / SmartCRLFHunter` → `実送信結果（完全なrequest、status、redirect chain、headers、body要約、elapsed、transport error）` → `finding または未判定reason code` → `session JSON` → `canonical extractor` → `Haddix report / gate`

## 3. 具体的な仕様と制約条件

### 3.1 コマンド注入

- 入力は、対象URL、発見済みのパラメータ、認証文脈、既存のプログラムスコープ・安全ガードである。
- URLにクエリがなくても、フォーム・観測済みリクエスト・再利用可能なパラメータを用いて候補を解決する。候補が解決できない場合は `untested_no_injection_parameter` とする。
- 検査は各段階を個別の明示的timeoutで制御し、全体timeout時も既に得た配送情報を失わない。任意の sleep による同期は使わない。
- 成功は、安全な出力canary、統計的に有意な時間差、または稼働確認済みOOB相関のいずれかで確認する。単一の応答差分やLLMの推測では confirmed にしない。
- timeout、接続失敗、ログインへのリダイレクト、WAF/guard block、候補パラメータ不足は「安全」ではなく、識別可能な reason code と delivery telemetry として残す。

### 3.2 CRLF 注入

- confirmed の必須条件は、(1) payload を含む実送信request、(2) 実HTTP response、(3) baseline応答にない、canary名または値を含む追加・変化した応答ヘッダー、の3点である。
- evidence の `request_url` / `poc_request` とpayloadの整合を検証する。payloadが証拠のrequestに存在しない、または応答が合成値・未取得なら confirmed を作らない。
- redirect先の値が変わっただけ、URL構文が壊れているだけ、source code表示ページだけを検査しただけ、またはレスポンスヘッダーをライブラリが正規化して重複を失った場合は、明確なreason code付きcandidateまたは未判定にする。
- `source/low.php` や `source/medium.php` をSecurity設定の実行経路と混同しない。実行対象・source表示・テストfixtureを区別する。

### 3.3 共通の安全・品質制約

- 公開プログラムでは、compiled guard、許可scope、レート制限、既存のHITL判断を必ず通す。DVWAでのみ有効な特例や固定ペイロードの成功判定は導入しない。
- session/report schema の既存フィールドを削除・転用しない。追加するreason codeやtelemetryはreaderを全検索してから加える。
- cookie、認証情報、トークン、機密レスポンス全文は成果物に平文保存しない。必要な証拠は既存のredaction境界を通す。

## 4. 実装ステップ（AIに指示する手順）

- [x] ステップ1: 現行の `cmd_ssrf` 実行経路を、ターゲット選択、パラメータ解決、送信、timeout、retry、session保存まで追跡する。Mediumセッションの timeout を再現する最小テストを先に追加し、timeout後も `tested_params`、最終ステージ、delivery状態、reason codeが残る失敗テストを作る。
- [x] ステップ2: `SmartCmdSSRFHunter` と manager のtimeout境界を修正する。安全な段階的プローブを中断可能にし、既存のguardを通過した実送信だけを判定に使う。結果を confirmed / safe / untested_or_inconclusive に分け、safe を返すのは十分な検査が完了した場合だけにする。
- [x] ステップ3: `SmartCRLFHunter` の合成証拠を実通信ベースへ置換する。baselineとpayload送信を同一条件で比較し、payload入りrequestと実response headerの一致を検証する。条件を満たさない既存の固定値型結果はcandidateまたは未判定に降格する。
- [x] ステップ4: 単体・manager統合・reporting のテストを追加する。特に「payloadなしのrequest + injected-via-crlf」は失敗、「実header差分 + payload入りrequest」は成功、timeoutは未判定、既存の正しいSQLi/LFI/XSS evidence は不変、を確認する。
- [ ] ステップ5: 許可済みDVWA Mediumで実行し、最新report/sessionの整合性、command injectionの最終理由、CRLFの証拠一致、Coverage Gate、候補reason codeを確認する。SCN08/10/12、HITL、2アカウント不足は既定どおり保留として扱う。実行前後に `verify_report_session_consistency.py` を実行する。

### 追加実施（2026-07-28）

- [x] 実フォームを取得できた場合は、そのフォームの入力欄だけをPOST本文とPoCに残すようにした。上流の別画面由来パラメータを混入させない。
- [x] confirmed findingにも、脆弱性種別・送信先パス・HTTPメソッド・攻撃パラメータをキーとする統合を適用した。同じURLでも攻撃パラメータが異なる場合は統合しない。
- [x] `session_20260727_165727.json` を正規抽出し、同一コマンド注入2件が提出前の統合で1件になることを確認した。
- [ ] この追加修正を含む次回のDVWA Medium全体実行で、生成済みreportのPoC本文が最小フォーム項目だけになっていることを最終確認する。

## 4.1 完了条件

- `/vulnerabilities/exec/` が再びtimeoutした場合でも、セッションには送信候補、送信済みか、最終ステージ、timeout reasonが残り、報告上「安全」と誤表示されない。
- command injectionが実証拠を得た場合だけ confirmed になり、得られない場合は再現可能な未判定として残る。
- CRLFのconfirmed findingには、payload入りの実requestと、baselineとの差分を示す実response headerがある。`injected-via-crlf` の固定合成値だけではconfirmedにならない。
- Medium report/session consistency は `consistent`、Coverage GateはPASS、SCN08/10/12の手動保留と2アカウント/HITL必須候補は変更しない。
- DVWAのパス名・Securityレベル・固定レスポンスに依存した成功判定を追加していないことを、汎用テストfixtureで確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）

- [ ] [重要度:中] CRLFではHTTPクライアントや中継プロキシが重複ヘッダーを正規化する場合がある。実raw responseを取得できない環境では、confirmedではなく `response_header_observation_incomplete` として保留する。
- [ ] [重要度:中] コマンド注入のtime-based確認はネットワーク遅延で誤判定し得る。baseline/controlを複数回測り、OOB未稼働を「安全」と混同しない。
- [ ] [重要度:低] 実行時間を短くするために証拠取得を省略しない。timeout設定の最適化は、正しい未判定telemetryが残ることを確認してから別タスクで扱う。
