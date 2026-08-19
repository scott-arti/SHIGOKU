---
task_id: SGK-2026-0454
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-16_sgk-2026-0453_sqli-impact-demonstration-defense-evasion.md
- docs/shigoku/reports/2026-08-20_sgk-2026-0454_xss-dom-firing-path_work_report.md
- docs/shigoku/worklogs/2026-08-20_sgk-2026-0454_xss-dom-firing-path_work_log.md
- docs/shigoku/plans/2026-08-20_sgk-2026-0455_dom-xss-confirmation-routing.md
created_at: '2026-08-18'
updated_at: '2026-08-20'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
- xss
- dom
- browser
- proxy
---

# SGK-2026-0454 計画書 — XSSの発火経路是正（DOM実行検証の到達性・ブラウザ導入・プロキシ経由の回復）

## 完了メモ（2026-08-20・status=done / 方針B）

発火経路の是正は達成。Juice Shop の看板DOM XSS `/#/search?q=<img src=x onerror=alert(1)>` で、Caido(8081)経由・**本物のブラウザ上で実際に alert 発火を実観測**（`browser_execution.dialog_observed=true`, executor=playwright）。`attempt_traces` に `xss:dom_browser_validation` が実データで出現（C1）。バー5点 `git diff --quiet HEAD` 全 exit0（C5）、製品非依存 verdict=pass/token0（C6）、新規40+回帰107 pass（C7）、chromium導入＋明示ログ（C2）、proxy配線（C3）。コミット `94a083c`。

未達は **C4（本物のXSSを confirmed に）**。実データ funnel で当該XSS finding（id 512d98c4bde8）は **F3(phase2) で `phase2_skipped_early_return` / `risk_not_met` / `phase2_on_empty_disabled` により脱落**し、確定判定(F5/F6)に到達していない（confirmed=0・Gateは正しく fail-closed）。原因は凍結したバー5点ではなく、その手前の phase2 昇格ロジックにある可能性が高い（要精密診断）。DeepSeekが当初挙げた「判定予算枯渇/poc_judge形式拒否」は funnel 実データと矛盾し、Claude 独立検証で否定（hypothesis 扱い）。

方針B：本タスクは発火経路是正（C1/C2/C3/C5/C6/C7）で `done`。C4＝ブラウザ実行証拠の確定経路是正は後続 **SGK-2026-0455** へ分離（バー無改変・カーブフィッティング禁止を継承）。

## 目的（Objective）

防御ありの相手（実在の練習台=OWASP Juice Shop 等）に対して、XSSの本命確認手段である「本物のブラウザで実際にスクリプトが実行されたことの確認（DOM実行検証）」まで**攻撃が到達し、確定バーを緩めずに本物として確定できる**状態にする。現状のXSSはSQLiより手前で、しかも複数箇所で止まっている。SQLiと同じ考え方（確定の門は緩めず、その門まで攻撃を届かせる）で、発火経路の是正のみを行う。

本タスクは検出・確認パイプラインの発火経路是正であり、確定の合否基準（バー）は1バイトも変更しない。

## 現状の根拠（実測で確定した3つの詰まり）

いずれも実データ（`workspace/projects/localhost:3000/sessions/session_20260816_223550.json` と対応 report `haddix_report_20260816_223552.md`）とコード読解・実起動テストで確認済み。

### 詰まり①：XSSの種類分けがDVWA専用の目印頼み（到達性の根本原因）
- `src/core/agents/swarm/injection/smart_xss.py:233-241` `_detect_xss_variant(target)` は、URLパスに `xss_s`/`xss_r`/`xss_d`/`javascript` が含まれるかだけで stored/reflected/dom を判定し、それ以外は `generic` を返す。これらは DVWA のルート目印（`/vulnerabilities/xss_r/` 等）に依存している。
- Juice Shop の実パス（`/rest/products/search`、`/#/search` 等）はどの目印にも一致せず、すべて `generic` に落ちる。
- 影響：ブラウザによるDOM実行検証は `smart_xss.py:958` の `if not self.vulnerable and self._detect_xss_variant(target) == "dom":` でのみ起動する。`generic` では到達せず、`_validate_dom_runtime_xss`（:309, 呼び出し:966）が**一度も呼ばれない**。
- 実データ根拠：対象5ルート全てで `reflection_observed=false` / `xss_evidence=""` / `probe_sent=None`、`attempt_traces.history` は `xss:start → process_single_url:return(findings=0)` のみでDOM段階が存在しない。
- 補足：Juice Shop の看板XSSはサーバ応答本文に現れず画面側（クライアント）で組み立つDOM型のため、現在の「応答本文への反射（`precheck_obs.diff == "reflected"`, `smart_xss.py:910-955`）」だけでは原理的に検出不能。ブラウザ実行確認が唯一の経路である。

### 詰まり②：検証用ブラウザ（chromium）が未導入で起動失敗
- 実起動テスト（`.venv/bin/python` + playwright）で確認：
  `BrowserType.launch: Executable doesn't exist at .../chrome-headless-shell`（`playwright install` 相当が未実施）。
- `src/tools/browser/playwright_validator.py:25-32` の可用性判定 `_check_availability()` は **Pythonモジュールの import 可否だけ**を見ており、ブラウザ実体の有無を確認しない。そのため `is_available=True` を返すが、実起動時に失敗し例外は握られて `False` 返却＝**静かに素通り**する。

### 詰まり③【デグレ】：ブラウザ検証がプロキシ（Caido）を経由していない
- ブラウザ起動系の全呼び出しに `proxy=` 指定が無い：`playwright_validator.py:62-71/145-150/237-238/284-285/329-330/406-409`、`smart_xss.py:387-388`、`browser_pool.py:106`。`_browser_args`（`playwright_validator.py:18-23`）にもプロキシ設定は無い。
- 一方、HTTP攻撃側はプロキシを経由している：`smart_xss.py:159-160` が `src.core.infra.proxy_manager.get_proxy_manager()` を使用。プロキシURLの正本は `src/core/config/settings.py:741` `get_proxy_url()`（優先度: `scan.proxy` > 明示Caido URL > None）。
- 結論：ブラウザ検証だけがプロキシを迂回して直結している。ユーザー報告「chromiumは必ずプロキシ経由のはず」と、コード上「プロキシ未指定」という事実は整合し、デグレとして扱う。
- 参考（関連 lessons, 2026-08 CRITICAL）：Caido がスタブ（識別だけ通し転送しない）だと全攻撃が握り潰される。今回は現時点で Caido(8080) が Juice Shop(3000) を実転送していることを確認済み（`curl -x 127.0.0.1:8080 → HTTP 200`）。プロキシ経由化にあたっては転送実体の前提を崩さないこと。

## 完了契約（この計画で固定する対象・完了条件・必須テスト・NOT in scope）

### 対象（In scope）
1. **①種類分けの是正**：DVWA専用目印頼みをやめ、実際の作り（構造・挙動）でDOM候補を見分ける。`generic`/`reflected` でも、サーバ応答本文への反射が観測されない反射向き引数を持つ相手に対して、ブラウザによるDOM実行検証へ到達できるようにする。**製品固有の焼き込み（ホスト名・パス直書き等）で分岐しないこと（カーブフィッティング禁止）。**
2. **②ブラウザ導入と可用性判定の是正**：検証用 chromium を当該 venv に導入する。`_check_availability()` を「モジュール import 可否」だけでなく「ブラウザ実体の起動可否」を含めて判定し、未導入時は静かに素通りせず明示ログ（可視化）する。
3. **③プロキシ経由の回復**：ブラウザ起動（`chromium.launch`/`new_context`）が `settings.get_proxy_url()`（＝HTTP側と同じ正本）を読み、`proxy={"server": <url>}` を渡して Caido 経由で通信するようにする。プロキシ未設定時は従来どおり直結（後方互換）。

### 完了条件（Fixed completion criteria）
- C1: ①の是正により、Juice Shop の看板XSS対象（例 `/#/search?q=`）でブラウザDOM実行検証が**実際に起動・到達する**ことを実データ（`attempt_traces` にDOM段階が現れる）で確認する。
- C2: ②の導入により、当該 venv で chromium が起動でき、未導入時は明示ログが出ることを確認する（実起動テスト＋ユニット）。
- C3: ③の是正により、ブラウザ起動に `settings.get_proxy_url()` 由来のプロキシが渡ること（設定時は付与・未設定時は付与しない）をユニットで確認する。
- C4: **本物のXSSを実確定**：Juice Shop に対し、ブラウザ実行証拠（実際のスクリプト発火/DOM危険挿入）を伴うXSSを**1件以上 confirmed** にし、正本 session/report を残す。`verify_report_session_consistency.py`（または shigoku-ops）が `consistent` / `rerun_required=false` を返すこと。
- C5: **確定バー無改変**：`payout_grade.py`/`sealed_reproduction_checker.py`/`poc_judge.md`/`finding_validator.py`/`task_queue.py(PCR-P1)` が個別に `git diff --quiet HEAD` = exit0。
- C6: **製品非依存**：`check_vdp_product_independence.py` verdict=pass・token0。①の是正が特定製品への焼き込みでないことを担保する。
- C7: 新規/変更に対するユニットテストが全て pass。既存テストに本変更由来の新規失敗が無い（HEAD既存の失敗は git stash で切り分け明示）。

### 必須テスト（Required tests）
- T1（①）：`_detect_xss_variant` 相当の是正後分類器が、DVWA目印の無い反射向きURL（例 `/rest/products/search?q=`、`/#/search?q=`）に対してDOM実行検証へ回す判定を返す（挙動ベース・製品名非依存）。
- T2（②）：ブラウザ実体が無い状態で可用性判定が `False`（または明示的 unavailable）を返し、明示ログが出る。実体がある状態では起動できる。
- T3（③）：`settings.get_proxy_url()` が値を返す時、`chromium.launch`/`new_context` に `proxy={"server": ...}` が渡る（mock で引数検証）。未設定時は `proxy` 引数を渡さない。
- T4（e2e・実データ）：Caido 経由で Juice Shop に対し実行し、ブラウザ実行証拠つきXSSが confirmed になった session/report を1件残し、整合チェッカが consistent を返す（CLAUDE.md §10 検出/報告パイプライン＝ユニット＋実成果物の双方で確認）。

### NOT in scope（明示的に対象外＝別タスク追跡）
- Stored XSS / POSTボディXSS の網羅的対応（別 variant・別経路）。
- オープンリダイレクト等、XSS以外の未実装検出（先の調査で挙げた別改良）。
- Ver.2（応答観察→変形再優先付けの自律型）や scn_07/08/10/12 の網羅。
- 確定バー自体の設計変更・閾値変更（恒久的に対象外）。

## 進め方（Phases）

SQLiと同じ運用（DeepSeek実装／Claudeが実データで独立検証／コミットは検証後／push はユーザー）。

1. **フェーズ0（設計確定・独立検証）**：①の是正方針（挙動ベースのDOM候補判定）を、`smart_xss.py` の所有者概念・呼び出し元・関連spec（`docs/shigoku/specs`）と突き合わせて確定する（lessons 2026-08：一ファイルの挙動を仕様と断定しない）。カーブフィッティングにならない判定設計であることを合意。
2. **STEP 1（②環境）**：venv に chromium を導入。可用性判定を実体確認込みに是正＋明示ログ。実起動テストで確認。
3. **STEP 2（③プロキシ）**：ブラウザ起動系を `settings.get_proxy_url()` 経由に是正（設定時付与・未設定時直結）。ユニットで引数検証。
4. **STEP 3（①到達性）**：DOM候補判定を挙動ベースへ是正し、`generic`/`reflected` からブラウザDOM実行検証へ到達する経路を通す。ユニット＋`attempt_traces` にDOM段階が出ることを確認。
5. **STEP 4（e2e実確定）**：Caido 経由で Juice Shop に対し実行、ブラウザ実行証拠つきXSSを confirmed にし、整合チェッカ consistent を確認。バー5点 diff0・製品非依存 pass を再確認。
6. **完了処理**：work_report / work_log 作成、registry / ledger 更新、`sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` 0エラー、コミット（push はユーザー）。

## 制約・ガードレール（不変）

- カーブフィッティング禁止・確定基準は下げない/変えない（トップハンター相当以上が理想）。①の是正は挙動ベースで製品非依存（`check_vdp_product_independence` pass・token0）。
- 確定バー5点（`payout_grade`/`sealed_reproduction_checker`/`poc_judge`/`finding_validator`/`task_queue` PCR-P1）は個別 diff0。
- XSSの確定は「本物のブラウザで実際に実行された証拠」を要求する現行の厳しさを維持する（緩めない）。到達性・環境・経路の是正のみを行う。
- GET中心の境界を尊重。機微ユーザーデータの取得はしない（DOM実行の証明は非機微なマーカー発火で行う）。
- 秘密情報の生値を成果物へ残さない。プロキシ経由化で通信内容がCaidoに渡るが、秘密の生値をログ/セッション/レポートへ書かない。
- 「確定するまで回す/当たりだけ拾う」は proxy gaming として不採用。信頼性は全数正直報告で測る。

## リスク / 未確定（hypothesis を明示）

- ①の「挙動ベース判定」の具体設計はフェーズ0で確定する（現時点では方針。所有モジュール・spec突合前の仮説として扱う）。
- ③プロキシ経由化後、Caido が実転送している前提が崩れると全ブラウザ検証が握り潰される（lessons 2026-08）。実行前に転送実体（path依存の実応答）を確認する。
- ②の chromium 導入はネットワーク取得を伴う。環境側の導入可否・容量に依存。

## 完了判定（§19）

- 完了契約 C1〜C7 が全PASSかつ `in_scope_blocker` 0件なら、追跡可能な `deferred_followup`（Stored/POST XSS、他種検出、Ver.2）が残っても本タスクを `done` にする。
- 各阻害事項は上記完了条件のいずれに違反するかを対応付ける。対応付けられないものは阻害事項にしない。
