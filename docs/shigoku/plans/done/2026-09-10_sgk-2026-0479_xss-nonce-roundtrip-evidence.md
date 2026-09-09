---
task_id: SGK-2026-0479
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/reports/2026-09-10_sgk-2026-0479_xss-nonce-roundtrip-evidence_work_report.md
- docs/shigoku/worklogs/2026-09-10_sgk-2026-0479_xss-nonce-roundtrip-evidence_work_log.md
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0477_xss-browser-execution-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- xss
- dom-xss
- evidence-quality
created_at: '2026-09-10'
updated_at: '2026-09-10'
---

# SGK-2026-0479 計画 — XSS 実行証拠を「合言葉往復」で独立検証可能にする

## 目的（何を・なぜ）

反射型/DOM型XSS は SGK-2026-0477 で ◎（機械フロア＋実対象再現は本物）。だが本物の
AI 審査（poc_judge・実LLM）を通したところ、DOM XSS finding は 3 回中 2 回で
`payout_grade=False`（非承認）になった。理由は「証拠が弱い」ではなく **「提示された
response_body / poc_response が実レスポンスや実行時の生ログではなく、スキャナ自身が
書いた観測結果の要約（`DOM runtime execution observed` / `dialog=alert message=1`）で
あり、自己申告に見える」** という指摘（実測・poc_judge の reason）。バーは下げず、
**証拠の見せ方を本物の強さへ底上げ**して AI 審査の通りを安定させる。

## 事実（実測・実コードで確定・2026-09-10）

- 実 poc_judge x3（実エンジン検出 finding を投入）:
  - コマンドインジェクション（実 DVWA）= 2 回○/1 回×（× 理由は「教育用ターゲットだから
    賞金級と認めない」＝ターゲット正当性の判断・証拠 uid= 自体は本物と認識）。
  - DOM XSS（実 Juice Shop）= 1 回○/2 回×（× 理由は上記「自己申告の要約に見える」）。
- **生 DOM は当てにならない**（実測）: 発火後に `page.content()` を取得しても、注入文字列
  `onerror=alert(1)` はレンダリング後 DOM に残らない（ブラウザが解釈・実行後に同形で
  残らない）。→ 「生 HTML を渡す」案は不採用。
- **合言葉往復は成立する**（実測・実 Juice Shop）: `<img src=x onerror=alert('SGK<nonce>')>`
  を注入すると、ブラウザの dialog message が **注入した nonce と完全一致**して返る
  （攻撃者が選んだランダム値が実行結果にそのまま出る＝テンプレ捏造では作れない実行証拠）。
- **両ブラウザ経路とも dialog message を既に捕捉済み**:
  - `src/core/detection/browser_pool.py` の `XSSVerificationResult.evidence["dialog_message"]`
    → `smart_xss._record_browser_verification_result` が `browser_execution["dialog_message"]` へ格納。
  - `src/tools/browser/playwright_validator.py` の `validate_xss` が `_last_observation_logs` に
    `{type:dialog, message:...}` を格納（`_validate_dom_runtime_xss` フォールバック経路）。
  - → **インフラ改変は不要**。合言葉の埋め込みと、往復の検証・提示を smart_xss 側で行うだけ。

## 対象（このタスクで触るファイル）

- **`src/core/agents/swarm/injection/smart_xss.py`（非凍結）**:
  1. **合言葉注入**: DOM/反射の検証ペイロードを、実行のたびに生成するランダム nonce
     （例 `SGK` + 乱数）入りにする（`alert(1)` → `alert('<nonce>')`）。`<img onerror>` /
     `<svg onload>` / `<script>` の各ペイロードに適用。nonce は run/param 単位で一意。
  2. **往復検証**: 発火後、観測された dialog message（browser_pool 経路＝
     `browser_execution["dialog_message"]`、Playwright フォールバック経路＝
     `_last_observation_logs` の dialog エントリ）が nonce と一致するかを検査し、
     `browser_execution` に `nonce` / `observed_dialog_message` / `nonce_match`(bool) を記録する。
  3. **証拠の提示強化**: `_build_browser_execution_poc_response` に「注入 nonce」「観測
     dialog message」「一致」の往復行を含める。`execute()` で browser 実行観測時の
     `evidence.response_body` を、要約文ではなく **往復証拠（nonce↔observed message）を
     明示した生の記録**にする。`_build_xss_impact` / `_build_xss_reproduction_steps` にも
     往復の事実を反映（捏造なし・実測の整理のみ）。

## 確定バー・凍結（本タスクでは無改変）

- 凍結5ファイル `payout_grade.py` / `sealed_reproduction_checker.py` / `poc_judge.md` /
  `task_queue.py` / `finding_validator.py` は無改変（`git diff --quiet HEAD` exit 0）。
- `payout_grade` の xss 分岐は `browser_execution.dialog_observed` で従来どおり発火（nonce は
  発火条件に影響しない）。再現チェッカーは同じ nonce 入り test_url を再ナビゲートして再発火
  するだけ（既存 DOM 再実行経路のまま・改変不要）。

## 完了条件（完了契約）

1. エンジンが DOM/反射 XSS を実対象で自力検出したとき、`browser_execution` に
   `nonce` / `observed_dialog_message` / `nonce_match=True` が入り、`payout_grade=True /
   reflected_payload` を維持する（発火条件は不変）。
2. `evidence.response_body` と `additional_info.poc_response` に、nonce↔observed message の
   往復（一致）が生の記録として含まれる（自己申告の要約だけにしない）。
3. **実対象 E2E（Juice Shop DOM XSS）**: 実エンジン検出→往復証拠付き finding→**実 poc_judge**
   ＋実再現で `CONFIRMED` に到達する回が安定して得られる（強化前は 1/3 だった通過率の改善を
   実測で示す。バーは下げない）。dialog 非観測は従来どおり非確定（fail-closed）。
4. 凍結5ファイルは `git diff --quiet HEAD` exit 0。製品非依存 token 0（denylist）。テスト
   fixture は汎用ペイロード・target.example 等のみ。
5. **非回帰**: 既存の本文反映 reflected XSS・保存型XSS の ◎、既存 injection/validation スイートが緑。

## 必須テスト（新規・製品非依存 fixture のみ）

- smart_xss 単体: (a) nonce 入りペイロードを生成し、観測 message==nonce のとき
  `nonce_match=True`＋poc_response/response_body に往復が入る、(b) 観測 message≠nonce の
  ときは `nonce_match=False`（捏造しない・強い主張をしない）、(c) dialog 非観測では
  browser_execution を付けない（fail-closed・非回帰）、(d) 既存の本文反映経路が不変。
- 統合: `validate_finding` が往復証拠付き browser-fired XSS＋AI賞金級（スタブ）＋再現matched で
  CONFIRMED（配線の非回帰確認）。
- 変更後 `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py` が 0 エラー。

## NOT in scope

- 確定バーの敷居低下・見かけだけ通す curve-fitting（教育用ターゲットであることを隠す等の
  judge を欺く小細工は禁止）。
- 凍結5ファイルの改変。XSS 以外の種別。コマンドインジェクション側の judge 通過率
  （× 理由はターゲット正当性であり別問題・本タスク対象外）。
- 生 DOM(page.content) の付与（実測で有用な証拠が残らないため不採用）。

## リスク

- nonce をペイロードに入れることで既存の payout_grade 発火・再現 DOM 再実行に影響しないこと
  （nonce は alert 引数だけで発火条件に無関係）を、完了条件1＋非回帰テストで担保。
- AI 審査は非決定的なため「必ず通る」ではなく「通過率が上がる」ことを実測で示す（誇張しない）。

## 実装・検証の分担

- 実装は DeepSeek/opencode に**テキストで**指示（ドキュメント化しない）。opencode は fixer
  サブエージェントの makora フォールバック対策として repo opencode.json に一時 agent→deepseek
  上書きを入れて起動し完了後復元（[[opencode-fixer-subagent-makora-fallback]]）。
- 完了報告は額面通り信用せず、Claude が独立検証（テスト実出力・diff・凍結5無改変・実 Juice Shop
  DOM XSS の実 poc_judge 通過率・fail-closed 否定側）。
