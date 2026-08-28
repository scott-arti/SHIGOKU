---
task_id: SGK-2026-0460
doc_type: work_report
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/2026-08-28_sgk-2026-0460_cross-target-state-isolation.md
- docs/shigoku/worklogs/2026-08-28_sgk-2026-0460_caido-origin-isolation_work_log.md
title: Caido履歴取り込みのオリジン（host:port）隔離 実装 作業完了報告
created_at: '2026-08-28'
updated_at: '2026-08-28'
tags:
- shigoku
- vdp
- state-isolation
- recon
- caido
- origin
target: src/core/agents/specialized/caido_sitemap_agent.py,src/recon/pipeline.py,tests/core/agents/test_caido_auth_resolver.py
---

# SGK-2026-0460 作業完了報告 — Caido 履歴取り込みのオリジン（host:port）隔離

## What（何をしたか）

計画書フェーズ0で確定した真因（`127.0.0.1:5001` 走行時、pipeline が Caido フィルタからポートを落とし、`_host_matches_domain` の「ループバック同士なら無条件 True」＋ポート除去により `localhost:3000` 等の全ポート履歴が流入）に対し、最小修正を実装した。

- **`src/core/agents/specialized/caido_sitemap_agent.py`**
  - 追加: `_normalize_domain_port(domain) -> Optional[int]` — フィルタ文字列から明示ポートを抽出（URL/netloc/IPv6/`*.` 対応）。未指定・不正は `None`。
  - 追加: `fetch_recent_requests` の host 照合直後にポート照合 — `filter_port` が指定されている場合、`node.get("port")` が一致しない履歴は除外（ポート欠落・不正も不一致＝fail-closed）。ポート未指定なら従来どおり全ポート許容。
  - 不変: `_host_matches_domain`（ループバック等価 `localhost`≡`127.0.0.1`≡`::1` 維持）、`_normalize_host_token`、`_normalize_domain_filter`。
- **`src/recon/pipeline.py`**（Caido 統合ブロック）
  - hostname 縮約（ポート落とし）を廃止し、`self.target` から **`scheme://host[:port]` オリジン**を組み立てて `fetch_recent_requests` に渡す（IPv6 は `[::1]:port`）。

ハードコードなし（製品・URL・セレクタの token 0）。製品・ポートは汎用のオリジン/ポート照合のみ。

## Why（なぜ）

Caido の履歴は全ターゲット横断で蓄積される。ループバック等価は正当な仕様（同一ローカルサービスを別名で指す救済）だが、ポート差まで畳み込むため別ポートの別ローカル製品履歴が現走行へ流入していた。ホスト等価は残しつつ**ポート一致を要求**することで混入のみを排除する（計画書「修正設計」のとおり）。

## Validation（実コマンド出力・そのまま）

- `$ .venv/bin/pytest tests/core/agents/test_caido_auth_resolver.py -q`
  - 出力: `43 passed in 0.96s`（既存 :181/:198-202/:269-271 含め全緑。新規: `test_normalize_domain_port` 14 ケース・`test_fetch_recent_requests_isolates_target_port`・`test_fetch_recent_requests_loopback_alias_same_port_passes`・`test_fetch_recent_requests_without_port_accepts_all_ports`）
- `$ git diff --quiet HEAD -- src/core/agents/swarm/injection/payout_grade.py src/prompts/roles/poc_judge.md src/core/engine/task_queue.py src/core/validation/finding_validator.py src/core/validation/sealed_reproduction_checker.py && echo BAR_UNCHANGED`
  - 出力: `BAR_UNCHANGED`（確定バー5ファイル無改変）
- `$ .venv/bin/python scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --denylist config/diagnostics/sealed_product_denylist.txt`
  - 出力: `verdict: pass` / `total_token_hits: 0`（checks 6/6 ok・changed_files 10・closure 31）
- 広域: `tests/recon/` = **129 passed, 3 failed**。失敗3件（`test_parallel_base::test_semaphore_custom` / `test_run` / `test_step1_file_persistence`）は **pristine HEAD worktree（`git worktree add` にて本変更なし状態）でも同一の3件失敗**を確認＝事前既存（Caido 未起動による Proxy 必須ゲート・bbot buckets 検証）。本変更起因ではない。
- **追修正（テストのトークン中立化）**: `--changed-files` 付きの製品非依存チェックで追加テスト内の2トークン（docstring の `localhost:3000`・パス `/juice`）が FAIL 検出されたため、テスト2箇所のみ語句を差し替え（docstring 中立表現化・パス `/other-a` 化。隔離セマンティクス・アサート・本体ロジック不変）。追修正後: `check_vdp_product_independence.py --changed-files`（SGK-2026-0460 コード3ファイル）→ **verdict: pass / total_token_hits: 0**（changed_files_input=3・files_scanned=3）／ pytest **43 passed in 0.97s** 維持／ BAR_UNCHANGED 維持。

## 完了契約との対応（SGK-2026-0460 計画書）

- C3（確定バー5ファイル無改変）: PASS（BAR_UNCHANGED）。
- C4（新規/変更ユニット全 pass・製品非依存 token0）: PASS（43 passed・verdict pass / token_hits 0）。
- C2（既存テスト緑・結果不変）: 対象ユニット緑。ポート未指定ターゲット（実ドメイン）は全ポート許容で挙動不変。
- C1（単一走行への別オリジンURL混入 0）: 本実装は混入経路（Caido 取り込み）をオリジン単位で遮断。**実走行での確認は未実施**（下記 deferred）。
- C5（隔離後のフル走行 confirmed=1・整合 consistent）: 未実施（下記 deferred）。

## Risks / 未達（正直な開示）

- **実走行未実施**: ユニットとコード上の隔離は検証済みだが、実 Caido（127.0.0.1:8081）を使った単一走行での混入ゼロ・完走・判定は未確認。ユーザー（Claude）が実データで再検証する前提。
- **ページング事前チェックはホストのみ**: `fetch_recent_requests` の「最初のページに候補ホストが居るか」の事前チェック（および後方ページ追加ループ）は従来どおりホスト照合のみで、ポート照合は最終ループでのみ実施。ページ1に「ポート不一致のループバック履歴」だけがある場合、ページングが早期停止して古いページの正しいポート履歴を見逃す可能性がある（混入ではなく**取りこぼし**の方向）。実データで顕在化する場合のみ追加対応。
- ポート欠落ノード（`node.get("port")` が None）は、ポート指定フィルタ時は不一致扱いで除外（fail-closed）。

## deferred_tasks

```yaml
deferred_tasks:
  - description: 実 Caido（127.0.0.1:8081）での単一走行確認 — 現ターゲット（例 127.0.0.1:5001）の履歴のみ取り込まれ、localhost:3000 / 旧ポート等の別オリジン履歴が混入しないこと（C1）と、隔離後のフル走行で修正版練習台の保存型XSSが variant="stored" confirmed=1・整合 consistent に到達すること（C5）。ユーザー（Claude）が実データで再検証する前提で本ターンの範囲外。
    tracking_task_id: SGK-2026-0460
    tracking_doc: docs/shigoku/plans/2026-08-28_sgk-2026-0460_cross-target-state-isolation.md
  - description: fetch_recent_requests のページング事前チェック（ホスト照合のみ）をポート照合込みに拡張するか否か。現状は取りこぼし方向（混入ではない）のため実データで顕在化する場合のみ対応。
    tracking_task_id: SGK-2026-0460
    tracking_doc: docs/shigoku/plans/2026-08-28_sgk-2026-0460_cross-target-state-isolation.md
```

## Next step

1. 実データ再検証（ユーザー担当）: 上記検証コマンドの再実行＋実走行での C1/C5 確認。
2. C1/C5 確認後、SGK-2026-0460 の残フェーズ（共有ワークスペース/スプール等の他の永続ストア経路の隔離）へ。

## 参考ルール

rules/lessons.md（一ファイル断定回避・worktree 回帰比較）、rules/codingrules.md、rules/task-ledger.md、rules/shigoku-docs.md、rules/python-tests.md、CLAUDE.md §17/§19。

## 実 Caido フル走行・独立検証記録（2026-08-28・Claude）

実 Caido（127.0.0.1:8081・preflight 全通過）経由で、新規練習台 `http://127.0.0.1:5007`（保存型XSS・resume=fresh）に対しフルパイプラインを実走行（`python -m src --target http://127.0.0.1:5007 --mode vulntest --profile bbpt`、`SHIGOKU_RECON_ACTIVE_POST_ENABLED=true`）。ミッション正常完了、セッション `workspace/projects/127.0.0.1:5007/sessions/session_20260828_075102.json`。

### C1（別オリジンURL混入 0）: 達成（実地で証明）
- セッション全体を独立走査: `localhost:3000`=**0** / `:5002`=**0** / `:3000`=**0** / `juice`(ci)=**0**。
- 全 http(s) URL のホスト内訳=**`127.0.0.1:5007` のみ 715 件**（他オリジン 0）。
- recon 統合 `…/scans/raw/20260828_recon_all_urls_for_tagging.json` のホスト内訳=**`127.0.0.1:5007` のみ 18 件**（修正前の同種走行は `localhost:3000`=217/target=69 だった）。
- 保存sink も full pipeline で捕捉: `…/comment`（POST・fields=["comment"]・marker・revisit_urls 6件）。
- → Caido オリジン隔離は実パイプラインでも有効。**C1 PASS（実地）**。

### C5（隔離後フル走行 confirmed=1・variant=stored）: 未達 — 別要因を実データで確定
- セッションに `variant=stored` / `dialog_observed` / `stored_revisit_browser_execution` は不在。保存型XSSは確定に至らず。
- 真因（Caido 混入とは別・新規判明）: dispatch 時に `src/core/engine/master_conductor.py:7717` が
  `task.params["_context"] = self.accumulated_context.to_dict()` で **_context を丸ごと置換**し、
  build 時（`master_conductor.py:14742-14744`）に注入した `save_endpoints`（および `forms_by_url`/`url_evidence_by_url`）を**破棄**していた。
- 実データ裏取り: セッションの全 15 completed_tasks の `_context` は recon 要約の 6 キー
  （`discovered_endpoints/auth_tokens/discovered_params/tech_stack/waf_info/critical_findings`）**のみ**で、
  `save_endpoints` は 1 件も存在しない。
- 伝播: `save_endpoints` 不達 → injection manager `_match_save_endpoint` が None → `candidate_params`（smart_xss ログ `Candidate params prioritized: []`）が空 →
  `smart_xss.py:1188` の `for param_name in candidate_params:` ループが空回りし、保存型確定手順
  `_attempt_stored_revisit_validation`（smart_xss.py:771）が**一度も呼ばれない**。

### 追加実装（C5 到達のための最小修正・DeepSeek 実装 / Claude 検証）
- `master_conductor.py:7717` を「置換」から「マージ」へ: `task.params["_context"] = {**existing, **accumulated}` 相当。
  accumulated（新しい recon 要約）を優先しつつ、build 時のみ入る discovery 契約キー
  （`save_endpoints`/`forms_by_url`/`url_evidence_by_url`）を保持する。製品非依存・加算のみ・確定バー無改変。
- 必須テスト: build 時に `_context["save_endpoints"]` を入れたタスクが dispatch 後も save_endpoints を保持することの単体テスト＋実練習台でのフル走行 `variant="stored"` confirmed=1。
- これは 0460 の完了契約 C5（＝0459 C1c）到達のための実装であり、固定契約の拡張ではない。

### 追加実装 完了（2026-08-28・本ターン・実装/検証済み）

**実装（変更行: `src/core/engine/master_conductor.py` 18+/2-）**
- `master_conductor.py:7716-7717` の「置換」を「マージ」へ変更。マージロジックは private ヘルパー `_merge_accumulated_context(task)`（`_execute_single_task_full_flow` 直後に追加）へ抽出し、dispatch 側は `accumulated_context` 非空時のみ呼び出し（呼び出しガード・`{**existing, **accumulated}` の優先セマンティクスは計画書どおり）。`enrich_task`（context_designer.py）は `_context` を一切触らないことを確認済み（マージ後に破棄されない）。
- 新規テスト: `tests/core/engine/test_master_conductor_context_merge.py`（4件）
  - `test_dispatch_merge_preserves_build_time_keys_and_accumulated_wins`（build 時 `save_endpoints`/`forms_by_url`/`url_evidence_by_url` 保持＋overlap キーは accumulated 優先）
  - `test_dispatch_merge_sets_accumulated_when_context_absent` / `test_dispatch_merge_replaces_non_dict_context`
  - `test_full_flow_dispatch_merge_keeps_save_endpoints_reachable`（実 `_execute_single_task_full_flow` 経由の配線テスト: 下流スタブのみ・merge/enrich は実コード）

**検証（実コマンド出力・そのまま）**
- `$ .venv/bin/pytest tests/core/engine/test_master_conductor_context_merge.py -q` → **4 passed in 1.80s**
- 広域: `tests/core/engine/ tests/core/agents/swarm/injection/` = **1307 passed / 32 failed / 1 error**。失敗32+エラー1は **pristine（変更 stash）ベースラインと同一リスト**（`diff baseline current` = IDENTICAL_FAILURES・33行一致）＝事前既存（`reserved_task_ids` kwarg 不一致・bugbounty bundle preflight・react_redundancy 等）で本変更起因なし。
- `$ .venv/bin/python scripts/check_vdp_product_independence.py --manifest config/diagnostics/product_independence_manifest_v1.json --denylist config/diagnostics/sealed_product_denylist.txt --changed-files <master_conductor.py, 新テスト>`
  - 出力: **verdict: pass / reason_codes: [] / total_token_hits: 0**（checks 6/6 ok・changed_files_input=2・files_scanned=2・closure 31・model_templates_scanned 21）
- `$ git diff --quiet HEAD -- src/core/agents/swarm/injection/payout_grade.py src/prompts/roles/poc_judge.md src/core/engine/task_queue.py src/core/validation/finding_validator.py src/core/validation/sealed_reproduction_checker.py && echo BAR_UNCHANGED` → **BAR_UNCHANGED**（確定バー5ファイル無改変）

**備考（pass 主張の正確性）**: 本ターンの検証はユニット＋配線テスト＋製品非依存＋バー無改変まで。フル走行での `variant="stored"` confirmed=1・整合 consistent（C5）は**未実施**で、ユーザー（Claude）が実 Caido で独立再検証する前提（計画書・deferred どおり）。

## 実 Caido フル再走行（_context マージ修正後・2026-08-28・Claude 独立検証）

修正（`master_conductor.py:7717` 置換→マージ）投入後、同一練習台 `http://127.0.0.1:5007`（resume=fresh）へ実 Caido 経由でフル再走行。セッション `…/sessions/session_20260828_223724.json`、レポート `…/reports/haddix_report_20260828_223725.md`（consistency.status=consistent）。

### C1（混入0）: 再走行でも維持
- セッション全 URL のホスト内訳=**`127.0.0.1:5007` のみ**。`localhost:3000`/`:5002`/`juice` すべて 0。

### 保存sink→確定鎖: 実際に貫通・本物のブラウザ警告を観測
- 修正効果（実ログ）: `SmartXSSHunter` の `Candidate params prioritized` が前回の `[]` から **`[comment]`** に変化（save_endpoints が dispatch 後も _context に生存＝マージ修正が有効）。
- ブラウザ発火（`src.tools.browser.playwright_validator`）: `[Headless] Dialog detected! Type: alert, Message: 1` を複数回観測。
- 生成 finding（`completed_tasks[9].result.data.findings[0]`, id=1184e6540ea5）: `type=xss`・`severity=high`・`variant=stored`、
  `additional_info.browser_execution = {dialog_observed:true, executor:playwright, event:stored_revisit_browser_execution, variant:stored, payload:"<img src=x onerror=alert(1)>"}`、
  `stored_xss_revisit = {save: POST /comment(payload), revisit: GET /}`。reproduction_steps 3段（書込→再訪→alert発火）付き。
  → **保存型XSSを、書込→別ページ反射→実ブラウザ alert 発火まで、フル製品パイプラインで到達**（製品非依存・確定バー無改変）。

### formal「confirmed=1」: 未達（設計上の shadow 保留・確定バー外の reporting ポリシー）
- haddix ゲート: `status=fail`（`confirmed_below_minimum, candidate_above_maximum`）。`report_findings_summary.confirmed_count=0 / candidate_count=8`（authoritative）。
- 当該 XSS 3件は **candidate / reason=insufficient_validation**。同レポートの **Evidence Quality Shadow Verdict** は当該3件を `would_promote=confirmed`（根拠 `browser_evidence`）と判定するが、**「Enforcement is disabled in shadow mode … Switching from shadow to enforcement is a separate, gated change.」**＝ candidate→confirmed の昇格は**意図的に shadow（無効）**。
- この昇格ロジックは `src/reporting/haddix_evidence_quality.py`（**reporting 層**）にあり、**確定バー5ファイルには含まれない**。よって formal confirmed=1 に到達させるには shadow→enforce の**別ゲート判断**が必要。CLAUDE.md の既知安全保留の趣旨に従い、FAIL を PASS にするための昇格・shadow 解除は**本ターンでは実施しない**（ユーザー判断事項）。

### 完了契約との対応（更新）
- C1（別オリジン混入0）: **PASS（実走行2回で実証）**。
- C2/C3/C4: PASS（後方互換・確定バー無改変・token0・新規ユニット緑）。
- C5（フル走行 confirmed=1・consistent）: **部分達成**。検出・発火・証拠・PoC・consistent は達成。ただし formal confirmed 集計は 0（reporting 層の evidence-quality 昇格が意図的に shadow）。formal confirmed=1 は shadow→enforce の別ゲート判断が前提で、確定バー外の reporting ポリシー変更（未実施・ユーザー判断）。

### 残課題（deferred・追跡）
- reporting 層 evidence-quality の shadow→enforce 切替可否（browser_evidence を根拠とする candidate→confirmed 昇格の有効化）。確定バー外だが確定集計に直結するため、ポリシー判断としてユーザー承認が必要。
- candidate param に meta キー（`method`/`url_evidence`/`detection_mode`）が混入する軽微ノイズ（C2 の URL 汚染・別 finding 生成）。保存型の本命 finding（C1）には影響しないが、dispatch の base_params→candidate_params 抽出の精緻化余地。
