---
task_id: SGK-2026-0460
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-22_sgk-2026-0459_active-save-sink-discovery.md
- docs/shigoku/reports/2026-08-26_sgk-2026-0459_active-save-sink-discovery_work_report.md
- docs/shigoku/worklogs/2026-08-28_sgk-2026-0460_caido-origin-isolation_work_log.md
- docs/shigoku/reports/2026-08-28_sgk-2026-0460_caido-origin-isolation_work_report.md
created_at: '2026-08-28'
updated_at: '2026-09-01'
tags:
- shigoku
- vdp
- infrastructure
- state-isolation
- workspace
- recon
---

# SGK-2026-0460 計画書 — プロジェクト横断の永続状態汚染の隔離

> **完了（2026-09-01）**: 走行単位の状態隔離（Caido オリジン隔離・dispatch時 _context マージ）を実装・検証済み。2026-09-01 の実走行（session_20260901_005406）でも全 finding が対象 `127.0.0.1:5008` のみ（他ターゲット混入0）を確認。当初 deferred だった formal confirmed=1 は SGK-2026-0461/0462/0463 で達成。

## 目的（Objective）

単一ターゲットの走行が、**過去の別ターゲットのURL・タスクを引き込まずに完走・判定できる**ようにする。SGK-2026-0459 の実走行で、保存型XSSの確定能力そのものは隔離ハーネスで実証できたが、**フル製品パイプラインの単一走行**は毎回、過去の別ターゲット（Juice Shop `localhost:3000`・旧ポート `5001` 等）のURL/タスクが現在走行へ注入され、走行が肥大・中断して confirmed=1 判定に到達できなかった。本タスクは汚染源を引用特定し、走行単位の状態隔離を実装する。

## 背景・根拠（SGK-2026-0459 実走行・2026-08-27〜28・引用特定）

- 新ポート（`127.0.0.1:5002`/`5006`）＝新規プロジェクトで走行しても、セッションの `task_queue`/`completed_tasks`/`task_execution_records` に `localhost:3000` が数万回出現（実際に別ターゲット宛タスクを生成・実行）。
- `SHIGOKU_NEO4J_URI` を未到達に向け **Neo4j 知識グラフを無効化（`driver is None` 確認済み）しても汚染は解消しなかった** → KG は源の一つに過ぎない。
- 走行中に `shared_workspace` が `localhost:3000/rest/products/{id}/reviews` 等を pool へ登録、XSS backfill が別ターゲットURLを seed に選択（`master_conductor.py` の backfill 経路）。`data/vuln_roi_db.json` は `localhost:3000` を含まない（源ではない）。
- 汚染により走行が肥大化し、`127.0.0.1:5001/comment?...&EIO=1&transport=1`（死んだ旧ポート＋socket.io系パラメータ）へ 502 を連発するなど、実務上フル走行が完走しない。

## フェーズ0（診断・実装前の必須ゲート）

1. 汚染源の引用特定: 共有ワークスペース（`src/core/workspace/shared_workspace.py`・`workspace_root="./workspace"`）、スプール（session の `spool_path`）、`run_ledger`/`adjacency_list`、backfill seed の供給元（`master_conductor.py` の `_refine_backfill_seed_targets` 等）が、どの永続ファイル/ストアから過去ターゲットURLを読み込むかを引用で確定する。lessons: 一ファイルの挙動を仕様と断定しない。
2. 単一ターゲット走行での注入経路を実データで裏取り（どのステップで `localhost:3000` が現走行へ入るか）。
3. 隔離方式の設計（走行単位のクリーンなワークスペース/状態、または対象オリジンでのフィルタリング）を、既存の複数ターゲット運用を壊さない形で提案。
→ フェーズ0を提出・レビュー承認後に実装。

## フェーズ0 結果（2026-08-28・Claude・引用付きで確定）

### 実データの裏取り（どこで混入するか）
- `resume_source="fresh"` の `127.0.0.1:5001` 走行のセッション（`workspace/projects/127.0.0.1:5001/sessions/session_20260827_083811.json`）に `localhost:3000` が **7561回** 出現。`completed_tasks`/`task_execution_records` に集中し、実際に Juice Shop 宛（`/rest/products/24/reviews`, `/api/Challenges`, `/socket.io/` 等）の CORS/API/XSS スキャンタスクが生成・実行されていた。
- 注入は **recon 第1ステップ**で発生。`completed_tasks[1]`（`action=parallel_recon`, `params.target=http://127.0.0.1:5001`）の結果時点で既に `localhost:3000` を185件保持。
- recon の統合ファイル `.../scans/raw/20260827_recon_all_urls_for_tagging.json` のホスト内訳は **`localhost:3000`=217件 / `127.0.0.1:5001`=69件**。→ recon が別オリジンのURLを混ぜて出力していた。
- `discovered_assets` は空（len=0）、`data/vuln_roi_db.json` は `localhost:3000` を含まない、Neo4j 無効化でも解消せず → backfill/KG/ROI-DB は本件の能動的注入源ではない。

### 確定した注入経路（コード引用）
Caido プロキシ履歴の取り込みが唯一の実効注入源。Caido の履歴は**全ターゲット横断で蓄積**され、ループバック一致がポートを無視するため別ポート/別ローカル製品の履歴が現走行へ流入する。
1. `src/recon/pipeline.py:2419` — `all_entries = katana_entries + httpx_entries + caido_entries + playwright_entries`。`localhost:3000` の Juice Shop URL は katana/httpx/playwright（現ターゲットのみクロール）や gau（公開アーカイブに localhost は無い）では出ない。**`caido_entries` 由来**。
2. `src/recon/pipeline.py:2124-2134` — Caido 呼び出し前に `target_domain` を `parsed_target.hostname`（=`127.0.0.1`）へ縮約し、**ポートを落として** `fetch_recent_requests(domain=target_domain, ...)` を呼ぶ。
3. `src/core/agents/specialized/caido_sitemap_agent.py:335` — `fetch_recent_requests` のフィルタ `if not self._host_matches_domain(host, normalized_domain): continue`。
4. `caido_sitemap_agent.py:88` — `_host_matches_domain`: **`_is_loopback_host(host) and _is_loopback_host(domain)` なら無条件 True**。かつ `_normalize_host_token`（:54-57）が比較前にポートを除去。
   → 結果、`127.0.0.1:5001` 走行時に `fetch_recent_requests(domain="127.0.0.1")` が **ループバックの全ポート履歴**（`localhost:3000`・`127.0.0.1:5002` 等）を通す。`:342-348` で元ポート付きURLに再構成して返す。
   → これが `all_urls_for_tagging`（:2419）→ `tagged_urls` → 下流スキャンタスクへ伝播し、5001走行が Juice Shop 宛タスクで肥大・中断していた。
   これはプラン背景の全事象（KG無効でも解消しない・5001↔5002 混入・ROI-DB無関係）と整合する。

### 設計意図と真のバグの切り分け（lessons: 一ファイルを仕様と断定しない）
- ループバック等価（`localhost`≡`127.0.0.1`≡`::1`）は既存テスト（`tests/core/agents/test_caido_auth_resolver.py:198-202`）が意図的に要求する正当な仕様（同一ローカルサービスを別名で指す救済）。**削ってはいけない。**
- 真のバグは、その等価判定が **ポート差まで畳み込む**こと（`localhost:3000` と `127.0.0.1:5001` を同一視）。ホスト等価は残しつつ **ポート一致を要求**すれば混入だけを排除できる。

## 修正設計（フェーズ0結論・最小・後方互換・製品非依存）
- **原則**: オリジン = (ループバック正規化ホスト, ポート)。ループバック同士でも**ポートが異なれば不一致**。フィルタにポート指定が無い場合（実ドメイン `example.com` 等）は**全ポート一致**を維持（既存挙動不変）。
- 変更点（DeepSeek 実装・Claude 検証）:
  1. `caido_sitemap_agent.py`: `_host_matches_domain` は**ホスト等価のまま不変**（:198-202 の単体テストを緑維持）。`fetch_recent_requests` にポート照合を追加 — フィルタから明示ポートを抽出（新ヘルパ `_normalize_domain_port` 等）、ポートがあれば `node_port == filter_port` を必須に。ポート未指定なら従来通り全ポート許容。
  2. `src/recon/pipeline.py:2124-2134`: Caido 呼び出しに**ポート付きオリジン**を渡す（`self.target` の scheme://host:port を使用。hostname 縮約をやめる）。
- **影響しないもの**: `_normalize_domain_filter` の戻り（host-only）は不変で :181 テスト緑維持。既存 :269-271 テスト（filter=8888 / fixture=8888）は同一ポートにつき緑維持。実ドメイン走行（ポート未指定）は全ポート許容で不変。
- **新規テスト**（DeepSeek 追加）: 混在ポート fixture（現ターゲット `127.0.0.1:5001` ＋ `localhost:3000`・`127.0.0.1:5002` の履歴）で **5001 のみ返る**こと／ポート未指定フィルタは全件返ること／`localhost:5001`（別名・同ポート）は通ること。

## 追加実装（実 Caido フル走行で判明・C5到達のための _context マージ修正）

2026-08-28 の実走行（`127.0.0.1:5007`）で **C1（混入0）は実地達成**したが、**C5（保存型 confirmed=1）は別要因で未達**と確定（詳細は work_report「実 Caido フル走行・独立検証記録」）。

- 真因（Caido 混入とは独立）: dispatch 時に `src/core/engine/master_conductor.py:7717`
  `task.params["_context"] = self.accumulated_context.to_dict()` が **_context を丸ごと置換**し、
  build 時（`master_conductor.py:14742-14744`）注入の `save_endpoints`/`forms_by_url`/`url_evidence_by_url` を破棄。
  → injection へ save_endpoints 不達 → `candidate_params` 空 → `smart_xss.py:1188` の param ループが空回り →
  保存型確定 `_attempt_stored_revisit_validation`（smart_xss.py:771）が未呼び出し。
- 修正（最小・製品非依存・確定バー無改変・DeepSeek 実装 / Claude 検証）:
  `7717` を「置換」から「マージ」へ（`{**existing, **accumulated}` 相当。accumulated 優先、build 時のみのキー
  `save_endpoints`/`forms_by_url`/`url_evidence_by_url` を保持）。
- 必須テスト: build 時に `_context["save_endpoints"]` を持つタスクが dispatch 後も保持することの単体テスト＋
  実練習台フル走行での `variant="stored"` confirmed=1。
- 位置づけ: 本修正は完了契約 C5（＝0459 C1c）到達のための実装であり、固定契約の拡張ではない。

## 完了契約（Fixed completion criteria・暫定）

- C1: 単一ターゲット（ローカル練習台）の走行で、セッションの task/finding に**対象オリジン以外のURLが混入しない**（別ターゲットURLの注入 0）。
- C2: 隔離は既存の複数ターゲット運用・共有ワークスペースの正当な用途を壊さない（オプトイン/走行単位スコープ等）。既存テスト緑・結果不変。
- C3: 確定バー無改変（5ファイル）。SGK-2026-0459 の検出・確定ロジックを判定として壊さない。
- C4: 新規/変更ユニット全 pass。製品非依存（token0）維持。
- C5: 隔離後のフル走行で、修正版練習台の保存型XSSが `variant="stored"` confirmed=1・整合 consistent（SGK-2026-0459 C1c をここで達成可能にする）。

## NOT in scope

- SGK-2026-0459 の能動発見・安全境界・結線・確定側ロジック（実証済み・判定として不変）。確定バーの変更。
- 知識グラフ/共有ワークスペースの機能そのものの再設計（隔離の範囲に限定）。

## ガードレール

- カーブフィッティング禁止・確定基準を下げない・製品非依存維持・能力の過小化をしない。
- 共有状態に触れるため、破壊的操作前に対象を確認し、既存プロジェクトのデータを不用意に消さない。
- Caido = 127.0.0.1:8081（8080 は SearXNG）。commit は検証後、push はユーザー。
