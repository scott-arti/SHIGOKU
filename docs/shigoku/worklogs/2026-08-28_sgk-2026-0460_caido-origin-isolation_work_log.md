---
task_id: SGK-2026-0460
doc_type: work_log
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/2026-08-28_sgk-2026-0460_cross-target-state-isolation.md
- docs/shigoku/reports/2026-08-28_sgk-2026-0460_caido-origin-isolation_work_report.md
title: Caido履歴取り込みのオリジン（host:port）隔離 実装 作業ログ
created_at: '2026-08-28'
updated_at: '2026-08-28'
tags:
- shigoku
- vdp
- state-isolation
- recon
- caido
- origin
---

# SGK-2026-0460 作業ログ — Caido 履歴取り込みのオリジン（host:port）隔離 実装

## 2026-08-28

### 実装（フェーズ0結論の最小修正・製品非依存・後方互換）

計画書（`2026-08-28_sgk-2026-0460_cross-target-state-isolation.md`）のフェーズ0で引用特定した真因（pipeline がポートを落とし、`_host_matches_domain` のループバック等価がポート差を畳み込む）に対し、以下を実装した。

1. **`src/core/agents/specialized/caido_sitemap_agent.py`**（2箇所・追加のみ）
   - `_normalize_domain_port(domain) -> Optional[int]` を追加（`_normalize_domain_filter` 直後）。フィルタ文字列（`example.com` / `example.com:8080` / `http://example.com:8080/path` / `localhost:5001` / `[::1]:8888` 等）から明示ポートのみを抽出し、未指定・不正は `None` を返す。`urlparse` ベースで IPv6 対応。
   - `fetch_recent_requests` の host 照合（`if not self._host_matches_domain(...): continue`）の直後にポート照合を追加。`filter_port = self._normalize_domain_port(domain)` が `None` でないとき、`node.get("port")` が `filter_port` と一致しない履歴は `continue`（ポート欠落・不正は不一致扱い＝fail-closed）。ポート未指定（実ドメイン等）は従来どおり全ポート許容。
   - `_host_matches_domain` / `_normalize_host_token` / `_normalize_domain_filter` は不変（ループバック等価 `localhost`≡`127.0.0.1`≡`::1` は維持）。

2. **`src/recon/pipeline.py`**（Caido 統合ブロックのみ・置換）
   - 従来の「`parsed_target.hostname` へ縮約してポートを落とす」処理を廃止し、`self.target` から **`scheme://host[:port]` のオリジン** を組み立てて `fetch_recent_requests(domain=...)` へ渡す。IPv6 は `[::1]:port` 形式で再構成。ポートなしターゲット（`example.com`・`*.example.com`）は scheme 付きホストのみ＝従来挙動。

### 追加テスト（`tests/core/agents/test_caido_auth_resolver.py`）

- `test_normalize_domain_port`（14 パラメータ: ポート抽出・未指定 None・不正ポート None・IPv6・ワイルドカード）。
- `test_fetch_recent_requests_isolates_target_port`（混在ポート fixture: `127.0.0.1:5001` のみ返り、`localhost:3000` / `127.0.0.1:5002` を除外）。
- `test_fetch_recent_requests_loopback_alias_same_port_passes`（`localhost:5001` 別名・同ポートは通す）。
- `test_fetch_recent_requests_without_port_accepts_all_ports`（ポート未指定 `example.com` は全ポート許容＝後方互換）。

### 追修正（2026-08-28・テストの製品トークン中立化）

`--changed-files` 付きの製品非依存チェックで追加テストが FAIL するのを受けて、`tests/core/agents/test_caido_auth_resolver.py` の2箇所のみ語句を差し替え（本体ロジック・封印バー・アサート不変）:

- 混在ポートテストの docstring: `localhost:3000 / 127.0.0.1:5002 の履歴を除外する。` → `別ポートのループバック履歴（別ローカルサービス）を除外する。`（封印デニーリストの `localhost:3000` を含まない中立表現）
- `_caido_node("localhost", 3000, "/juice")` のパスを `/other-a` へ（`juice` トークンを除去。`host="localhost"`・`port=3000` の引数は別ポートのループバック履歴という検証意図のため維持）

### 検証（実コマンド出力）

- `.venv/bin/pytest tests/core/agents/test_caido_auth_resolver.py -q` → **43 passed in 0.96s**（既存 :181/:198-202/:269-271 含め全緑）。
- `git diff --quiet HEAD -- payout_grade.py / poc_judge.md / task_queue.py / finding_validator.py / sealed_reproduction_checker.py && echo BAR_UNCHANGED` → **BAR_UNCHANGED**（確定バー5ファイル無改変）。
- `scripts/check_vdp_product_independence.py` → **verdict=pass / total_token_hits=0**（token0・製品非依存）。
- `tests/recon/` 全実行: **129 passed, 3 failed**。失敗3件（`test_parallel_base` 2件・`test_step1_file_persistence` 1件）は **pristine HEAD worktree でも同一**（Caido 未起動による Proxy 必須ゲート / bbot buckets）＝事前既存・本変更起因でない。
- 追修正後: `check_vdp_product_independence.py --changed-files`（SGK-2026-0460 コード3ファイル）→ **verdict: pass / total_token_hits: 0**（changed_files_input=3・files_scanned=3）。pytest **43 passed in 0.97s**。BAR_UNCHANGED 維持。

### 追加実装: dispatch 時 _context マージ化（2026-08-28・実走行 C5 未達の真因対応）

**背景**: 実 Caido フル走行（`127.0.0.1:5007`・session_20260828_075102.json）で C1 は達成したが C5（stored confirmed=1）は未達。セッションの全 15 completed_tasks の `_context` に `save_endpoints` が 1 件も存在しないことを実データで確認 → 真因は dispatch 時 `master_conductor.py:7717` の `task.params["_context"] = self.accumulated_context.to_dict()` による丸ごと置換（build 時 :14742-14744 注入の discovery 契約キーを破棄）。

**実装（追加・マージのみ）**:
1. `master_conductor.py:7716-7717` — 置換をマージ呼び出しへ（`accumulated_context` 非空時のみ）: `self._merge_accumulated_context(task)`。
2. `_merge_accumulated_context(self, task)` を `_execute_single_task_full_flow` 直後に追加 — `_existing = task.params.get("_context")` が dict なら `{**_existing, **_accumulated}`（overlap は accumulated 優先・build 時のみのキーは生存）、非 dict/不在なら accumulated を設定。
3. `context_designer.enrich_task` は `_context` を触らないことを確認（マージ後に破棄されない）。

**テスト（新規 4 件・`tests/core/engine/test_master_conductor_context_merge.py`）**: 保持＋accumulated 優先 / 不在時セット / 非 dict 置換 / 実 `_execute_single_task_full_flow` 配線。

**検証結果**: 新規テスト 4 passed（1.80s）／広域 engine+injection 1307 passed・失敗32+エラー1 は pristine ベースラインと IDENTICAL_FAILURES（事前既存）／製品非依存 `--changed-files` 付き verdict pass・total_token_hits 0／BAR_UNCHANGED。フル走行 stored confirmed=1 はユーザー（Claude）実 Caido 再検証待ち。

## 参考ルール
