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
