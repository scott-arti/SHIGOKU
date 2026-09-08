---
task_id: SGK-2026-0474
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-08_sgk-2026-0474_lfi-path-based-confirmation.md
- docs/shigoku/worklogs/2026-09-08_sgk-2026-0474_lfi-path-based-confirmation_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0471_open-redirect-confirmation.md
tags:
- shigoku
- detection
- lfi
- path-traversal
- confirmation-bar
created_at: '2026-09-08'
updated_at: '2026-09-08'
---

# SGK-2026-0474 作業完了報告 — LFI/パストラバーサルを本物確定（◎）まで到達（パス方式対応）

## 何をしたか / なぜ

検出能力マップ [[sgk-2026-0465]] で LFI は「△〜○」。実対象 Juice Shop で本物確定（◎）へ引き上げた。
実測で、現行 smart_lfi は**パラメータ方式のみ**で、Juice Shop の**パス方式ヌルバイト LFI**
（`/ftp/<file>%2500.md` で本来非公開の機密ファイルを取得）に構造的に噴かないこと、Finding の
impact/reproduction_steps が空で機械フロア missing_impact 落ちすること、再現チェッカー（凍結）が
`file_content_leak` を `_LFI_PATTERNS`（/etc/passwd 定型）だけで照合し `.bak`（JSON/MD）は再現不成立に
なることを確定した（詳細は計画書 [[sgk-2026-0474]]）。

## 実装（非凍結1＋凍結1・凍結はユーザー明示承認済み）

- **B（`smart_lfi.py`・非凍結）**: パス方式トラバーサル/ヌルバイト検出モードを追加
  （`_run_path_traversal_precheck` / `_path_bypass_variants` / `_send_path_get` / `_path_leak_excerpt`）。
  **差分ベースの誤検知ガード**: クリーン GET が非 2xx かつバイパス GET が 200＋実体本文の差分成立時のみ
  vulnerable とし、そのときだけ `file_marker_excerpt` に安定抜粋を残す（HTML 先頭・エラートークン・
  短文は不採用＝fail-closed）。発火 Finding に impact / reproduction_steps を設定（パラメータ方式経路でも設定）。
  既存パラメータ方式・LLM ループは非回帰で維持。
- **A（`sealed_reproduction_checker.py`・凍結・承認済み）**: `file_content_leak` の再現照合を拡張。
  既存 `_LFI_PATTERNS` 一致を先に試し、非発火時のみ元 Finding の `file_marker_excerpt`
  （payload additional_info 由来）が封印再送本文に再出現すれば matched。空白正規化＋最小長 24 ガード・
  空/短すぎ抜粋は excerpt 経路で matched にしない（fail-closed）。他マーカー・既存経路は byte-identical。

## 結果（独立検証・Claude が実施）

- **実 Juice Shop で ◎ を実証**: クリーン `/ftp/package.json.bak` → 403、パス方式バイパス
  `/ftp/package.json.bak%2500.md` → 200（差分成立）。実エンジン→excerpt（取得ファイル内容 120字）→
  `payout_grade=True/file_content_leak`→実 `SealedReproductionChecker` が GET 再送し excerpt 再出現で
  `matched`→**`CONFIRMED / hybrid_confirmed`**。
- テスト: 新規3ファイル18テスト全緑（独立実行）。`tests/core/agents/swarm/injection/ tests/core/validation/`
  = **896 passed / 2 failed**。2 failed は `test_phase_b_readiness.py`（別環境の成果物存在チェック）で
  本変更と無関係（workspace 配下に不関与）。
- 凍結: 改変は承認済み `sealed_reproduction_checker.py` のみ。`payout_grade.py` / `poc_judge.md` /
  `task_queue.py` / `finding_validator.py` は `git diff --quiet HEAD` exit 0（無改変）を独立確認。
- 製品非依存 token 0（denylist 照合で変更コード・テストにヒット 0）。excerpt 等の runtime 証拠に対象内容が
  含まれるのは仕様（証拠）でありコード/テストのハードコードではない。
- 誤検知 fail-closed（クリーンも 200・エラーページ・短文・空/短すぎ抜粋）をテストで担保。敷居は下げていない。

## 完了条件の充足

計画の完了条件 1〜7 すべて PASS。`in_scope_blocker=0`。実対象 ◎ は Juice Shop `/ftp` で達成（条件7）。

## 実装フローの注記（インフラ）

DeepSeek 実装は opencode デタッチ起動で実施。1回目は opencode プリセット（oh-my-opencode-slim）の
サブエージェント（fixer 等）が未認証プロバイダ `makora` にルーティングされ auth 失敗で中断
（対象ファイルは無変更）。リポジトリ `opencode.json` に一時的な agent→deepseek 上書きを入れて genuine
deepseek へ強制し再実行、完了後に `opencode.json` を元へ復元（追跡ファイルの無改変を確認）。詳細は
[[opencode-fixer-subagent-makora-fallback]]。

## deferred_tasks

（本タスクに阻害なし。関連する将来課題は [[sgk-2026-0473]]（オープンリダイレクト側・別能力）に既存。）
