---
task_id: SGK-2026-0296
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0295
related_docs:
- docs/shigoku/plans/2026-06-23_sgk-2026-0295_strict-entry-gate-caido-mandatory-and-runtime-preflight-validation_plan.md
- docs/shigoku/reports/2026-06-23_SGK-2026-0295_work_report.md
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
title: Strict Entry Gate Review Fixes Instruction
created_at: '2026-06-23'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/core/preflight and CLI entry gate
---

# 実装計画書：Strict Entry Gate Review Fixes Instruction

## 1. 達成したいゴール（ユーザー視点）
- [ ] `shigoku --target example.com` のような通常入力でも、入口ゲートが正しく URL 正規化後の対象を検査し、不要な `AUTH_UNKNOWN` で停止しないこと。
- [ ] CLI 初回、`--resume`、`/resume`、`InteractiveBridge` の各経路で、実行コンテキストごとに入口ゲートが正しく再評価されること。
- [ ] `nuclei`, `bbot`, `katana`, `httpx` などの必須ツール確認と、BinaryManager 管理対象の更新ポリシーが実行経路に接続されていること。
- [ ] Cookie/Bearer が渡されたときは認証有効性を strict に見るが、認証不要の公開 recon を誤って止めないこと。
- [ ] Caido 必須チェックが「8080番に何かいる」ではなく、Caido として利用できる状態を確認すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/preflight/entry_gate.py`: `EntryGateFacade.run_once()` のキャッシュ粒度を修正し、実行コンテキストごとに再評価できるようにする。
  - `src/main.py`: preflight に渡す `target` と `goal` を正規化し、`mode` ではなく実行目的に応じた goal を渡す。
  - `src/core/conductor/interactive_bridge.py`: Cookie 文字列を dict 化し、`auto_goal` をそのまま tool matrix に通せる形式へ正規化する。
  - `src/cli/commands.py`: `/resume` の preflight context 抽出を強化し、保存済み session の target/auth/profile を使う。
  - `src/core/engine/master_conductor.py`: resume hardening の二重実行・キャッシュ誤用を防ぎ、session 復元後の context でゲートを実行する。
  - `src/core/preflight/tool_check.py`: `ToolUpdatePolicy` を実際に呼び、required tool matrix を実行 goal/profile に合わせて修正する。
  - `src/core/preflight/tool_update_policy.py`: update 失敗時でも最低版を満たす既存 tool は通すルールを明確化する。
  - `src/core/preflight/auth_probe.py`: 認証情報なしの公開 target と、認証情報ありの target を別ルールで評価する。
  - `src/core/preflight/caido_check.py`: token なしでも Caido 固有の確認ができる判定へ寄せる。
  - `tests/unit/preflight/`: 上記の regressions を単体テストで固定する。
  - `tests/test_session_resume.py` / CLI 関連テスト: `--resume` と `/resume` の入口ゲートを統合テストで固定する。
- **データの流れ / 依存関係:**
  - CLI args / saved session / InteractiveBridge args -> target/goal/auth 正規化 -> `PreflightContext` -> `EntryGateFacade.run(context)` -> checkers -> pass/fail
  - `goal` は `mode` ではなく `Reconnaissance`, `Crawl`, `Analyze`, `HybridHunt`, `xss`, `full` などの実行目的から正規化する。
  - Cookie/Bearer が存在する場合のみ `auth_required=True` として認証済み判定を必須にする。認証情報なしの場合は login/challenge/block の検出は行うが、`authenticated marker` 不在だけでは停止しない。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - `target`: CLI 入力または session の target URL。scheme なし入力は preflight 前に `https://` を補完する。
  - `goal`: 実行目的。`mode` ではなく command/auto_goal から導出する。
  - `profile`: `bbpt`, `ctf`, `full` など。tool matrix に渡す前に小文字化する。
  - `cookies`, `bearer_token`, `auth_headers`: Cookie 文字列も dict へ正規化して渡す。
  - `resume_session_id`: resume 経路の再評価キーとして使う。
- **出力/結果 (Output):**
  - 成功: 現在の context に対する `PreflightResult(PASS)`。
  - 失敗: context 固有の `PreflightResult(FAIL)` と reason code。古い context の cached result を返してはいけない。
- **制約・ルール:**
  - `EntryGateFacade` はプロセス全体で1回だけ実行する singleton cache にしない。少なくとも `target + goal + profile + auth presence + resume_session_id` を含む cache key を使うか、入口ゲートは常に fresh に評価する。
  - `demo`, `projects`, `report`, `rag` など HTTP 実行を伴わない経路は、重い tool/auth check の対象外にする。
  - `ToolUpdatePolicy` を dead code にしない。`ToolChecker` から呼び出し、managed tool の install/update 判定を実行する。
  - `bbot` は recon/full 相当の goal で必須にする。`goal=bugbounty` のまま tool matrix に渡さない。
  - Caido チェックは TCP 成功だけで通さない。token なしでも Caido の API/GraphQL 到達、または Caido 固有の応答確認を試みる。
  - Cookie, Authorization, token はログ・CLI・snapshot に平文で出さない。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `src/main.py` に preflight 前 target 正規化 helper を追加する。`args.target`, `args.recon`, `args.crawl`, `args.analyze` は scheme なしなら `https://` を補完し、`args.log` は URL として auth probe しないよう goal 側で分岐する。
- [ ] ステップ2: `src/main.py` の preflight 呼び出しで `goal=str(mode)` をやめ、command から `goal` を導出する。例: `--target/--recon -> recon`, `--crawl -> crawl`, `--analyze -> analyze`, `--log -> hybridhunt`, `--interactive -> interactive`。
- [ ] ステップ3: `src/core/preflight/entry_gate.py` の `EntryGateFacade.run_once()` を修正する。推奨は `run(context)` を毎回評価する `run_gate()` に寄せること。キャッシュを残すなら context key を導入し、異なる target/session/auth では必ず再評価する。
- [ ] ステップ4: `EntryGateFacade` の既存テストを修正する。`test_run_once_idempotent` は「同一 key なら再利用」または「毎回評価」に合わせて更新し、別 target / 別 resume_session_id / 別 auth presence では再評価される regression test を追加する。
- [ ] ステップ5: `src/core/conductor/interactive_bridge.py` で Cookie 文字列を dict 化する。`cookies` が `str` でも `PreflightContext.cookies` に入るよう、`src/main.py` と同等の parse helper を共通化するか、小さな preflight utility に移す。
- [ ] ステップ6: `src/cli/commands.py` の `/resume` で saved session から `target`, `cookies`, `bearer_token`, `auth_headers`, `goal`, `profile` を取り出す処理をテストで固定する。取得できない場合は target 空のゲートではなく、明示的な `RESUME_CONTEXT_INCOMPLETE` failure にする。
- [ ] ステップ7: `src/core/preflight/tool_check.py` に `ToolUpdatePolicy` を注入し、`_check_single_tool()` の存在確認・version 確認後に policy を呼ぶ。managed tool は BinaryManager に渡し、unmanaged tool は remediation 付きで停止する。
- [ ] ステップ8: required tool matrix を修正する。`nuclei`, `katana`, `httpx` は recon/crawl/analyze/full で必須、`bbot`, `subfinder`, `gau` は recon/full で必須、`dalfox` は xss/injection/full で必須にする。`HybridHunt` はログ解析に必要な tool と Caido の扱いを別定義にする。
- [ ] ステップ9: `src/core/preflight/auth_probe.py` に `auth_required` を導入する。Cookie/Bearer/auth_headers がある場合は authenticated 判定必須、ない場合は login/challenge/block を検出して failure にするが、authenticated marker 不在だけでは fail にしない。
- [ ] ステップ10: `src/core/preflight/caido_check.py` を修正する。token なし時の root GET 成功だけで pass せず、`/graphql` の応答形、Caido 固有 API、または明確な Caido 識別情報を確認する。確認不能なら `CAIDO_IDENTITY_UNVERIFIED` で fail-close にする。
- [ ] ステップ11: CLI heavy path の preflight 対象を見直す。`args.demo` と完全 interactive は Caido/tool/auth の全チェックが必要か判断し、HTTP 実行に入る直前の bridge 側で評価する。二重評価が残る場合は context key で安全に扱う。
- [ ] ステップ12: テストを追加する。
  - `shigoku --target example.com` 相当の context が `https://example.com` に正規化されること。
  - 別 target で `EntryGateFacade` が前回結果を返さないこと。
  - `goal=recon` で `bbot` が required になること。
  - `goal=bugbounty` の誤渡し regression を防ぐこと。
  - Cookie なし公開ページが authenticated marker 不在だけで fail しないこと。
  - Cookie あり login redirect は fail すること。
  - token なし Caido identity 未確認は fail すること。
  - `/resume` で session target/auth を使って preflight context が作られること。
- [ ] ステップ13: 既存テストを実行する。
  - `.venv/bin/pytest tests/unit/preflight -q`
  - `.venv/bin/pytest tests/test_session_resume.py -q`
  - 追加した CLI/preflight 統合テスト
- [ ] ステップ14: 構文確認とドキュメント検証を実行する。
  - `.venv/bin/python - <<'PY' ... compile(...) ... PY` 形式で `py_compile` の `__pycache__` 権限問題を避ける。
  - `python3 scripts/sync_shigoku_updated_at.py --repo-root /home/bbb/Documents/App/Shigoku`
  - `python3 scripts/validate_shigoku_docs.py`

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] `EntryGateFacade` の cache key 設計を雑にすると、また別 context の結果を流用する。テストでは必ず異なる target/session/auth の再評価を固定する。
- [ ] [重要度:高] auth probe を強くしすぎると公開 recon が止まる。`auth_required` と `block/login detection` を分離する。
- [ ] [重要度:中] Caido identity 判定は Caido のバージョン差に影響される可能性がある。初版は複数手段を試し、失敗時 reason code を分ける。
- [ ] [重要度:中] tool matrix は今後増えるため、実装直書きだけでなく設定化を検討する。ただし今回の修正では既存実装の誤動作修正を優先する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0296-D01
    title: "継続監視: Strict Entry Gate false positive / false negative"
    reason: "入口ゲートは運用環境差の影響を受けるため、導入後の停止理由を継続観測する"
    impact: medium
    tracking_task_id: SGK-2026-0296
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
