---
task_id: SGK-2026-0320
doc_type: plan
status: done
parent_task_id: null
related_docs:
- docs/shigoku/subtasks/2026-06-20_sgk-2026-0281_recon-resume-recipe-phasegate_subtask_plan.md
- docs/shigoku/plans/done/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- docs/shigoku/subtasks/done/2026-06-23_sgk-2026-0293_vulnerability-management-review-trail_subtask_plan.md
- docs/shigoku/roadmaps/future_functions1.md
- docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0321_recon-step-state-resume-diff_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0322_reconstate-completion-parallel-checkpoint-decision-tree_subtask_plan.md
- docs/shigoku/subtasks/done/2026-07-01_sgk-2026-0334_p1b-shigoku-ops-decision-tree-cli_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0323_phasegate-granularity-import-recon_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0324_neo4j-attack-path-ui-vuln-management_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0325_conversational-ops-chat-direction_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0326_flexible-report-generation-reinjection_subtask_plan.md
title: 'Recon途中再開・可視化・対話型オペレーション 統合ロードマップ'
created_at: '2026-06-29'
updated_at: '2026-07-28'
tags:
- shigoku
- roadmap
target: src/recon/, src/core/engine/, src/reporting/, src/cli/, scripts/shigoku_ops_cli.py
---

# 統合ロードマップ：Recon途中再開・可視化・対話型オペレーション

> 本書は、たたき台（ブラッシュアップ前提）の統合ロードマップである。個別計画書 SGK-2026-0321〜0326 と SGK-2026-0334 はすべて本ロードマップの子タスクとする。特に SGK-2026-0325 と SGK-2026-0326 は CLI と運用導線を共有する兄弟タスクとして扱い、完全統合は初期スコープに含めない。0325 は「入力側」、0326 は「出力側」として段階的に進める。

## 1. 達成したいゴール（ユーザー視点）
- 長い Recon が中断しても途中成果を活かし、任意の step/ポイントから再開できる。
- 「前回との差分」「どこまで何をしてどうだったか」が可視化され、再開やスキップの判断材料になる。
- 「2回目は API だけ Fuzz」「1回目のここから開始」「このワードリストで攻撃」をチャット/指示ベースで柔軟に進められる。
- 見つけたエンドポイント一覧や脆弱性一覧を自由な形式で出し、それを SHIGOKU に再投入して分析・攻撃できる。

## 2. 対応するユーザー要望と子タスク対応

| 要望群 | 子タスク | 概要 |
|--------|----------|------|
| **P0** 即効 | SGK-2026-0321 | Recon step状態の自動保存＋再開CLI＋前回差分可視化 |
| **P1a** 基盤 | SGK-2026-0322 | ReconState完全化＋並行タスクcheckpoint/resume堅牢化 |
| **P1b** 可視化 | SGK-2026-0334 | 判断ツリー可視化＋shigoku-ops decision-tree CLI |
| **P2** 運用 | SGK-2026-0323 | PhaseGate細粒度化＋過去Recon成果物再利用(`--import-recon`) |
| **P3** 発展 | SGK-2026-0324 | 攻撃パスNeo4j UI＋脆弱性管理システム |
| **A** 対話 | SGK-2026-0325 | 入力側: 対話型オペレーション（チャットベース指揮 軽量版） |
| **B** レポート | SGK-2026-0326 | 出力側: 自由形式レポート生成→SHIGOKU再投入（single-session最小版先行） |

## 3. 優先度と依存関係

```text
P0 (0321) ──┐
P1a (0322) ─┼─→ P2 (0323) ──→ P3 (0324)
             │                 │
             │                 └─→ B Phase C (0326 cross-session)
             │
P1b (0334) ──┼─→ B Phase A/B (0326 output side: single-session export/reinjection)
             │                  │
             │                  └─→ A (0325 input side) へ structured target file / endpoint list を受け渡し
             └──────────────────→ A (0325 input side: resume + NL intent + CLI execution)
```

- **P0/P1a** が最優先。ReconState.save()/load() と start_step/end_step はすでにコードに存在し、統合するだけで価値が出る。
- **P1b** は P1a の checkpoint 契約を前提にしつつ、reporting/CLI 側で独立して進められる。
- **B** は「出力側」。基盤が近い（`inspect_session_findings` + フィルタ/射影 + JSON envelope が既存）ため、single-session の最小版は P0/P1 と並行可能。
- **A** は「入力側」。P0/P1a の step resume CLI を土台に先行でき、B が出力する structured target file / endpoint list を後から受ける形で段階拡張する。
- **P2** は P0/P1a の差分可視化が前提（freshness判定に差分が必要）。
- **P3** は SGK-2026-0307（攻撃パスPhase2）と SGK-2026-0293（脆弱性管理）の設計を引き継ぐ。0326 の cross-session / FindingsRepository 連携はこの後段依存として扱う。

## 4. 現状の前提知識（実装踏まえた評価）

### 4.1 すでに存在する基盤
- `ReconPipeline.run(start_step, end_step)` が step レンジ指定をサポート（`src/recon/pipeline.py:3696`）。
- `ReconState.save()/load()` が存在するが本番で未呼び出し（同 `pipeline.py:80/97`）。
- Run Ledger / LLM Usage Summary / Run Narrative / Target Profile / Attack Path Markdown は SGK-2026-0298 系列で実装済み。
- `inspect_session_findings(detection_class, fields, preset, max)` と JSON envelope 出力が既存。
- `shigoku-ops` には `report loop` / `session findings` / `session resolve-from-report` などの運用補助 CLI があり、A/B 共有導線の土台にできる。
- `--interactive` と `InteractiveBridge` が存在し、preflight / ProjectManager / MasterConductor 起動の橋渡しはすでにある。
- `FindingsRepository`（SQLite `~/.shigoku/findings.db`）は存在し、`shigoku-ops findings list/search/stats/export-targets` で CLI 露出済み。

### 4.2 主なギャップ
- `ReconState.save()` のフィールド不足（`tech_stack`/`screenshots_count`/`results` 未保存）＋並行タスク途中状態未保存。
- 再開ポイント・差分の可視化がなく、前回結果との added/removed/modified 比較がない。
- PhaseGate がバイナリ（INIT/RECON 常時解放 → ATTACK 一括解放）。
- `InteractiveBridge` はあるが、自由形式の会話ループ、NL→コマンド翻訳、`0326` 出力の入力受け渡しが未整備。
- エンドポイント一覧抽出、structured target file 出力、single-session 逆投入 CLI が未整備。cross-session はさらに後段。

## 5. フェーズ分割と達成基準
2026-07-21 更新: 本ロードマップは shared schema / single-session export-reinjection / lightweight intent dispatch の完了をもってクローズし、P3 downstream continuation は `SGK-2026-0324` へ分離追跡する。

- **Phase 1（P0+P1a+P1b+B最小版並行）**: Recon step resume 実用化、checkpoint/resume 堅牢化、判断ツリー可視化、single-session の抽出/再投入 artifact 基盤を固める。
  完了条件: 1つの実 session から `structured target file` を生成し、整合性チェックを通したうえで再投入 dry-run まで確認できること。
- **Phase 2（P2+A軽量+B出力拡張）**: PhaseGate 細粒度化、import-recon、対話ラッパー（shigoku-ops 経由）、A/B 共有 CLI 契約と structured artifact 運用を実用化する。
  完了条件: `0326` の出力 artifact を `0325` 経由で読み込み、プレビュー確認つきで 1 本の安全な実行経路としてつながること。
- **Phase 3（P3+B cross-session+A重量）**: Neo4j UI、脆弱性管理、0326 の cross-session 連携、実行中MC動的注入（次期アーキテクチャ）。
  完了条件: `0324` の成果物と FindingsRepository CLI 露出を前提に、cross-session 出力と重量版導線の可否判断が実 artifact で検証されること。

達成基準（共通）: 各子タスクは単体テスト＋可能なら実 session/report artifact で検証すること。
本ロードマップの close 条件は、Phase 1-2 と shared bridge hardening の完了、および Phase 3 残件が `SGK-2026-0324` として独立追跡できる状態にあることとする。

### 5.1 統合実装ステップ
- [x] ステップ1: `0325/0326` 共通の正本 schema を先に固定する。最低でも `IntentCommand`, `AttackTargetSpec`, `ExportManifest`, `correlation_id`, `reason_codes`, `provenance`, `allowed_hosts` を定義し、どの文書/型が正本かを明記する。
- [x] ステップ2: `0326` 側で single-session 出力系を先行し、`report/session` 解決、整合性チェック、artifact の置き場所、命名、hash、TTL、atomic write を備えた最小 export/reinjection 経路を固める。
- [x] ステップ3: `0325` 側で入力系を実装し、NL 指示は allowlist 済み構造化 command のみへ変換し、プレビュー確認、scope 検証、non-TTY fail-closed、timeout、retry budget、kill switch を備えた軽量 dispatch に接続する。
- [x] ステップ4: `0325/0326` を end-to-end で接続し、`0326` 出力 artifact を `0325` が受けて dry-run と限定実行の両方を通せるか検証する。ログと JSON envelope には `correlation_id` と `manifest_hash` を必須出力する。
- [x] ステップ5: `P2` の import-recon / freshness 判定へ統合し、古い成果物混入を防ぐ `source_session`, `source_report`, `generated_at`, `scope_snapshot` をチェック可能にする。
- [x] ステップ6: `0324` の FindingsRepository CLI と実 artifact 検証が整うまで cross-session は解放しない。解放条件は「CLI 露出済み」「整合性チェックを通る」「out-of-scope 混入を拒否できる」の3点とする。
- [x] ステップ7: lightweight 導線で十分な安全性と観測性が証明されるまで、実行中MC動的注入（重量版）は着手しない。重量版着手前に feature flag / rollout 停止条件 / daily LLM budget を先に文書化する。

進捗メモ（2026-07-21）:
- `ops_artifacts.py`, `endpoint_extractor.py`, `shigoku-ops report/session export-targets`, `shigoku-ops ops intent` によりステップ1-3は実装済み。
- `ops intent --execute --approve --main-dry-run` により `report.export-targets -> main.attack-targets` の限定実行を確認し、ステップ4を完了。
- shared target bundle の ingress で `generated_at` / `ttl_days` / `scope_snapshot` / single-session source provenance を fail-closed で検証し、expired bundle を拒否するようにした。
- `import-recon` は `recon_state.json` の `saved_at` provenance を freshness 正本として使い、欠落時は `missing_provenance` で fail-closed にした。
- `shigoku-ops findings list/search/stats/export-targets` と mixed-scope fail-closed を追加し、ステップ6の cross-session 最小解放条件を満たした。
- follow-up hardening として `approval deny` / `command_timeout` / `ops_intent_kill_switch` / `scope外 target` / `allowed_hosts mismatch` / `redaction regression` / `empty export` / `intent_llm_unavailable` の回帰テストを追加した。
- `docs/shigoku/manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md` に `ops_intent.feature_flag`, `ops_intent.kill_switch`, `ops_intent.daily_llm_budget`, preview-only へ戻す停止条件を追記し、ステップ7を完了。
- `0325` / `0326` は done 化し、P3 downstream continuation は `SGK-2026-0324` へ分離追跡して本ロードマップをクローズ可能にした。

## 6. 懸念点と対策 / 既知のリスク
### 6.1 懸念点と対策
- [ ] [視点:SRE/インフラ][発生確率:高][影響度:大] `0325` の入力契約と `0326` の出力契約がズレると、共有CLI導線が本番で崩れる。
  対策: `IntentCommand` / `AttackTargetSpec` / `ExportManifest` を共通 schema として先に固定し、`provenance`, `allowed_hosts`, `manifest_hash` を最小必須項目にする。
- [ ] [視点:SRE/インフラ][発生確率:高][影響度:中] export/reinjection artifact の寿命、配置、上書き方式が曖昧だと、運用中に古いファイルや壊れた途中ファイルを拾う。
  対策: artifact lifecycle を計画に追加し、配置先、命名規則、TTL、atomic write、再実行時の上書きポリシーを明文化する。
- [ ] [視点:ソフトウェアアーキテクト][発生確率:高][影響度:大] shared contract の正本がないまま実装を始めると、`0325` と `0326` が別々の辞書構造で進み、後で大きな結合作業が発生する。
  対策: 実装前の最初のステップとして共通型・正本文書・読者一覧を固定し、ad hoc dict ではなく明示的な型定義へ寄せる。
- [ ] [視点:デバッガー][発生確率:中][影響度:中] `0325` と `0326` をまたぐ失敗時に、どの指示がどの artifact を生成し、どの run へ渡ったか追跡できない。
  対策: `correlation_id`, `intent_hash`, `manifest_hash`, `source_session`, `reason_codes` を全経路に必須で残す。
- [ ] [視点:ハッカー][発生確率:中][影響度:大] `structured target file` が改ざんされると、scope 外ホストや意図しない path を再投入される。
  対策: 再投入前に hash 検証、scope validation、`allowed_hosts` 照合を必須化し、検証失敗時は fail-closed で停止する。
- [ ] [視点:CTO][発生確率:高][影響度:大] フェーズの完了条件が曖昧だと、どこで止めてよいか、何が MVP（最小実用版）かの判断がぶれる。
  対策: 各 Phase に実 artifact ベースの完了条件を明記し、cross-session と重量版は解放条件を満たすまで後段へ固定する。
- [ ] [視点:CTO][発生確率:中][影響度:中] lightweight 導線のままでもコストや危険操作が膨らむ可能性がある。
  対策: feature flag, kill switch, daily LLM budget, rollout 停止条件を Phase 3 着手前ではなく軽量版の時点で計画へ含める。

### 6.2 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:中] legacy artifact reuse 全体にはまだ揺れが残る。shared target bundle と `import-recon` は freshness/provenance を fail-closed にしたが、他の旧 artifact reader へ同等ポリシーを広げる余地がある。
- [ ] [重要度:高] 実行中MCへの動的タスク注入はアーキテクチャ変更を伴う。軽量版（外部エージェントが shigoku-ops を呼ぶ）を先行し、重量版は次期フェーズ。
- [ ] [重要度:高] A/0325 の入力契約と B/0326 の出力契約がズレると、共有CLI導線が運用不能になる。structured target file / provenance / scope を最小共通 schema として先に固定する。
- [ ] [重要度:中] チャット/レポート出力の機密値マスク。既存 redactor を再利用し、secret を出力に漏らさない。
- [ ] [重要度:中] 人間向け Markdown と再投入用 machine-readable artifact を混同すると誤投入の原因になる。再投入の正本を構造化出力へ固定する。
- [ ] [重要度:中] ReconState の保存フォーマット後方互換。schema_version を付け、旧セッション reader を壊さない。

### 6.3 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0320-D01
    title: "継続監視: 子タスク群の進捗と依存整合"
    reason: "本ロードマップはたたき台であり、子タスクの設計変更に追随が必要"
    impact: medium
    tracking_task_id: SGK-2026-0320
    recommended_next_action: "各子タスク計画書のブラッシュアップ時に本 related_docs を更新する"
```
