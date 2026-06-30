---
task_id: SGK-2026-0295
doc_type: plan
status: active
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/specs/katana_caido_integration.md
- docs/shigoku/specs/2026-01-26_Proxy_ErrorHandling.md
title: 'Strict Entry Gate: Caido Mandatory and Runtime Preflight Validation'
created_at: '2026-06-23'
updated_at: '2026-06-30'
tags:
- shigoku
target: runtime entry gate / preflight validation
---

# 実装計画書：Strict Entry Gate: Caido Mandatory and Runtime Preflight Validation

## 1. 達成したいゴール（ユーザー視点）
- [ ] `shigoku` を初回実行しても `--resume` / `/resume` で再開しても、実タスク開始前に必ず strict な入口ゲートが走ること。
- [ ] Caido が未起動、必須ツールが未導入、認証 Cookie/Bearer が無効、ターゲットが login/challenge 画面に落ちている、といった実行失敗が見込まれる状態では fail-close で停止し、原因をアラート表示できること。
- [ ] Katana / Recon / HybridHunt のような長尺ジョブを始める前に、認証済み到達性、WAF/Block 兆候、スコープ/接続性の異常を事前に検知し、無駄打ちとブロックリスクを減らせること。
- [ ] AI は補助判定に使うが、停止条件そのものは deterministic に保ち、曖昧ケースのみ AI が分類を補強すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/main.py`: 修正。CLI 初回実行と `--resume` 分岐の両方で入口ゲートを必須化する。
  - `src/core/conductor/interactive_bridge.py`: 修正。`start_interactive_session()` の最初で preflight 実行し、auto goal 実行前に停止判定できるようにする。
  - `src/cli/commands.py`: 修正。`/resume` からの再開でも同一ゲートを通す。
  - `src/core/engine/master_conductor.py`: 修正候補。resume 復元後の実行開始点に再確認フックを入れ、CLI 経由以外の再開にも保険を掛ける。
  - `src/core/adapters/external/binary_manager.py`: 既存活用。管理対象バイナリの存在確認・更新処理を再利用する。
  - `src/core/adapters/external/*.py`: 既存活用。Nuclei / DalFox など既存 adapter の health check を流用する。
  - `src/core/infra/network_client.py`: 既存活用。認証付きプリフライト、302/401/403、challenge 応答、Cookie 反映の共通 I/O 境界として使う。
  - `src/recon/pipeline.py`: 既存活用。認証ヘッダーや Cookie 伝搬の現状契約をゲートに接続する。
  - `src/core/preflight/entry_gate.py`: 新規。strict 入口ゲートの統合 orchestration。
  - `src/core/preflight/models.py`: 新規。`PreflightResult`, `PreflightFailure`, `ToolRequirement`, `AuthProbeResult` などのデータ定義。
  - `src/core/preflight/tooling.py`: 新規。必須ツール一覧、存在確認、BinaryManager 経由更新判定、Caido 生存確認を集約。
  - `src/core/preflight/auth_probe.py`: 新規。Cookie/Bearer 付き到達性確認、login/challenge 判定、認証後らしさ判定。
  - `src/core/preflight/ai_classifier.py`: 新規。曖昧レスポンスの軽量 AI 分類を担当。deterministic 判定の補助専用。
  - `tests/unit/preflight/`: 新規。tool / auth / AI fallback / fail-close の単体テスト。
  - `tests/core/test_main_*`, `tests/test_session_resume.py`, `tests/recon/`: 修正。CLI 入口と resume 再開の回帰を追加。
- **データの流れ / 依存関係:**
  - CLI 引数 / Resume 対象 session / config / context -> `EntryGate.run()` -> `CaidoCheck + ToolCheck + AuthProbe + TargetProbe + AI fallback` -> `pass` の場合のみ `InteractiveBridge` / `MasterConductor.execute_with_replan()`
  - `Cookie` / `Authorization` / 対象 URL -> `auth_probe` -> redirect chain / status / body signature / title / challenge signal を収集 -> deterministic 判定 -> 曖昧時のみ `ai_classifier`
  - 管理対象ツール (`nuclei`, `httpx`, `dalfox` 等) -> `BinaryManager.ensure_binary()` / version probe -> 更新成功 or 失敗理由 -> strict policy に従い停止
  - ゲート失敗 -> CLI アラート表示 + ログ出力 + session には「未実行理由」を残す

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - 実行コンテキスト: `mode`, `auto_goal`, `auto_target`, `resume session`, `scope_file`, `profile`
  - 認証情報: `cookies`, `bearer_token`, `auth_headers`, Caido から復元された session 情報
  - 設定: strict gate policy, tool requirements, update policy, AI classification toggle, auth probe target hints
  - 外部状態: Caido process / GraphQL endpoint / tool binary / target response
- **出力/結果 (Output):**
  - 成功時: `PreflightResult(status="pass")` を返し、以降の実行を許可
  - 失敗時: `PreflightResult(status="fail")` と構造化された失敗理由一覧を返し、実行を停止
  - 警告のみ: strict 方針のため原則なし。ただし監視情報や改善ヒントは補足欄に出す
- **制約・ルール:**
  - fail-open を禁止し、入口ゲートに失敗したら長尺ジョブは開始しない。
  - CLI 初回、`--resume`、`/resume`、`start_interactive_session()` のどこから入っても同じゲートを通す。
  - Caido は常時必須とし、少なくとも `http://127.0.0.1:8080` への疎通、必要なら GraphQL 応答確認まで行う。
  - ツール更新は「SHIGOKU 管理対象バイナリのみ自動更新」を基本とする。system package や手動導入ツールは、古い/不明/未導入なら strict に停止して remediation を表示する。
  - AI 判定は deterministic で `authenticated/login/challenge/waf/blocked` を確定できないレスポンスに限定する。
  - 秘密情報をログへ平文出力しない。Cookie, Authorization, PAT, access token は必ずマスクする。
  - 認証チェックはなるべく低負荷にし、HEAD/GET 1-3 本程度のプリフライトに制限する。

### 3.1 strict 入口ゲートで必須チェックする項目

1. **Caido Mandatory**
   - プロセスまたは TCP 疎通確認
   - 必須 URL への応答確認
   - Caido API/GraphQL を使う経路では token と API 応答も確認
2. **必須ツール存在確認**
   - 共通候補: `katana`, `nuclei`, `bbot`, `httpx`, `subfinder`, `gau`, `ffuf`
   - goal/profile に応じた追加候補: `dalfox`, `gospider`, `amass`, `subzy`, `nmap`
3. **ツール更新/鮮度確認**
   - BinaryManager 管理対象は `ensure_binary()` と version probe
   - `nuclei` は template directory の存在と `-update-templates` が必要な状態も確認
   - `bbot` など未管理ツールは version 不明なら fail-close
4. **認証 Cookie/Bearer 妥当性**
   - 302 -> login, 401, 403, logout 循環, session expired 文言
   - 期待ページ title / body / path と不一致
5. **認証後らしさ確認**
   - ログイン後にのみ出る DOM/文言/URL ヒントが見えるか
   - 既知 login 画面にしか到達していないなら停止
6. **ブロック兆候確認**
   - 403/406/429, captcha, challenge, WAF banner
7. **対象基本健全性**
   - DNS 解決、TLS/HTTP 接続、scope 不整合、Proxy 経由強制

### 3.2 AI を使うポイント

- `auth_probe` が「200 は返るが login 画面かアプリ画面か曖昧」「challenge か通常エラーページか判断しにくい」ケースで、軽量 LLM に body/title/redirect chain/signal を渡して分類する。
- 出力ラベルは `authenticated`, `login_page`, `session_expired`, `waf_challenge`, `rate_limited`, `unknown` の固定集合に制限する。
- AI が `unknown` または低信頼なら strict 方針により停止する。
- AI は意思決定の置き換えではなく、deterministic シグナル不足時の補強に限定する。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `src/core/preflight/` を新設し、`EntryGateFacade`, `EntryGate`, `PreflightResult`, `PreflightFailure`, `ToolRequirement`, `AuthProbeResult`, `ResponseClassificationInput`, `ResponseClassificationResult` を定義する。失敗理由は `reason_code`, `severity`, `remediation`, `evidence` を持つ構造化形式にする。
- [ ] ステップ2: 入口ゲートの責務境界を固定する。`src/main.py`、`src/core/conductor/interactive_bridge.py`、`src/cli/commands.py`、必要なら `src/core/engine/master_conductor.py` は `EntryGateFacade.run_once(context)` だけを呼び、個別に判定ロジックを持たない方針へ統一する。
- [ ] ステップ3: `src/core/preflight/` を `entry_gate.py`, `caido_check.py`, `tool_check.py`, `tool_update_policy.py`, `auth_probe.py`, `ai_classifier.py`, `models.py` に分割し、`1 checker = 1責務 = 1 reason_code namespace` で実装する。
- [ ] ステップ4: strict gate policy と mode を定義する。少なくとも `strict-prod` と `strict-dev` を追加し、共通で fail-close としつつ、更新ポリシー・診断出力の差だけを設定で切り替える。
- [ ] ステップ5: `caido_check.py` に二段階の Caido 判定を実装する。`TCP疎通` と `HTTP/GraphQL 応答` を分離し、両方失敗・片方のみ失敗で異なる `reason_code` を返せるようにする。各チェックの timeout を明記し、到達不能時は fail-close とする。
- [ ] ステップ6: `tool_check.py` と `tool_update_policy.py` で required tool matrix を実装する。goal/profile ごとに `required`, `optional`, `not_applicable` を定義し、存在確認と version probe を分離する。
- [ ] ステップ7: ツール更新ポリシーを実装する。BinaryManager 管理対象は `存在確認 -> 最低版判定 -> 更新試行` とし、`更新失敗でも既存版が最低版以上なら通過 / 未導入または最低版未満なら停止` を適用する。未管理ツールは strict に停止し remediation を返す。
- [ ] ステップ8: `nuclei` 専用の健全性確認を追加する。binary だけでなく template directory、最低限の template 解決、必要時の `-update-templates` 要否を reason code 付きで返す。
- [ ] ステップ9: `auth_probe.py` で Cookie/Bearer 付き低負荷プリフライトを実装する。`network_client` を使って redirect/status/body/title/challenge marker を取得し、`AUTH_LOGIN_REDIRECT`, `AUTH_SESSION_EXPIRED`, `BLOCK_WAF_CHALLENGE`, `BLOCK_RATE_LIMIT`, `APP_FORBIDDEN` などの deterministic 判定器を作る。
- [ ] ステップ10: 認証後らしさ判定を generic heuristic として実装する。`URL`, `title`, `body marker`, `redirect chain` を点数化し、login 画面・challenge 画面・認証済み画面を deterministic に区別できるケースは AI を使わず確定する。
- [ ] ステップ11: `ai_classifier.py` を `response classification` の補助層として実装する。曖昧レスポンスのみ lightweight model へ `title + redirect summary + top markers` を送り、固定ラベル集合 `authenticated`, `login_page`, `session_expired`, `waf_challenge`, `rate_limited`, `unknown` だけを返させる。
- [ ] ステップ12: AI 使用制御を追加する。`1 run あたり最大回数`, `1 probe あたり最大1回`, `model timeout`, `model failure -> unknown`, `unknown -> strict fail` を実装し、コスト/待ち時間を抑制する。
- [ ] ステップ13: `--resume`、`/resume`、`start_interactive_session()`、必要なら CLI 以外の resume 経路に入口ゲートを接続する。resume 時は session 復元後に `target`, `cookies`, `auth_headers`, `profile`, `goal`, `previous preflight snapshot` を再評価し、当時 valid でも現在 invalid なら停止する。
- [ ] ステップ14: observability と debug trace を実装する。`preflight_pass_total`, `preflight_fail_total{reason_code}`, `caido_unreachable_total`, `auth_probe_login_redirect_total` などのメトリクス、`preflight_snapshot`、`AI classification trace`、`tool/version/path` をマスク付きで保存する。
- [ ] ステップ15: CLI 表示と remediation 出力を整備する。失敗時は「何が足りないか」「再現コマンド」「何を直せば再実行できるか」を短く表示し、session/context には構造化 reason code を残す。
- [ ] ステップ16: Phase rollout を実装する。`Phase 1: deterministic gate only`, `Phase 2: tool update`, `Phase 3: AI classifier`, `Phase 4: resume hardening` の順で有効化し、各 phase に feature flag または settings gate を持たせる。
- [ ] ステップ17: 単体テストを追加する。
  - Caido down -> fail
  - Caido TCP ok / GraphQL fail -> dedicated fail reason
  - tool missing -> fail
  - managed tool update success -> pass
  - managed tool update fail but minimum version satisfied -> pass
  - unmanaged stale tool -> fail
  - nuclei templates missing -> fail
  - 302 to login -> fail
  - 200 login page -> fail
  - 403/429 challenge -> fail
  - ambiguous page + AI says authenticated -> pass
  - ambiguous page + AI unknown -> fail
  - resume path also gated -> fail-close
- [ ] ステップ18: 統合テストを追加する。最低でも `CLI --target`, `CLI --resume`, `/resume`, `InteractiveBridge direct call` の4経路に対して、`Caido down + resume`, `cookie expired + recon`, `tool missing + hybridhunt` を検証する。
- [ ] ステップ19: 関連テスト実行後、ドキュメントとマニュアルに「Caido は必須」「入口ゲートで停止しうる条件」「認証プリフライトの意味」「strict-prod / strict-dev の差分」を追記する。
- [ ] ステップ20: 導入後の評価項目を追加する。`login-page-only reconnaissance incidents`, `Caido未起動run`, `preflight停止 reason code 上位`, `AI fallback 発火率` を継続観測対象として記録する。

## 4.1 推奨ファイル分割

- `src/core/preflight/entry_gate.py`
  - orchestration 専用
- `src/core/preflight/tooling.py`
  - Caido/tool/version/update/template チェック
- `src/core/preflight/auth_probe.py`
  - target reachability/authenticated-ness 判定
- `src/core/preflight/ai_classifier.py`
  - AI 補助判定のみ
- `src/core/preflight/models.py`
  - 共通 Typed model

## 4.2 受け入れ基準

- `shigoku --target ...` 実行時、Caido 未起動なら実タスク開始前に即停止する。
- `shigoku --resume --target ...` 実行時、session 復元後でも再度入口ゲートが走る。
- `Cookie` が失効して login 画面しか見えていない場合、Katana 実行前に停止する。
- 必須ツール不足や Nuclei template 欠落があれば、スキャン前に停止する。
- 認証判定が曖昧でも AI 分類が `unknown` なら strict に停止する。

## 5. 懸念点と対策（Backlog / 技術的負債を含む）
- ※レビューで挙がった懸念は、発生確率・影響度とセットで管理し、計画書の対応ステップへ反映する。

### 5.1 SRE / インフラ観点

- [ ] [発生確率:高] [影響度:大] 入口ゲートが Caido / tool / auth probe で長時間ハングする可能性
  - 対策: 全チェックに timeout / retry / fail-fast 順序を持たせる。`Caido TCP 2s`, `GraphQL 5s`, `tool probe 3s`, `auth probe 8s`, `AI 3s` を初期値として明文化する。
- [ ] [発生確率:中] [影響度:大] upstream 障害やオフライン環境で自動更新が不安定になり、実行不能が増える可能性
  - 対策: `存在確認`, `最低版判定`, `更新試行` を分離し、更新失敗でも既存版が最低版以上なら通過させる。`offline/no-update gate mode` も用意する。
- [ ] [発生確率:中] [影響度:中] CLI 表示だけでは運用監視しづらく、失敗傾向を横断集計できない可能性
  - 対策: `preflight_fail_total{reason_code}`, `caido_unreachable_total`, `auth_probe_login_redirect_total` などのメトリクスと `preflight_snapshot` を出力する。
- [ ] [発生確率:中] [影響度:大] Caido の一時的瞬断で strict fail-close が過剰停止を生む可能性
  - 対策: `TCP疎通` と `HTTP/GraphQL 応答` の二段階判定に分け、障害理由を細分化した reason code と remediation を返す。

### 5.2 ソフトウェアアーキテクト観点

- [ ] [発生確率:高] [影響度:大] 入口ゲートの呼び出し点が分散し、将来の追加経路でゲート漏れや二重実行が起きる可能性
  - 対策: `EntryGateFacade.run_once(context)` を唯一の入口とし、`main`, `InteractiveBridge`, `resume` は facade 呼び出しだけに統一する。
- [ ] [発生確率:中] [影響度:大] `tooling.py` が過密化し、Caido / tool / update / template の責務が混線する可能性
  - 対策: `caido_check.py`, `tool_check.py`, `tool_update_policy.py` に分割し、`1 checker = 1責務` を徹底する。
- [ ] [発生確率:中] [影響度:中] AI classifier の責務が auth probe 固有に閉じてしまい、将来の challenge/block 判定拡張で境界が崩れる可能性
  - 対策: `response classification` 共通インターフェースを定義し、`auth_probe` は classifier を注入で使う。
- [ ] [発生確率:低] [影響度:中] goal/profile ごとの差異が plan 上で曖昧で、不要ツール欠落でも停止する誤設計になる可能性
  - 対策: required tool matrix を表形式で定義し、`required`, `optional`, `not_applicable` を分ける。

### 5.3 デバッガー観点

- [ ] [発生確率:高] [影響度:中] fail-close の停止理由が短い表示だけだと再現と切り分けが難しい可能性
  - 対策: `reason_code`, `checked_url`, `status_code`, `redirect_chain`, `tool_path`, `tool_version`, `timeout_ms` を含む debug trace を保存する。
- [ ] [発生確率:中] [影響度:大] `auth failure`, `WAF challenge`, `app 403` の誤分類で誤停止または誤通過が起こる可能性
  - 対策: `AUTH_LOGIN_REDIRECT`, `AUTH_SESSION_EXPIRED`, `BLOCK_WAF_CHALLENGE`, `BLOCK_RATE_LIMIT`, `APP_FORBIDDEN` を分けて deterministic 判定する。
- [ ] [発生確率:中] [影響度:中] 単体テスト中心では入口統合の不具合を見逃す可能性
  - 対策: `CLI --target`, `CLI --resume`, `/resume`, `InteractiveBridge direct call` の4経路に統合テストを追加する。
- [ ] [発生確率:低] [影響度:中] AI の誤分類時に入力・出力が残らず、誤停止の解析が困難になる可能性
  - 対策: title, redirect summary, top markers, output label, confidence を debug trace として保存し、AI disabled 再評価手順も用意する。

### 5.4 CTO 観点

- [ ] [発生確率:高] [影響度:大] 導入効果を測る KPI が弱く、実装価値を継続評価しづらい可能性
  - 対策: `login-page-only reconnaissance incidents`, `Caido未起動run`, `preflight停止 reason code 上位`, `AI fallback 発火率` を KPI として受け入れ基準/継続観測対象に追加する。
- [ ] [発生確率:中] [影響度:大] strict 化でローカル検証や開発速度が過度に落ちる可能性
  - 対策: `strict-prod` と `strict-dev` を定義し、共通で fail-close を維持しつつ更新ポリシーや診断出力を調整する。
- [ ] [発生確率:中] [影響度:中] AI コストとモデル障害時の停止率増加が読みにくい可能性
  - 対策: `1 run あたり最大回数`, `1 probe あたり最大1回`, `model failure -> unknown`, `unknown -> fail` を明文化する。
- [ ] [発生確率:中] [影響度:大] 一括導入で問題が起きると切り戻しが難しい可能性
  - 対策: `Phase 1: deterministic gate`, `Phase 2: tool update`, `Phase 3: AI`, `Phase 4: resume hardening` の段階導入と feature flag を実装する。

### 5.5 継続監視・技術的負債

- [ ] [重要度:高] tool の自動更新を system package にまで広げると、実行時の副作用と再現性低下が大きい。初版は BinaryManager 管理対象に限定し、未管理ツールは fail-close + remediation を推奨。
- [ ] [重要度:高] 認証後らしさ判定はターゲットごとの差が大きい。初版は generic heuristic + AI fallback に留め、将来は program-specific fingerprint を導入する。
- [ ] [重要度:中] Caido の「起動確認」を process 検知でやるか API 応答でやるかは OS/環境差異がある。初版は TCP + HTTP/GraphQL 応答優先が安全。
- [ ] [重要度:中] AI 判定はコストと待ち時間を増やすため、曖昧レスポンスのみ・短い抜粋のみ送る制御が必要。
- [ ] [重要度:中] WAF/Challenge 検知は vendor 差が大きい。Cloudflare/Akamai/F5 を最初の優先対象にする。
- [ ] [重要度:低] `/external-tools` の既存ヘルス表示と入口ゲートの実装が二重化しやすい。共通 service 化して片方を薄くする余地がある。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0295-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
