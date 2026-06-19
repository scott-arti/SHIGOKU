---
task_id: SGK-2026-0301
doc_type: plan
doc_usage: implementation_plan
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/specs/ARCHITECTURE.md
- docs/shigoku/specs/modules/AUTH_NINJA.md
title: '巨大ファイル分割計画: AuthNinja 分割'
created_at: '2026-06-17'
updated_at: '2026-06-18'
tags:
- shigoku
target: src/core/agents/swarm/auth_ninja.py
---

# 実装計画書：巨大ファイル分割計画: AuthNinja 分割

## 1. 達成したいゴール（ユーザー視点）
- [x] `src/core/agents/swarm/auth_ninja.py` の公開 import path を維持したまま、AuthNinja 系エージェントの責務をクラス単位で分割できること。
- [x] `JWTInspector` / `OAuthDancer` / `MFABypasser` / `SessionHijacker` の公開挙動、`create_auth_agent()` の factory 挙動、`register_agent` による registry 連携が変わらないこと。
- [x] 分割後の各ファイルが「1ファイル1責務」に近づき、`auth_ninja.py` 自体は facade / re-export / factory に限定された薄い互換レイヤとして維持されること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/agents/swarm/auth_ninja.py`: （修正）互換維持用 facade。公開 import、re-export、`create_auth_agent()`、共通 alias のみを保持する。
  - `src/core/agents/swarm/auth_ninja_base.py`: （新規）`BaseAuthAgent`、`AuthBypassResult`、logger、共通 network client 初期化などの基盤を保持する。
  - `src/core/agents/swarm/auth_ninja_jwt.py`: （新規）`JWTInspector` と JWT 専用 helper を保持する。
  - `src/core/agents/swarm/auth_ninja_oauth.py`: （新規）`OAuthDancer` と OAuth 専用 helper を保持する。
  - `src/core/agents/swarm/auth_ninja_mfa.py`: （新規）`MFABypasser` と MFA 専用 helper を保持する。
  - `src/core/agents/swarm/auth_ninja_session.py`: （新規）`SessionHijacker` と session/weak-id 専用 helper を保持する。
  - `src/core/agents/swarm/__init__.py`: （原則据え置き、必要時のみ修正）既存 re-export が分割後も成立するか確認する。
  - `src/core/attack/auth/__init__.py`: （原則据え置き、必要時のみ修正）attack package 側の import 互換 smoke 対象とする。
  - `tests/unit/agents/swarm/test_auth_ninja.py`: （修正）分割前後の import / factory / representative behavior 回帰を固定する。
  - `tests/core/test_agent_protocol.py`: （必要時のみ修正）`BaseAuthAgent` / `JWTInspector` の protocol 準拠回帰を固定する。
  - `tests/core/test_factory_registry.py`: （必要時のみ修正）`AgentFactory.create_agent("authninja")` と registry 経由生成の回帰を固定する。
- **データの流れ / 依存関係:**
  - 既存呼び出し元（`src/commands/hunt.py`、`src/commands/demo.py`、テスト群） -> `src.core.agents.swarm.auth_ninja` facade -> 各分割モジュール -> `EthicsGuard` / `AsyncNetworkClient` / `asset_loader` / `Finding` / `HandoffResult`

## 2.1 分割境界の基本方針
- `auth_ninja.py` と同名のサブパッケージ `src/core/agents/swarm/auth_ninja/` は作らない。既存の `from src.core.agents.swarm.auth_ninja import ...` を壊す可能性があるため、 sibling module を平置きで追加する。
- 分割単位は「クラス + クラス専用 helper」を優先し、`JWTInspector` / `OAuthDancer` / `MFABypasser` / `SessionHijacker` をそれぞれ独立モジュールへ出す。
- shared state の所有者は `BaseAuthAgent` のみとし、concrete agent 間で helper を横断共有しない。共通化が必要でも first pass では `auth_ninja_base.py` に閉じる。
- `auth_ninja.py` は最終的に `import`、`re-export`、`create_auth_agent()`、後方互換 alias のみを持つ薄い facade とし、 target は 200 行未満を目安にする。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - `HandoffContext`、legacy `target + params`、`AgentFactory.create_agent("authninja")`、`src.core.agents.swarm.auth_ninja` からの直接 import
- **出力/結果 (Output):**
  - 既存どおりの `HandoffResult`、`Finding.to_dict()` payload、`create_run_result()` payload、`create_auth_agent()` が返す agent instance
- **制約・ルール:**
  - 公開 import path は維持する。少なくとも `BaseAuthAgent`、`JWTInspector`、`OAuthDancer`、`MFABypasser`、`SessionHijacker`、`AuthBypassResult`、`create_auth_agent` は `src.core.agents.swarm.auth_ninja` から引き続き取得できること。
  - `@register_agent` の decorator side effect を壊さない。facade import 時に `JWTInspector` / `OAuthDancer` / `SessionHijacker` などの登録が従来どおり行われること。
  - `src/core/agents/swarm/auth/auth_ninja.py` の legacy fast checker は今回の対象外とし、名前が近いからといって移動・統合しない。
  - `Finding` schema、`HandoffResult` schema、network request の実行条件、EthicsGuard の判定順序は変更しない。
  - first pass では behavior change を狙わない。重複削減や helper 再編成は「分割の副作用として最小限」に留める。
  - 目安サイズ:
    - `auth_ninja.py`: facade として 200 行未満
    - `auth_ninja_base.py`: 100-250 行
    - `auth_ninja_jwt.py`: 350-650 行
    - `auth_ninja_oauth.py`: 350-650 行
    - `auth_ninja_mfa.py`: 350-650 行
    - `auth_ninja_session.py`: 500-900 行

## 3.1 事前に固定する回帰観点
- import 回帰:
  - `from src.core.agents.swarm.auth_ninja import JWTInspector, OAuthDancer, MFABypasser, SessionHijacker`
  - `from src.core.agents.swarm import JWTInspector, OAuthDancer, MFABypasser`
  - `from src.core.attack.auth import JWTInspector, OAuthDancer, MFABypasser`
- registry / factory 回帰:
  - `AgentFactory.create_agent("authninja")` が `JWTInspector` を返すこと
  - `get_agent_class("authninja")` / alias 解決が維持されること
- representative behavior 回帰:
  - `JWTInspector._try_alg_none()`
  - `OAuthDancer._try_redirect_bypass()`
  - `OAuthDancer._try_pkce_downgrade()`
  - `SessionHijacker` の weak-id / fixation 系テスト

## 3.2 DeepSeek 向け実装ルール
- 1ステップごとに `write failing test -> fail を確認 -> 最小差分で分割 -> targeted test` の順を守る。
- クラス抽出は 1モジュールずつ行い、1回の差分で複数クラスを同時に移さない。
- import path 互換のため、consumer 側の import 文書き換えを初手で広げない。まず facade で吸収し、どうしても必要な consumer 修正だけを最後に行う。
- circular import が見えたら `auth_ninja_base.py` に共通基盤を寄せ、concrete module 間の直接参照は禁止する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: まず characterization test を追加または拡張する。`tests/unit/agents/swarm/test_auth_ninja.py` に `create_auth_agent()` の alias 解決、`src.core.agents.swarm.auth_ninja` からの import、必要なら `src.core.attack.auth` からの import smoke を追加する。`tests/core/test_factory_registry.py` と `tests/core/test_agent_protocol.py` は既存 assertions で十分か確認し、不足があれば最小追加する。
- [x] ステップ2: 追加したテストだけを先に実行して RED/GREEN の基準を固定する。最初の確認コマンドは `.venv/bin/pytest tests/unit/agents/swarm/test_auth_ninja.py tests/core/test_agent_protocol.py tests/core/test_factory_registry.py -q` とし、失敗理由が「未分割前提の壊れやすい import/registry」を捕捉できていることを確認する。
- [x] ステップ3: `BaseAuthAgent`、`AuthBypassResult`、logger、共通 import を `src/core/agents/swarm/auth_ninja_base.py` へ移し、`src/core/agents/swarm/auth_ninja.py` はまず base を re-export する形へ整理する。この時点では concrete agent はまだ元ファイルに残してよい。targeted tests を再実行し、import cycle がないことを確認する。
- [x] ステップ4: `JWTInspector` と JWT 専用 helper 群を `src/core/agents/swarm/auth_ninja_jwt.py` へ抽出する。`@register_agent` は抽出先クラス定義に残し、facade から `from .auth_ninja_jwt import JWTInspector` で読み込む。`test_jwt_inspector_try_alg_none`、factory/registry、protocol tests を通す。
- [x] ステップ5: `OAuthDancer` を `src/core/agents/swarm/auth_ninja_oauth.py` へ抽出する。`test_oauth_dancer_try_redirect_bypass` と `test_oauth_dancer_try_pkce_downgrade` を targeted check とし、JWT 分割済み状態でも registry が壊れていないことを確認する。
- [x] ステップ6: `MFABypasser` を `src/core/agents/swarm/auth_ninja_mfa.py` へ抽出する。現状 MFA の厚い unit test が少ない場合は、import smoke と `create_auth_agent("mfa")` だけでも先に固定してから移す。MFA 分割で `asset_loader` や `_guard` 初期化の重複が出ても、 first pass は behavior preservation を優先する。
- [x] ステップ7: `SessionHijacker` を `src/core/agents/swarm/auth_ninja_session.py` へ抽出する。現在最も大きいクラスなので、weak-session / weak-id / cookie-audit helper を class 内に残したままでもよいが、モジュール単位では 1000 行未満に抑える。`tests/unit/agents/swarm/test_auth_ninja.py` 内の SessionHijacker 系テストを優先実行し、`save_finding` や runtime session cookie 優先ロジックが壊れていないことを確認する。
- [x] ステップ8: `src/core/agents/swarm/auth_ninja.py` を facade と factory のみに薄化し、`create_auth_agent()` の mapping を最終確認する。`src/core/agents/swarm/__init__.py` と `src/core/attack/auth/__init__.py` は原則変更しないが、re-export 解決で不足があれば最小差分で整える。targeted tests 後、広めの関連確認として `.venv/bin/pytest tests/unit/agents/swarm/test_auth_ninja.py tests/core/test_agent_protocol.py tests/core/test_factory_registry.py tests/integration/test_tier6_advanced.py -q` を実行する。
- [x] ステップ9: 完了条件を確認する。`auth_ninja.py` が facade へ縮小されていること、公開 import path が互換であること、factory/registry/protocol/representative auth tests が通ること、consumer 側の import 書き換えを極小に留めたことを満たせば完了とする。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] `@register_agent` の登録副作用が facade import 順に依存している可能性がある - 抽出先モジュールを facade が eager import する構成を維持し、 lazy import 化は別タスクに分離する。
- [ ] [重要度:高] `src/core/agents/swarm/auth_ninja.py` と `src/core/agents/swarm/auth/auth_ninja.py` の名前が近く、誤編集や誤 import を誘発しやすい - 今回は legacy fast checker を完全に対象外と明記し、必要なら follow-up で命名整理タスクを切る。
- [ ] [重要度:中] `SessionHijacker` は単独でも 700 行超のため、将来的には `session fixation` / `weak-id` / `cookie audit` の helper へ二段分割したくなる可能性がある - 今回は first pass で 1モジュール化までに留め、追加分割は別 subtask にする。
- [ ] [重要度:中] `src/core/attack/auth/__init__.py` の import 元や attack package 側の設計負債が残る - facade 互換だけで吸収し、 package 再整理は別計画に分ける。
- [ ] [重要度:中] AuthNinja module spec のパス記述が古く、実装実態とズレている (`src/agents/swarm/auth_ninja.py`) - 実装完了後の work_report で spec 更新要否を必ず判断する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0301-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
