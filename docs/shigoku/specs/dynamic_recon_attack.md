---
name: dynamic_recon_attack
description: Dynamic Recon and High-Precision Attack Validation Architecture
task_id: SGK-2026-0114
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Dynamic Recon and Context Propagation Specification

## 概要

SHIGOKUの現在のアーキテクチャはSPAや動的APIのエンドポイント（XHR/Fetch通信）を捕捉しきれていない。また、検出したパラメータへの攻撃時（SQLi, Open Redirect等）、親タスクから攻撃ツール（Specialist）へ認証コンテキスト（CookieやHeaders）が正しく引き継がれないバグが存在する。
さらに、Open Redirectの検知が「HTTPステータスコード（301/302等）」依存となっており、クライアントサイドのリダイレクト（JavaScript遷移やmetaタグ）を見逃すという精度面での致命的欠陥がある。

本仕様は、「動的ネットワーク傍受機構の導入」「確実なコンテキスト伝播」「ハイブリッド検証（Reflection + Event Hook）による高精度なOpen Redirect検知」の3点を実装し、誤検知なく実戦的な脆弱性検出を実現する。

## 変更範囲

1. **Core / Shared Modules**
   - `src/tools/custom/playwright_recon.py` (新規): 動的通信を傍受するPlaywrightクロールツール
   - `src/core/agents/swarm/base_manager.py`: タスク委譲時の認証コンテキスト（Cookie/Auth）ハードプロパゲーション対応
2. **Dependent Modules**
   - `src/core/agents/swarm/injection/manager.py`: ツールの引数パススルー、URLパラメータのタグ付けの強化
   - `src/core/agents/swarm/injection/open_redirect.py`: ハイブリッド検証ロジック（Reflection検知 + Playwrightイベントバリデーション）の導入

## 挙動

1. **動的Recon (Network Interception)**
   - `playwright_recon.py` により、ターゲットURLへのアクセス裏で発生するすべてのXHR/Fetchリクエストをインターセプトする。
   - 動的APIエンドポイントや隠しパラメータを含むURLを抽出し、ターゲットリストを拡充する。
2. **コンテキストプロパゲーション (Context Propagation)**
   - `BaseManagerAgent` が専門ツール（`run_open_redirect_check`等）を呼び出す際、現在保持している `auth_headers` と `cookies` をツールの引数等に強制パススルーし、常に認証済みの状態で攻撃を実行可能にする。
3. **Open Redirect 高精度ハイブリッド検証**
   - **Phase 1 (Reflection Check)**: 高速なHTTP検証で、レスポンスヘッダ(Location) または レスポンスボディ内にペイロード文字列が反射（Reflect）しているかを確認する。反射していなければ即時終了。
   - **Phase 2 (Dynamic Event Hook)**: Reflectionした候補に対してのみ、Playwrightを起動し独自のペイロードURL（`http://shigoku-verify-<uuid>.evil.com/`）を含ませて遷移を試行する。ブラウザのネットワークイベント（`page.on("request")`等）をフックし、一意なペイロードドメインへのアクセスが発生したことを確証した場合のみ「脆弱性あり」と確定させる。

## 制約

- `EthicsGuard` プロトコルに違反しないよう、全ての自動化ブラウザのリクエストもスコープチェック (`check_scope`) またはブロックリストを適用すること。
- PIIマスクやレートリミット（`AdaptiveRateLimiter`）の適用を維持すること。
- 全ての出力を日本語で行うこと。
- アーキテクチャのCore (共通部分) → Edge (末端) の順序で実装を進めること。
