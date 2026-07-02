---
task_id: SGK-2026-0133
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Spec: Katana Headless Crawler Integration & Unified Caido Proxy Strategy

## 1. 概要

現代のWebアプリケーション（SPA/React/Next.js等）を攻略するため、KatanaのHeadlessモードを有効化し、偵察から脆弱性診断まで全てのWebトラフィックをCaidoプロキシに集約する。
プロキシが利用不可能な場合は、不正な通信やスキャンの見落としを防ぐため、システムを安全に一時停止（PAUSE）させる。

## 2. 変更範囲

1.  **`src/tools/custom/katana.py`**:
    - `headless` モードの解析オプション強化（`-jc`, `-jsluicy`）。
    - プロキシ設定を絶対要件化。
2.  **`src/core/infra/network_client.py`**:
    - 全ての `AsyncNetworkClient` にデフォルトでプロキシ（settings.scan.proxy）を適用するオプションを追加。
    - リクエスト実行前にプロキシの死活監視を挿入。
3.  **`src/recon/pipeline.py`**:
    - `step3b_hybrid_url_discovery` 内での Katana 呼び出しを `headless` に固定。
    - 偵察開始時にCaidoへの接続を確認し、失敗時は診断を停止するゲートチェックを実装。

## 3. 具体的挙動

### プロキシ・デッドマン・スイッチ (Strict Check)

- Webアクセスを伴う全てのタスク実行前に、`127.0.0.1:8080`（Caido）へのTCP接続テストを行う。
- **Caidoが未起動の場合**:
  1. ユーザーに対して「Caidoが見つかりません。診断を継続できません。」というアラートを出す。
  2. インタラクティブ・ブリッジを通じて診断を「一時停止（PAUSE）」し、ユーザーがCaidoを起動するのを待つ。

### Katana Headless & JS解析の詳細仕様

- フラグ: `-headless`, `-jc`, `-jsluicy`, `-automatic-form-fill` (認証時除く)。
- 全てのJSファイルをCaido経由で読み込ませることで、Caidoの「History」から不可視のAPIリクエストをAIが分析可能にする。

### 全通信のプロキシ化

- Reconパイプラインだけでなく、`AuthenticationSpecialist` や `LFIHunter` 等、全てのサブエージェントが発生させるパケットをCaido経由にする。
- これにより、Caido側で全てのリクエストに対して「Replay（手動確認）」や「デバッグ」が可能になる。

## 4. 制約・安全性

- プロキシ無しのフォールバックは原則禁止。
- 大規模なスキャン時にCaidoのメモリが飽和しないよう、Katanaの `threads` 数を適切に制限する。

## 5. 次のステップ

1. ロードマップドキュメントの承認。
2. プロキシ生存確認ロジック（Gatekeeper）の実装。
