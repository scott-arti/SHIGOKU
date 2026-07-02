---
task_id: SGK-2026-0279
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0278
related_docs:
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
- docs/shigoku/roadmaps/bug_bounty_enhancements_2026.md
title: DEV_MODEデモ経路分離とBurpIntegration削除計画
created_at: '2026-06-20'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/recon/tool_runner.py, src/recon/pipeline.py, src/core/adapters/proxy_integration.py
---

# 実装計画書：DEV_MODEデモ経路分離とBurpIntegration削除計画

## 1. 達成したいゴール（ユーザー視点）
- `SHIGOKU_DEV_MODE=true` を「デモ/テスト向け機能」として明確化し、本番実行経路と責務を分離する。
- Recon 実行コードから Burp placeholder を排除し、Caido 単独前提に揃える。
- 将来のデモモード保守を、Recon 本体の条件分岐増殖なしで続けられるようにする。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/tool_runner.py`: `dev_mode` 判定の現在地。実 subprocess と mock 出力を同居させている
  - `src/recon/pipeline.py`: resolver / whatweb などで DEV_MODE 用の分岐を持つ
  - `src/core/adapters/proxy_integration.py`: `CaidoIntegration` と不要な `BurpIntegration` が同居している
- **データの流れ / 依存関係:**
  - `SHIGOKU_DEV_MODE` -> `ToolRunner` / `ReconPipeline` -> 実 subprocess か fixture/provider を選択
  - finding replay -> `ProxyManager` -> `CaidoIntegration` -> Caido Repeater/API

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - 環境変数 `SHIGOKU_DEV_MODE`
  - Recon ツール実行要求
  - finding の proxy 送信要求
- **出力/結果 (Output):**
  - 本番経路は「実ツール実行のみ」を担当
  - デモ経路は fixture/provider 層で mock を返す
  - `proxy_integration.py` は Caido 実装のみに整理
- **制約・ルール:**
  - デモモード自体は削除しない
  - `InternalToolProvider` など別の技術的負債には触れない
  - テスト容易性は維持しつつ、本番ロジックと mock ロジックの責務を明確化する
  - Burp は履歴ドキュメントに残っていてもよいが、実コードでは消す

## 3.1 懸念点と対策

### SRE/インフラエンジニア視点
- [発生確率:高][影響度:大] `SHIGOKU_DEV_MODE=false` / 未設定 / `true` の挙動境界が曖昧なまま分離を進めると、本番経路に mock が混入したり、CI でデモ経路が誤発火するおそれがある。
  - 対策: 3状態それぞれの期待挙動を先に固定し、`ToolRunner.run` / `run_json` / `check_tools` / `is_tool_available` の経路選択を targeted test で先にロックする。
- [発生確率:中][影響度:大] デモ経路が resolver 取得や Caido 接続などの外部 I/O に触れるままだと、ローカル実行・CI・デモで再現性が不安定になる。
  - 対策: デモ経路では外部ネットワーク・実 subprocess・Caido 接続へ到達しないことを制約として明記し、fixture/provider が成果物生成まで閉じるようにする。
- [発生確率:中][影響度:中] 実行経路の識別情報が残らないと、障害時に production/demo どちらの経路で動いたかを追跡しづらい。
  - 対策: ログまたは成果物メタ情報に `execution_mode=production|demo` 相当の識別を残し、秘密値を出さずに追跡できるようにする。

### ソフトウェアアーキテクト視点
- [発生確率:高][影響度:大] `demo provider` / `fixture loader` / `test adapter` の選択基準が未定義なまま着手すると、実装者ごとに責務分割がぶれる。
  - 対策: 採用方針を「`ToolRunner` は subprocess 実行のみ、demo 出力は provider 層が担当、`pipeline.py` は provider interface に依存」に固定してから実装に入る。
- [発生確率:高][影響度:大] 計画書が `BurpIntegration` 削除を未完了前提で書かれているため、実コードの現状と計画の主眼がずれている。
  - 対策: 本タスクでは Burp 実装削除を「削除済み確認事項」とし、残存コメント・表記・前提の整合化を対象に切り替える。
- [発生確率:中][影響度:大] `src/recon/demo/` のような新設先を曖昧にすると、fixture/provider と外部ツール adapter の責務が混ざる。
  - 対策: demo 専用層には fixture と provider のみ置き、外部ツール adapter 追加は本タスクのスコープ外と明記する。

### デバッガー視点
- [発生確率:高][影響度:大] `tests/recon` の多くが `pipeline.runner.dev_mode = True` の直接代入に依存しているため、互換方針なしに分離すると広範囲にテストが壊れる。
  - 対策: 既存テストの依存箇所を先に棚卸しし、初回パッチでは互換 shim または注入ポイントを残して回帰を防ぐ。
- [発生確率:中][影響度:中] `fetch_resolvers` や `whatweb` のようなファイル副作用が文字列出力テストだけでは守れず、退行を見逃しやすい。
  - 対策: `resolvers.txt`、`whatweb.json`、`live_subs.txt` などの生成有無・内容・形式を regression test に含める。
- [発生確率:中][影響度:大] `ToolRunner.run` の非0終了時・timeout 時・JSON parse warning 時の既存挙動を暗黙に変えると、今回の責務分離以外の不具合を混ぜ込みやすい。
  - 対策: 本タスクでは subprocess の失敗時挙動は変更しない方針を先に固定し、必要なら別タスクへ切り出す。

### CTO視点
- [発生確率:高][影響度:大] この計画の価値が「Burp削除」寄りのままだと、実際に必要な DEV_MODE 境界整理の成果がぼやける。
  - 対策: 本タスクの主目的を「本番経路・デモ経路・テスト経路の境界明確化」に置き、Burp は前提整合の確認対象へ下げる。
- [発生確率:中][影響度:大] `Caido`、preflight、proxy chain、external adapter へ議論が広がると、計画より実装スコープが膨張しやすい。
  - 対策: 変更対象を `ToolRunner` の mock責務分離、`pipeline.py` の DEV_MODE ファイル副作用整理、`proxy_integration.py` の残存表記整合化に限定する。
- [発生確率:中][影響度:中] 完了条件が抽象的だと、実装後に「整理されたか」の判断が人によってぶれる。
  - 対策: provider への移設対象、`pipeline.py` 側の分岐削減、`SHIGOKU_DEV_MODE=false` で mock 文字列が混入しないことを測定可能な完了条件として明文化する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `tool_runner.py`、`pipeline.py`、`tests/recon/` の `DEV_MODE` 依存箇所を棚卸しし、`SHIGOKU_DEV_MODE=false` / 未設定 / `true` の期待挙動、互換維持が必要なテスト注入点、外部 I/O 境界を一覧化する
- [x] ステップ2: 本タスクの設計方針を固定する。`ToolRunner` は subprocess 実行 abstraction のみ、demo 出力は provider/fixture 層、`pipeline.py` は provider interface を呼ぶ構成とし、非0終了・timeout などの既存 subprocess 挙動は変更対象外にする
- [x] ステップ3: demo 用 fixture schema と生成成果物 (`resolvers.txt`、`whatweb.json`、`live_subs.txt` など) を定義し、デモ経路では外部ネットワーク・実 subprocess・Caido 接続へ到達しない方針をテスト前提として固める
- [x] ステップ4: `proxy_integration.py` は `BurpIntegration` 削除済みであることを確認したうえで、残存コメント・表記・前提があれば Caido 単独前提に整合化する
- [x] ステップ5: `tool_runner.py` と `pipeline.py` の DEV_MODE 分岐を provider/fixture 層へ寄せる。初回パッチでは既存 `tests/recon` が壊れないよう互換 shim または注入ポイントを維持しつつ、ファイル副作用生成も provider 経由へ寄せる
- [x] ステップ6: targeted test を追加・更新し、`SHIGOKU_DEV_MODE=false` / 未設定 / `true` の経路選択、mock 非混入、fixture 成果物生成、既存 subprocess 失敗時挙動の非変更を確認する

## 4.1 推奨設計
- `ToolRunner` は「コマンド実行 abstraction」のみ残す
- デモ専用出力は `src/recon/demo/` または同等の小さな層へ移し、`ToolRunner` に注入する
- `pipeline.py` の DEV_MODE ファイル直書きは、fixture 生成 helper へ切り出す
- demo 専用層には fixture / provider のみを置き、外部ツール adapter の新設や preflight/ProxyChain 変更は本タスクの対象外とする

## 4.2 完了条件
- `proxy_integration.py` では Burp 実装が削除済みであることを確認し、残存するコメント・表記・前提があれば Caido 単独前提に整合している
- DEV_MODE の責務が「本番分岐」ではなく「デモ用 provider」に整理され、`ToolRunner` には subprocess 実行 abstraction の責務のみが残る
- `pipeline.py` の DEV_MODE ファイル副作用が provider/fixture helper 経由へ整理され、デモ経路が外部ネットワーク・実 subprocess・Caido 接続に依存しない
- `SHIGOKU_DEV_MODE=false` で mock 文字列や fixture 成果物が本番経路に混入せず、`true` では既存デモ用途と成果物生成が維持される targeted test が存在する

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] fixture 形式を固めずに移すと、既存テスト資産との互換が壊れやすい - 先に fixture schema を固定する
- [ ] [重要度:低] ドキュメント上に Burp の痕跡が残る可能性がある - 必要なら後続で文書整理タスクを起票する

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0279-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
